// Package store is conductor-idp's local state in SQLite (pure Go driver,
// CGO off): registered clients and SAML service providers, authorization
// requests, hashed codes and tokens, sealed signing keys, consents, the
// local 2FA store and the hash-chained audit log. AD stays the source of
// truth for users and groups: no copy of the directory is kept.
package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // database/sql driver "sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("store: not found")

// ErrConflict is returned when a unique row already exists.
var ErrConflict = errors.New("store: already exists")

// Store wraps the database.
type Store struct {
	db *sql.DB
	// auditMu serializes appends so the chain has no forks.
	auditMu sync.Mutex
	now     func() time.Time
}

// Open opens (creating if needed) the database at path and applies the
// embedded migrations. The file is made private to the process user.
func Open(ctx context.Context, path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("store: empty path")
	}
	q := url.Values{}
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "synchronous(FULL)")
	q.Set("_txlock", "immediate")
	dsn := "file:" + path + "?" + q.Encode()
	if path == ":memory:" {
		dsn = "file::memory:?" + q.Encode()
	}
	if path != ":memory:" {
		// Create the file private before SQLite does (umask may be 022).
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			return nil, fmt.Errorf("store: %w", err)
		}
		_ = f.Close()
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite allows one writer; one connection also keeps :memory: shared.
	db.SetMaxOpenConns(1)
	s := &Store{db: db, now: func() time.Time { return time.Now().UTC() }}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if path != ":memory:" {
		for _, p := range []string{path, path + "-wal", path + "-shm"} {
			if _, err := os.Stat(p); err == nil {
				_ = os.Chmod(p, 0o600)
			}
		}
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// SetClock replaces the clock (tests).
func (s *Store) SetClock(now func() time.Time) { s.now = now }

// Now returns the store's clock.
func (s *Store) Now() time.Time { return s.now() }

// Ping checks the database (health endpoint).
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		v, err := strconv.Atoi(strings.SplitN(path.Base(name), "_", 2)[0])
		if err != nil {
			return fmt.Errorf("store: migration %s: bad name", name)
		}
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, v).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			continue
		}
		body, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: migration %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)`, v, nanos(s.now())); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// nanos stores a time; the zero time is 0.
func nanos(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

// fromNanos reads a stored time; 0 is the zero time.
func fromNanos(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}

func toJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		// Only slices of strings and plain structs are stored.
		panic("store: json: " + err.Error())
	}
	return string(b)
}

func strs(s string) []string {
	var out []string
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// Purge deletes what has expired: authorization requests, codes, SAML
// requests, tokens and used enrollment links. Called periodically.
func (s *Store) Purge(ctx context.Context) error {
	now := nanos(s.now())
	// Refresh chains are kept a day after they end so a late reuse of a
	// rotated token is still recognized (and logged) instead of "unknown".
	grace := now - int64(24*time.Hour)
	stmts := []struct {
		q    string
		args []any
	}{
		{`DELETE FROM auth_requests WHERE expires_at < ?`, []any{now}},
		{`DELETE FROM auth_codes WHERE expires_at < ?`, []any{grace}},
		{`DELETE FROM saml_pending WHERE expires_at < ?`, []any{now}},
		{`DELETE FROM access_tokens WHERE expires_at < ?`, []any{now}},
		{`DELETE FROM refresh_tokens WHERE chain_expires_at < ? OR (revoked_at > 0 AND revoked_at < ?)`, []any{grace, grace}},
		{`DELETE FROM enroll_links WHERE expires_at < ?`, []any{now}},
		{`DELETE FROM signing_keys WHERE retire_at > 0 AND retire_at < ?`, []any{now}},
	}
	for _, st := range stmts {
		if _, err := s.db.ExecContext(ctx, st.q, st.args...); err != nil {
			return err
		}
	}
	return nil
}
