package store

import (
	"context"
	"time"
)

// ActivityCount is one group of audit rows: an action, its target and
// result, how many rows and how many distinct actors.
type ActivityCount struct {
	Action string
	Target string
	Result string
	Rows   int
	Actors int
}

// activityActions are the actions the activity summary reads.
var activityActions = []any{"oidc.authorize", "saml.sso", "signin.password", "signin.failure", "signin.rate_limited", "mfa.failure"}

// Activity counts the sign-in related audit rows since a time, grouped by
// action, target and result. Lockouts are counted apart: sign-in refusals
// whose reason is a locked account.
func (s *Store) Activity(ctx context.Context, since time.Time) ([]ActivityCount, int, error) {
	q := `SELECT action, target, result, COUNT(*), COUNT(DISTINCT actor_name) FROM audit
		WHERE ts >= ? AND action IN (?, ?, ?, ?, ?, ?) GROUP BY action, target, result ORDER BY action, target, result`
	args := append([]any{auditTS(since)}, activityActions...)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()
	var out []ActivityCount
	for rows.Next() {
		var c ActivityCount
		if err := rows.Scan(&c.Action, &c.Target, &c.Result, &c.Rows, &c.Actors); err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	var locked int
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit WHERE ts >= ? AND action = 'signin.failure'
		AND substr(detail, 1, 21) = 'reason=account locked'`, auditTS(since)).Scan(&locked)
	return out, locked, err
}
