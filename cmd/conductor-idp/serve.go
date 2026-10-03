package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/samba-conductor/conductor-idp/internal/config"
	"github.com/samba-conductor/conductor-idp/internal/directory"
	"github.com/samba-conductor/conductor-idp/internal/mfa"
	"github.com/samba-conductor/conductor-idp/internal/oidcp"
	"github.com/samba-conductor/conductor-idp/internal/samlidp"
	"github.com/samba-conductor/conductor-idp/internal/secret"
	"github.com/samba-conductor/conductor-idp/internal/store"
	"github.com/samba-conductor/conductor-idp/internal/web"
)

// env is what most commands need: configuration and state.
type env struct {
	cfg   *config.Config
	store *store.Store
	log   *slog.Logger
}

func openEnv(ctx context.Context, path string) (*env, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	st, err := store.Open(ctx, cfg.State.Database)
	if err != nil {
		return nil, err
	}
	return &env{cfg: cfg, store: st, log: slog.New(slog.NewTextHandler(os.Stderr, nil))}, nil
}

func (e *env) close() { _ = e.store.Close() }

func (e *env) masterKey() ([]byte, error) {
	p, err := e.cfg.MasterKeyPath()
	if err != nil {
		return nil, err
	}
	return secret.LoadKeyFile(p)
}

// directory builds the AD backend with the service account.
func (e *env) directory() (*directory.Directory, error) {
	p, err := e.cfg.ServicePasswordPath()
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	forbidden := os.FileMode(0o077)
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" && strings.HasPrefix(p, dir+"/") {
		forbidden = 0o037
	}
	if st.Mode().Perm()&forbidden != 0 {
		return nil, fmt.Errorf("%s is accessible by group or others; use 0600", p)
	}
	pw, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	adCfg, err := directory.ADConfig(e.cfg.Domain.Realm, e.cfg.Domain.CAFile, e.cfg.Domain.DCs, e.cfg.Domain.Preferred, e.cfg.Domain.DNSServers)
	if err != nil {
		return nil, err
	}
	return directory.New(directory.Options{Config: adCfg, SimpleBindFallback: e.cfg.Domain.SimpleBindFallback,
		ServiceUser: e.cfg.ServiceAccount.Username, ServicePassword: strings.TrimRight(string(pw), "\r\n")})
}

// providers builds the key managers and the provider pieces.
type providers struct {
	box  *secret.Box
	oidc *oidcp.KeyManager
	saml *samlidp.KeyManager
	key  []byte
}

func (e *env) providers() (*providers, error) {
	key, err := e.masterKey()
	if err != nil {
		return nil, err
	}
	box, err := secret.New(key)
	if err != nil {
		return nil, err
	}
	host := e.cfg.IssuerHost()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return &providers{box: box, key: key,
		oidc: &oidcp.KeyManager{Store: e.store, Box: box, RotateAfter: e.cfg.KeyRotateAfter(), Overlap: e.cfg.KeyOverlap()},
		saml: &samlidp.KeyManager{Store: e.store, Box: box, Subject: host, Overlap: e.cfg.KeyOverlap()},
	}, nil
}

// rotator implements web.KeyRotator.
type rotator struct{ p *providers }

func (r rotator) RotateOIDC(ctx context.Context) (string, error) { return r.p.oidc.Rotate(ctx) }
func (r rotator) RotateSAML(ctx context.Context, immediate bool) (string, error) {
	return r.p.saml.Rotate(ctx, immediate)
}

func cmdServe(ctx context.Context, cfgPath string, _ []string) error {
	e, err := openEnv(ctx, cfgPath)
	if err != nil {
		return err
	}
	defer e.close()
	log := e.log
	// The OIDC library logs through the default logger.
	slog.SetDefault(log)
	p, err := e.providers()
	if err != nil {
		return err
	}
	dir, err := e.directory()
	if err != nil {
		return fmt.Errorf("directory: %w", err)
	}
	defer dir.Close()
	if err := dir.Check(ctx); err != nil {
		// Start anyway: the DCs may come up later; sign-ins fail until then.
		log.Warn("service account check failed; continuing", "err", err)
	}
	if created, err := p.oidc.Ensure(ctx); err != nil {
		return err
	} else if created {
		log.Info("created a new OIDC signing key")
	}
	var samlIdP *samlidp.IdP
	if e.cfg.SAML.Enabled {
		if created, err := p.saml.Ensure(ctx); err != nil {
			return err
		} else if created {
			log.Info("created a new SAML signing key")
		}
		samlIdP = &samlidp.IdP{Store: e.store, Dir: dir, Keys: p.saml, BaseURL: e.cfg.Issuer(),
			AssertionTTL: time.Duration(e.cfg.SAML.AssertionMinutes) * time.Minute}
	}
	var backend mfa.Backend
	switch e.cfg.MFA.Backend {
	case config.MFABackendConductor:
		backend = &mfa.Conductor{Socket: e.cfg.MFA.ConductorSocket}
	default:
		backend = &mfa.Local{Store: e.store, Box: p.box}
	}
	storage := &oidcp.Storage{Store: e.store, Keys: p.oidc, Dir: dir, Logger: log, Audit: web.AuditProvider(e.store, log),
		Lifetimes: oidcp.Lifetimes{IDToken: e.cfg.IDTokenTTL(), AccessToken: e.cfg.AccessTokenTTL(), Refresh: e.cfg.RefreshTTL(),
			RefreshIdle: e.cfg.RefreshIdleTTL()}}
	atKey, err := oidcp.AccessTokenKey(p.key)
	if err != nil {
		return err
	}
	provider, err := oidcp.NewProvider(e.cfg.Issuer(), storage, atKey, log)
	if err != nil {
		return err
	}
	srv, err := web.New(web.Options{Config: e.cfg, Store: e.store, Dir: dir, MFA: backend, OIDC: storage, Provider: provider,
		SAML: samlIdP, Keys: rotator{p}, Logger: log, Version: version})
	if err != nil {
		return err
	}
	hs := &http.Server{
		Addr:              e.cfg.Server.Listen,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	if e.cfg.TLS() {
		hs.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	go maintenance(ctx, log, e.store, p, srv)
	errc := make(chan error, 1)
	go func() {
		log.Info("conductor-idp listening", "addr", e.cfg.Server.Listen, "issuer", e.cfg.Issuer(), "saml", e.cfg.SAML.Enabled,
			"mfa_backend", backend.Name(), "version", version)
		if e.cfg.TLS() {
			errc <- hs.ListenAndServeTLS(e.cfg.Server.TLSCert, e.cfg.Server.TLSKey)
		} else {
			errc <- hs.ListenAndServe()
		}
	}()
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return hs.Shutdown(sctx)
	}
}

// maintenance rotates the OIDC key on schedule, purges expired rows and
// sweeps sessions.
func maintenance(ctx context.Context, log *slog.Logger, st *store.Store, p *providers, srv *web.Server) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	n := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		srv.Sweep()
		n++
		if n%10 != 0 {
			continue
		}
		if err := st.Purge(ctx); err != nil {
			log.Error("purge failed", "err", err)
		}
		if created, err := p.oidc.Ensure(ctx); err != nil {
			log.Error("OIDC key rotation check failed", "err", err)
		} else if created {
			log.Info("rotated the OIDC signing key")
		}
	}
}

func cmdCheck(ctx context.Context, cfgPath string) error {
	e, err := openEnv(ctx, cfgPath)
	if err != nil {
		return err
	}
	defer e.close()
	fmt.Println("configuration: ok")
	if _, err := e.masterKey(); err != nil {
		return fmt.Errorf("master key: %w", err)
	}
	fmt.Println("master key: ok")
	dir, err := e.directory()
	if err != nil {
		return fmt.Errorf("directory: %w", err)
	}
	defer dir.Close()
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := dir.Check(cctx); err != nil {
		return fmt.Errorf("service account: %w", err)
	}
	fmt.Println("service account bind and read: ok")
	return nil
}
