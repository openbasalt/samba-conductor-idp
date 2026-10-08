package main

import (
	"context"
	"fmt"
	"time"

	"github.com/openbasalt/samba-conductor-idp/internal/config"
)

// cmdHealthcheck is the container healthcheck (the image has no shell): GET
// /healthz on the main listener over TLS pinned to the IdP's own
// certificate (the handler pings the database), a pinned handshake with a
// separate admin listener, and the management API socket when the IdP
// creates it. Reads only the configuration. Exit status 0 = healthy.
func cmdHealthcheck(ctx context.Context, cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addr, err := loopbackAddr(cfg.Server.Listen)
	if err != nil {
		return err
	}
	if cfg.TLS() {
		err = probeHTTPS(ctx, addr, cfg.Server.TLSCert, "/healthz")
	} else {
		err = probeTCP(ctx, addr)
	}
	if err != nil {
		return err
	}
	if cfg.AdminMode() == config.AdminSeparate {
		aaddr, err := loopbackAddr(cfg.Server.AdminListen)
		if err != nil {
			return err
		}
		if cert, _, ok := cfg.AdminTLS(); ok {
			err = probeTLS(ctx, aaddr, cert)
		} else {
			err = probeTCP(ctx, aaddr)
		}
		if err != nil {
			return fmt.Errorf("admin listener: %w", err)
		}
	}
	if cfg.API.Enabled && cfg.API.Socket != "" {
		if err := checkSocket(cfg.API.Socket); err != nil {
			return fmt.Errorf("management API socket: %w", err)
		}
	}
	fmt.Println("ok")
	return nil
}
