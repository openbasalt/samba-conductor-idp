// Command conductor-idp is the OpenID Connect provider and SAML 2.0
// identity provider of Samba Conductor, backed by Samba AD.
//
//	conductor-idp serve            run the provider
//	conductor-idp client ...       register and maintain OIDC clients
//	conductor-idp saml ...         register and maintain SAML service providers
//	conductor-idp keys ...         list and rotate signing keys
//	conductor-idp enroll-link      one-time 2FA enrollment link for an administrator
//	conductor-idp mfa reset        remove a user's 2FA (local backend)
//	conductor-idp audit ...        verify or export the audit log
//	conductor-idp gen-key FILE     create a master key file (0600)
//	conductor-idp templates ...    list, show and check the template overrides
//	conductor-idp check            check the configuration and the directory
//	conductor-idp version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

var version = "dev"

func usage() {
	fmt.Fprintln(os.Stderr, `usage: conductor-idp [-config FILE] COMMAND [ARGS]

commands:
  serve                       run the provider
  client add|list|show|update|rotate|enable|disable|remove
  saml add|list|show|update|enable|disable|remove
  keys list | keys rotate oidc | keys rotate saml [-immediate]
  enroll-link -user NAME      one-time 2FA enrollment link (administrators)
  mfa reset -user NAME        remove a user's 2FA (local backend)
  audit verify | audit export
  gen-key FILE                write a new 32-byte master key (0600)
  templates list | templates show NAME | templates check
                              template overrides of the sign-in pages
  check                       validate the configuration, bind the service account
  version

Run "conductor-idp COMMAND -h" for a command's flags.`)
}

func main() {
	global := flag.NewFlagSet("conductor-idp", flag.ContinueOnError)
	cfgPath := global.String("config", defaultConfigPath(), "configuration file")
	global.Usage = usage
	if err := global.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	args := global.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch args[0] {
	case "serve":
		err = cmdServe(ctx, *cfgPath, args[1:])
	case "client":
		err = cmdClient(ctx, *cfgPath, args[1:])
	case "saml":
		err = cmdSAML(ctx, *cfgPath, args[1:])
	case "keys":
		err = cmdKeys(ctx, *cfgPath, args[1:])
	case "enroll-link":
		err = cmdEnrollLink(ctx, *cfgPath, args[1:])
	case "mfa":
		err = cmdMFA(ctx, *cfgPath, args[1:])
	case "audit":
		err = cmdAudit(ctx, *cfgPath, args[1:])
	case "gen-key":
		err = cmdGenKey(args[1:])
	case "templates":
		err = cmdTemplates(*cfgPath, args[1:])
	case "check":
		err = cmdCheck(ctx, *cfgPath)
	case "version":
		fmt.Println("conductor-idp", version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		var ue usageError
		if errors.As(err, &ue) {
			fmt.Fprintln(os.Stderr, "conductor-idp:", err)
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "conductor-idp:", err)
		os.Exit(1)
	}
}

type usageError string

func (u usageError) Error() string { return string(u) }

func defaultConfigPath() string {
	if p := os.Getenv("CONDUCTOR_IDP_CONFIG"); p != "" {
		return p
	}
	return "/etc/conductor-idp/idp.toml"
}
