package main

import (
	"fmt"
	"strings"

	"github.com/openbasalt/samba-conductor-idp/branding"
	"github.com/openbasalt/samba-conductor-idp/internal/config"
	"github.com/openbasalt/samba-conductor-idp/internal/web"
)

// cmdTemplates lists, shows and checks the template overrides of the
// user-facing pages (branding.templates_dir).
func cmdTemplates(cfgPath string, args []string) error {
	if len(args) == 0 {
		return usageError("templates list | templates show NAME | templates check")
	}
	switch args[0] {
	case "list":
		for _, p := range web.BuiltinPartials() {
			fmt.Printf("%-12s %-16s base=%s  %s\n", p.Name, p.File, p.Base(), p.Doc)
			fmt.Printf("    required: %s\n", strings.Join(p.Required, " "))
		}
		return nil
	case "show":
		if len(args) != 2 {
			return usageError("templates show NAME (see templates list)")
		}
		for _, p := range web.BuiltinPartials() {
			if p.Name == args[1] || p.File == args[1] {
				fmt.Println(p.Header())
				fmt.Print(p.Source)
				return nil
			}
		}
		return usageError("unknown partial " + args[1] + " (see templates list)")
	case "check":
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		return printTemplateCheck(cfg)
	}
	return usageError("templates list | templates show NAME | templates check")
}

// printTemplateCheck prints the findings of the template directory and
// fails when an override is refused or needs a review.
func printTemplateCheck(cfg *config.Config) error {
	if cfg.Branding.TemplatesDir == "" {
		fmt.Println("templates: no override directory (branding.templates_dir)")
		return nil
	}
	fs, err := web.CheckTemplates(cfg)
	if err != nil {
		return err
	}
	if len(fs) == 0 {
		fmt.Println("templates: " + cfg.Branding.TemplatesDir + " has no overrides")
		return nil
	}
	problems := 0
	for _, f := range fs {
		fmt.Println("templates: " + f.String())
		if f.Level != branding.LevelOK {
			problems++
		}
	}
	if problems > 0 {
		return fmt.Errorf("templates: %d override(s) refused or to review", problems)
	}
	return nil
}
