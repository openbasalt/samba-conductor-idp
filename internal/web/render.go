package web

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/openbasalt/samba-conductor-idp/branding"
	"github.com/openbasalt/samba-conductor-idp/internal/i18n"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// pageData is what every template receives.
type pageData struct {
	Lang    string
	Theme   string
	CSRF    string
	User    *userInfo
	Flashes []flash
	Path    string
	Version string
	Product string
	Query   url.Values
	D       map[string]any
	// Nonce and ScriptSRI load the WebAuthn script (second-factor page
	// with a security key only); empty everywhere else.
	Nonce     string
	ScriptSRI string
	// B is the branding of a user-facing page (nil: the product look,
	// always on admin pages); BG shows its sign-in background image.
	B  *branding.View
	BG bool
}

type userInfo struct {
	Name  string
	SAM   string
	Admin bool
}

var e2eRE = regexp.MustCompile(`[^a-z0-9]+`)

// e2eID turns any value into a safe data-e2e suffix.
func e2eID(v any) string {
	s := strings.Trim(e2eRE.ReplaceAllString(strings.ToLower(fmt.Sprint(v)), "-"), "-")
	if s == "" {
		return "x"
	}
	return s
}

func (s *Server) funcs(lang string) template.FuncMap {
	return template.FuncMap{
		"t":   func(key string, args ...any) string { return s.cat.T(lang, key, args...) },
		"e2e": e2eID,
		"time": func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			return t.UTC().Format("2006-01-02 15:04 UTC")
		},
		"join": strings.Join,
		// pref links to the current page with one UI preference changed,
		// keeping the rest of the query (a sign-in flow's continuation).
		"pref": func(q url.Values, key, value string) template.URL {
			v := url.Values{}
			for k, vals := range q {
				if k != "lang" && k != "theme" && k != "m" && len(vals) > 0 {
					v.Set(k, vals[0])
				}
			}
			v.Set(key, value)
			return template.URL("?" + v.Encode())
		},
		"langs": func() []string { return i18n.Languages },
		"dict": func(kv ...any) map[string]any {
			m := map[string]any{}
			for i := 0; i+1 < len(kv); i += 2 {
				m[fmt.Sprint(kv[i])] = kv[i+1]
			}
			return m
		},
		"list": func(v ...string) []string { return v },
		"has": func(list []string, v string) bool {
			for _, x := range list {
				if x == v {
					return true
				}
			}
			return false
		},
	}
}

// loadTemplates parses every page with the layout, once per language,
// with the partial bodies chosen at startup (bodies nil: the built-in
// ones).
func (s *Server) loadTemplates(bodies map[string]string) (map[string]map[string]*template.Template, error) {
	names, err := pageNames()
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]*template.Template{}
	for _, lang := range i18n.Languages {
		out[lang] = map[string]*template.Template{}
		for _, n := range names {
			t, err := s.parsePage(lang, n, bodies)
			if err != nil {
				return nil, fmt.Errorf("web: template %s: %w", n, err)
			}
			out[lang][strings.TrimSuffix(path.Base(n), ".html")] = t
		}
	}
	return out, nil
}

// render executes a page into a buffer first, so a template error never
// sends half a page.
func (rc *reqCtx) render(status int, page string, d map[string]any) {
	t, ok := rc.s.tmpl[rc.lang][page]
	if !ok {
		rc.s.log.Error("unknown template", "page", page)
		http.Error(rc.w, "internal error", http.StatusInternalServerError)
		return
	}
	pd := pageData{Lang: rc.lang, Theme: rc.theme, Path: rc.r.URL.Path, Version: rc.s.version, Product: rc.s.cfg.UI.ProductName,
		Query: rc.r.URL.Query(), D: d, B: rc.brandView(), BG: slices.Contains(signinPages, page)}
	if rc.nonce != "" && d["KeyOptions"] != nil {
		pd.Nonce, pd.ScriptSRI = rc.nonce, rc.s.scriptSRI
	}
	if rc.sess != nil {
		rc.sess.mu.Lock()
		pd.CSRF = rc.sess.csrf
		if rc.sess.stage == stageFull {
			pd.User = &userInfo{Name: rc.sess.name, SAM: rc.sess.sam, Admin: rc.sess.admin && rc.sess.mfaVerified}
		}
		rc.sess.mu.Unlock()
		pd.Flashes = rc.sess.takeFlashes()
	}
	if pd.CSRF == "" {
		if c, err := rc.r.Cookie(rc.s.preName); err == nil {
			pd.CSRF = c.Value
		}
	}
	var buf bytes.Buffer
	err := t.ExecuteTemplate(&buf, "layout", pd)
	if err != nil && pd.B != nil && len(rc.s.overridden) > 0 {
		// A template override failed on this page's data: fall back to
		// the built-in partials (the startup check renders overrides
		// with sample data only).
		rc.s.log.Warn("branding template override failed; using the built-in partials", "page", page, "err", err)
		buf.Reset()
		err = rc.s.tmplBuiltin[rc.lang][page].ExecuteTemplate(&buf, "layout", pd)
	}
	if err != nil {
		rc.s.log.Error("template execution failed", "page", page, "err", err)
		http.Error(rc.w, "internal error", http.StatusInternalServerError)
		return
	}
	var extra []string
	if pd.B != nil {
		extra = rc.s.allowed
	}
	if len(rc.formTargets) > 0 || pd.Nonce != "" || len(extra) > 0 {
		rc.w.Header().Set("Content-Security-Policy", csp(rc.formTargets, pd.Nonce, extra...))
	}
	rc.w.Header().Set("Content-Type", "text/html; charset=utf-8")
	rc.w.WriteHeader(status)
	_, _ = rc.w.Write(buf.Bytes())
}

// errorPage shows a translated error with no internal detail.
func (rc *reqCtx) errorPage(status int, key string) {
	rc.render(status, "error", map[string]any{"Status": status, "Message": rc.T(key)})
}

// staticHandler serves the embedded CSS and images.
func (s *Server) staticHandler() http.Handler {
	sub, _ := fs.Sub(staticFS, "static")
	files := http.FileServerFS(sub)
	return http.StripPrefix("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.securityHeaders(w.Header())
		if r.URL.Path == "" || strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=3600")
		files.ServeHTTP(w, r)
	}))
}
