package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/openbasalt/samba-conductor-idp/branding"
	"github.com/openbasalt/samba-conductor-idp/internal/config"
	"github.com/openbasalt/samba-conductor-idp/internal/i18n"
	"github.com/openbasalt/samba-conductor-idp/internal/store"
)

// Branding of the user-facing pages (docs/decisions.md D15).
//
// Level 1 comes from conductor through the management API (stored in the
// database, so it survives a restart and works when conductor is down);
// level 2 is the template directory read at startup. Only the public
// listener's pages are branded, and never the admin pages: on the admin
// listener, and for admin routes on a shared listener, pages render with
// the product look and the built-in partials whatever is configured.

//go:embed templates/brand/*.html
var brandFS embed.FS

// brandState is the applied level 1 branding.
type brandState struct {
	version   int64
	doc       branding.Branding
	updatedAt time.Time
	updatedBy string
	css       []byte
	cssTag    string
	assets    map[string]store.BrandingAsset
}

// overridable partials and their contract (required strings of a sample
// rendering): the hooks the e2e suite and the sign-in flow rely on.
var partialSpecs = []struct {
	name, file, doc string
	required        []string
}{
	{"brand-header", "header.html", "page header: logo, organization name, signed-in user and sign-out",
		[]string{`data-e2e="nav-link-home"`, `href="/"`, `data-e2e="nav-btn-signout"`, `action="/logout"`, `name="csrf"`}},
	{"brand-footer", "footer.html", "page footer: footer text, links, support contact, language and theme",
		[]string{`data-e2e="footer-link-lang-en"`, `data-e2e="footer-link-lang-pt-br"`, `data-e2e="footer-link-theme-light"`,
			`data-e2e="footer-link-theme-dark"`, `data-e2e="footer-link-theme-system"`}},
	{"signin-box", "signin-box.html", "the sign-in card: title, notes, errors and the username and password form",
		[]string{`action="/login"`, `method="post"`, `name="csrf"`, `name="c"`, `name="enroll"`, `name="username"`, `name="password"`,
			`data-e2e="signin-input-username"`, `data-e2e="signin-input-password"`, `data-e2e="signin-btn-submit"`,
			`data-e2e="form-text-error"`, `<label for="username"`, `<label for="password"`}},
}

// BuiltinPartials returns the overridable partials with their built-in
// bodies (`conductor-idp templates show|list`).
func BuiltinPartials() []branding.Partial {
	var out []branding.Partial
	for _, p := range partialSpecs {
		src, err := brandFS.ReadFile("templates/brand/" + p.file)
		if err != nil {
			panic("web: missing built-in partial " + p.file)
		}
		out = append(out, branding.Partial{Name: p.name, File: p.file, Source: string(src), Required: p.required, Doc: p.doc})
	}
	return out
}

// signinPages show the sign-in background image.
var signinPages = []string{"login", "login_password", "login_2fa", "enroll", "logged_out", "logout_confirm", "recovery_codes"}

// samplePage is the data an override is checked with: every optional
// block on, so a broken reference shows up at startup.
func (s *Server) samplePage() pageData {
	return pageData{Lang: "en", CSRF: "sample-csrf", User: &userInfo{Name: "Sample User", SAM: "sample"}, Path: "/login",
		Version: s.version, Product: s.cfg.UI.ProductName, Query: url.Values{}, B: branding.SampleView(), BG: true,
		D: map[string]any{"C": "sample-continuation", "Enroll": "sample-enroll", "Error": "Sample error", "Username": "sample",
			"App": "Sample application", "Notice": "Sample notice"}}
}

// renderPartial renders a candidate partial body with the sample data,
// with the same functions and shared partials as the pages.
func (s *Server) renderPartial(p branding.Partial, body string) (string, error) {
	t, err := template.New("").Funcs(s.funcs("en")).ParseFS(templateFS, "templates/partials.html")
	if err != nil {
		return "", err
	}
	if _, err := t.Parse(branding.Define(p.Name, body)); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, p.Name, s.samplePage()); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// loadOverrides reads the template directory (level 2) and logs what it
// decided; refused overrides keep the built-in partials.
func (s *Server) loadOverrides() branding.Result {
	res := branding.Load(s.cfg.Branding.TemplatesDir, BuiltinPartials(), s.allowed, s.renderPartial)
	for _, f := range res.Findings {
		switch f.Level {
		case branding.LevelOK:
			s.log.Info("branding template", "file", f.File, "result", f.Message)
		default:
			s.log.Warn("branding template", "file", f.File, "level", f.Level, "result", f.Message)
		}
	}
	return res
}

// CheckTemplates checks the template directory of a configuration
// (`conductor-idp templates check`).
func CheckTemplates(cfg *config.Config) ([]branding.Finding, error) {
	cat, err := i18n.Load()
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, cat: cat, version: "check", allowed: cfg.AllowedOrigins()}
	return branding.Check(cfg.Branding.TemplatesDir, BuiltinPartials(), s.allowed, s.renderPartial), nil
}

// ApplyBranding makes a pushed branding effective at once.
func (s *Server) ApplyBranding(version int64, doc branding.Branding, updatedAt time.Time, by string, assets []store.BrandingAsset) {
	st := &brandState{version: version, doc: doc, updatedAt: updatedAt, updatedBy: by, assets: map[string]store.BrandingAsset{}}
	for _, a := range assets {
		st.assets[a.SHA256] = a
	}
	st.css = []byte(branding.CSS(doc, branding.PageScope, assetURL))
	st.cssTag = tag(st.css)
	s.brand.Store(st)
}

// loadBranding reads the stored branding at startup. A stored document
// that no longer validates is ignored (product look) with an error in the
// log: a bad branding must never stop users from signing in.
func (s *Server) loadBranding(ctx context.Context) {
	s.ApplyBranding(0, branding.Branding{}, time.Time{}, "", nil)
	row, err := s.store.GetBranding(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return
	}
	if err != nil {
		s.log.Error("branding: reading the stored branding failed; using the product look", "err", err)
		return
	}
	var doc branding.Branding
	if err := json.Unmarshal([]byte(row.Data), &doc); err != nil || doc.Validate() != nil {
		s.log.Error("branding: the stored branding is not valid; using the product look", "version", row.Version)
		return
	}
	assets, err := s.store.BrandingAssets(ctx)
	if err != nil {
		s.log.Error("branding: reading the stored images failed; using the product look", "err", err)
		return
	}
	s.ApplyBranding(row.Version, doc, row.UpdatedAt, row.UpdatedBy, assets)
}

func assetURL(a branding.Asset) string { return "/branding/assets/" + a.SHA256 }

func tag(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:6])
}

// branded reports whether this request's page gets the branding: the
// public listener only, and never an admin page.
func (rc *reqCtx) branded() bool {
	return rc.s.surface&surfacePublic != 0 && rc.route.on != surfaceAdmin && !strings.HasPrefix(rc.r.URL.Path, "/admin")
}

// brandView is the page's {{.B}}, or nil for the product look.
func (rc *reqCtx) brandView() *branding.View {
	if !rc.branded() {
		return nil
	}
	st := rc.s.brand.Load()
	if st == nil {
		return nil
	}
	if st.doc.IsZero() && len(rc.s.overridden) == 0 && rc.s.customCSS == nil {
		return nil
	}
	u := branding.URLs{CSS: "/branding/theme.css?v=" + st.cssTag, Asset: assetURL}
	if rc.s.customCSS != nil {
		u.CustomCSS = "/branding/custom.css?v=" + rc.s.customTag
	}
	return branding.NewView(st.doc, rc.lang, rc.s.cfg.UI.ProductName, u)
}

// brandRoutes registers the stylesheets and images of the branding
// (public listener only).
func (s *Server) brandRoutes() {
	s.mux.HandleFunc("GET /branding/theme.css", func(w http.ResponseWriter, r *http.Request) {
		st := s.brand.Load()
		s.serveVersioned(w, r, "text/css; charset=utf-8", st.css, st.cssTag)
	})
	s.mux.HandleFunc("GET /branding/custom.css", func(w http.ResponseWriter, r *http.Request) {
		if s.customCSS == nil {
			s.securityHeaders(w.Header())
			http.NotFound(w, r)
			return
		}
		s.serveVersioned(w, r, "text/css; charset=utf-8", s.customCSS, s.customTag)
	})
	s.mux.HandleFunc("GET /branding/assets/{sha}", func(w http.ResponseWriter, r *http.Request) {
		s.securityHeaders(w.Header())
		a, ok := s.brand.Load().assets[r.PathValue("sha")]
		if !ok || !slices.Contains([]string{branding.TypePNG, branding.TypeJPEG, branding.TypeWebP, branding.TypeICO}, a.ContentType) {
			http.NotFound(w, r)
			return
		}
		h := w.Header()
		h.Set("Content-Type", a.ContentType)
		// Addressed by its digest: the content never changes.
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
		h.Set("ETag", `"`+a.SHA256+`"`)
		if r.Header.Get("If-None-Match") == `"`+a.SHA256+`"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write(a.Data)
	})
}

// serveVersioned serves a generated file: cached for long when the URL
// names its current version, revalidated otherwise.
func (s *Server) serveVersioned(w http.ResponseWriter, r *http.Request, ctype string, body []byte, version string) {
	s.securityHeaders(w.Header())
	h := w.Header()
	h.Set("Content-Type", ctype)
	h.Set("ETag", `"`+version+`"`)
	if r.URL.Query().Get("v") == version {
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		h.Set("Cache-Control", "no-cache")
	}
	if r.Header.Get("If-None-Match") == `"`+version+`"` {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write(body)
}

// parsePage parses one page with the layout, the shared partials and the
// overridable partials: "product-<name>" is always the built-in body (the
// unbranded pages use it), "<name>" the body chosen at startup.
func (s *Server) parsePage(lang, file string, bodies map[string]string) (*template.Template, error) {
	t, err := template.New("").Funcs(s.funcs(lang)).ParseFS(templateFS, "templates/layout.html", "templates/partials.html", file)
	if err != nil {
		return nil, err
	}
	for _, p := range BuiltinPartials() {
		if _, err := t.Parse(branding.Define("product-"+p.Name, p.Source)); err != nil {
			return nil, err
		}
		body, ok := bodies[p.Name]
		if !ok {
			body = p.Source
		}
		if _, err := t.Parse(branding.Define(p.Name, body)); err != nil {
			return nil, err
		}
	}
	return t, nil
}

// pageNames lists the page templates (every file but the shared ones).
func pageNames() ([]string, error) {
	names, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, n := range names {
		base := strings.TrimSuffix(path.Base(n), ".html")
		if base != "layout" && base != "partials" {
			out = append(out, n)
		}
	}
	return out, nil
}
