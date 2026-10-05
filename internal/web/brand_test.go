package web

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/png"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor-idp/branding"
	"github.com/openbasalt/samba-conductor-idp/internal/store"
)

func pngOf(w, h int) []byte {
	var buf bytes.Buffer
	_ = png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, w, h)))
	return buf.Bytes()
}

// testBranding is a full document with a logo, a favicon and a
// background image, and the images' bytes.
func testBranding(t *testing.T) (branding.Branding, []store.BrandingAsset) {
	t.Helper()
	b := branding.Branding{OrgName: "Example Org", PrimaryColor: "#1d4ed8", AccentColor: "#f59e0b",
		Texts: map[string]branding.Texts{
			"en":    {SignInTitle: "Sign in to Example", SignInNote: "Use your network account.", Help: "Forgot it? Call us.", Footer: "Example IT", Notice: "Maintenance on Saturday"},
			"pt-BR": {SignInTitle: "Entrar no Example", Notice: "Manutenção no sábado"}},
		Support: branding.Support{Email: "help@example.com", Phone: "+1 555 0100", URL: "https://help.example.com"},
		Links:   branding.Links{Help: "https://help.example.com", Terms: "https://example.com/terms", PasswordPolicy: "https://example.com/pw"},
		Assets:  map[string]branding.Asset{}}
	var assets []store.BrandingAsset
	for slot, data := range map[string][]byte{branding.SlotLogoLight: pngOf(120, 30), branding.SlotFavicon: pngOf(32, 32),
		branding.SlotBackground: pngOf(64, 48)} {
		a, err := branding.Inspect(slot, data)
		if err != nil {
			t.Fatal(err)
		}
		b.Assets[slot] = a
		assets = append(assets, store.BrandingAsset{SHA256: a.SHA256, ContentType: a.Type, Data: data})
	}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	return b, assets
}

func (h *harness) applyBranding(t *testing.T) branding.Branding {
	b, assets := testBranding(t)
	h.srv.ApplyBranding(4, b, time.Now(), "conductor", assets)
	return b
}

func TestBrandedSignIn(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	b := h.browser()
	b.get("/login")
	unbranded := b.last.Header.Get("Content-Security-Policy")
	if strings.Contains(b.body, "/branding/") || !strings.Contains(b.body, "Samba Conductor") {
		t.Fatal("a fresh idp should have the product look")
	}
	doc := h.applyBranding(t)
	b.get("/login")
	b.mustStatus(http.StatusOK)
	logo := "/branding/assets/" + doc.Assets[branding.SlotLogoLight].SHA256
	for _, want := range []string{"Example Org", `href="/branding/theme.css?v=`, `src="` + logo + `"`, "Sign in to Example",
		`data-e2e="signin-text-brand-note"`, `data-e2e="brand-text-notice">Maintenance on Saturday`, `class="brand-bg"`,
		`data-e2e="signin-link-help"`, `href="https://example.com/pw"`, `href="mailto:help@example.com"`, `href="tel:&#43;15550100"`,
		`data-e2e="brand-text-footer">Example IT`, `data-e2e="signin-input-username"`, `type="image/png"`} {
		b.mustContain(want)
	}
	// The policy is the same strict one: branding adds no source.
	if got := b.last.Header.Get("Content-Security-Policy"); got != unbranded || !strings.Contains(got, "script-src 'none'") {
		t.Fatalf("CSP changed: %q vs %q", got, unbranded)
	}
	// Per language, with the fallback to English for missing texts.
	b.get("/login?lang=pt-BR")
	b.mustContain("Entrar no Example")
	b.mustContain("Manutenção no sábado")
	b.mustContain("Use your network account.")

	// The stylesheet and the images are served from this origin, with
	// their types, cached by version, under the strict headers.
	css := b.get("/branding/theme.css?v=x")
	if css.Header.Get("Content-Type") != "text/css; charset=utf-8" || css.Header.Get("Cache-Control") != "no-cache" ||
		!strings.Contains(b.body, "--accent: #1d4ed8") || !strings.Contains(b.body, "background-image") {
		t.Fatalf("theme.css: %v %s", css.Header, b.body)
	}
	img := b.get(logo)
	if img.StatusCode != http.StatusOK || img.Header.Get("Content-Type") != "image/png" || img.Header.Get("X-Content-Type-Options") != "nosniff" ||
		!strings.Contains(img.Header.Get("Cache-Control"), "immutable") || !strings.Contains(img.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("asset: %d %v", img.StatusCode, img.Header)
	}
	if b.get("/branding/assets/" + strings.Repeat("0", 64)); b.last.StatusCode != http.StatusNotFound {
		t.Fatal("unknown asset served")
	}
	if b.get("/branding/custom.css"); b.last.StatusCode != http.StatusNotFound {
		t.Fatal("custom.css served without a template directory")
	}

	// The second-factor page of the flow keeps the look; the protocol
	// endpoints are not touched.
	disc := b.get("/.well-known/openid-configuration")
	if disc.StatusCode != http.StatusOK || strings.Contains(b.body, "Example") {
		t.Fatal("discovery changed")
	}
}

func TestAdminPagesNotBranded(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	h.applyBranding(t)
	b := h.adminBrowser()
	b.get("/admin/clients")
	b.mustStatus(http.StatusOK)
	if strings.Contains(b.body, "Example Org") || strings.Contains(b.body, "/branding/") || strings.Contains(b.body, "Maintenance") {
		t.Fatalf("admin page branded: %.400s", b.body)
	}
	// The public pages of the same listener are.
	b.get("/")
	b.mustContain("Example Org")

	// A separate admin listener: no branding at all, not even the files.
	s := newHarness(t, harnessOpts{admin: "split"})
	s.applyBranding(t)
	a := s.browserOn(s.adminTS, nil)
	a.get("/login")
	if strings.Contains(a.body, "Example Org") || strings.Contains(a.body, "/branding/") {
		t.Fatal("admin listener sign-in branded")
	}
	a.get("/branding/theme.css")
	mustNotFound(t, s, a, "theme.css on the admin listener")
	p := s.browser()
	p.get("/login")
	p.mustContain("Example Org")
}

func writeTemplate(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestTemplateOverrides(t *testing.T) {
	dir := t.TempDir()
	parts := BuiltinPartials()
	// A header override that works, a sign-in box that does not parse.
	header := strings.Replace(parts[0].Source, `<span>{{if .B}}{{.B.Name}}`, `<span class="custom-header">{{if .B}}{{.B.Name}}`, 1)
	writeTemplate(t, dir, "header.html", parts[0].Header()+"\n"+header)
	writeTemplate(t, dir, "signin-box.html", "{{.D.Username")
	writeTemplate(t, dir, "custom.css", `.brand span{letter-spacing:.02em}`)
	h := newHarness(t, harnessOpts{templatesDir: dir, admin: "split"})
	b := h.browser()
	b.get("/login")
	b.mustStatus(http.StatusOK)
	b.mustContain(`class="custom-header"`)
	b.mustContain(`data-e2e="signin-input-username"`)
	b.mustContain(`href="/branding/custom.css?v=`)
	css := b.get("/branding/custom.css")
	if css.StatusCode != http.StatusOK || !strings.Contains(b.body, "letter-spacing") {
		t.Fatal("custom.css not served")
	}
	// The admin listener keeps the built-in partials.
	a := h.browserOn(h.adminTS, nil)
	a.get("/login")
	if strings.Contains(a.body, "custom-header") || strings.Contains(a.body, "custom.css") {
		t.Fatal("override on the admin listener")
	}

	// Every built-in partial meets its own contract.
	for _, p := range parts {
		out, err := h.srv.renderPartial(p, p.Source)
		if err != nil {
			t.Fatal(err)
		}
		if issues := branding.CheckOutput(out, p.Required, nil); len(issues) > 0 {
			t.Errorf("%s: %v", p.Name, issues)
		}
	}
	findings, err := CheckTemplates(h.srv.cfg)
	if err != nil {
		t.Fatal(err)
	}
	levels := map[string]string{}
	for _, f := range findings {
		levels[f.File] = f.Level
	}
	if levels["header.html"] != branding.LevelOK || levels["signin-box.html"] != branding.LevelError || levels["custom.css"] != branding.LevelOK {
		t.Fatalf("%v", findings)
	}
}

// An override that renders with the sample data but fails on a real page
// falls back to the built-in partials for that response.
func TestTemplateOverrideRuntimeFallback(t *testing.T) {
	dir := t.TempDir()
	parts := BuiltinPartials()
	writeTemplate(t, dir, "header.html", strings.Replace(parts[0].Source, "<span>", `<span data-len="{{.User.Name}}">`, 1))
	h := newHarness(t, harnessOpts{templatesDir: dir})
	if len(h.srv.overridden) != 1 {
		t.Fatalf("override not accepted: %v", h.srv.overridden)
	}
	b := h.browser()
	b.get("/login")
	b.mustStatus(http.StatusOK)
	if strings.Contains(b.body, "data-len") {
		t.Fatal("broken override used")
	}
	b.mustContain(`data-e2e="nav-link-home"`)
}

func TestAllowedOriginsOnlyOnBrandedPages(t *testing.T) {
	h := newHarness(t, harnessOpts{allowed: []string{"https://cdn.example.com"}})
	h.applyBranding(t)
	b := h.browser()
	b.get("/login")
	csp := b.last.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "img-src 'self' https://cdn.example.com") || !strings.Contains(csp, "font-src 'self' https://cdn.example.com") ||
		!strings.Contains(csp, "script-src 'none'") || !strings.Contains(csp, "style-src 'self';") {
		t.Fatalf("branded CSP: %s", csp)
	}
	a := h.adminBrowser()
	a.get("/admin/clients")
	if strings.Contains(a.last.Header.Get("Content-Security-Policy"), "cdn.example.com") {
		t.Fatal("allowlist on an admin page")
	}
}

// The branding is read back from the database at startup (it works when
// conductor is down).
func TestBrandingFromStore(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	doc, assets := testBranding(t)
	data, _ := json.Marshal(doc)
	if err := h.store.PutBranding(context.Background(), 7, string(data), "conductor", assets); err != nil {
		t.Fatal(err)
	}
	h.srv.loadBranding(context.Background())
	b := h.browser()
	b.get("/login")
	b.mustContain("Example Org")
	if v := h.srv.brand.Load().version; v != 7 {
		t.Fatalf("version %d", v)
	}
	// A stored document that no longer validates gives the product look.
	doc.PrimaryColor = "#ffff00"
	data, _ = json.Marshal(doc)
	_ = h.store.PutBranding(context.Background(), 8, string(data), "conductor", assets)
	h.srv.loadBranding(context.Background())
	b.get("/login")
	if strings.Contains(b.body, "Example Org") {
		t.Fatal("invalid stored branding applied")
	}
	b.submit("/login", url.Values{"username": {"alice"}, "password": {"Passw0rd!alice"}})
	if b.last.StatusCode >= 400 {
		t.Fatal("sign-in broken")
	}
}
