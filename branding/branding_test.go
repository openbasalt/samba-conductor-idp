package branding

import (
	"bytes"
	"encoding/binary"
	"errors"
	"html/template"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func codes(ps []Problem) []string {
	var out []string
	for _, p := range ps {
		out = append(out, p.Field+":"+p.Code)
	}
	return out
}

func TestContrast(t *testing.T) {
	if r := Contrast("#000000", "#ffffff"); r < 20.9 || r > 21.01 {
		t.Fatalf("black on white: %v", r)
	}
	if r := Contrast("#777777", "#ffffff"); r > 4.5 {
		t.Fatalf("#777 on white should fail AA: %v", r)
	}
	// The product's own accent passes.
	b := Branding{PrimaryColor: "#0f766e", AccentColor: "#0f766e"}
	if ps := b.Check(); len(ps) != 0 {
		t.Fatalf("product colors: %v", ps)
	}
	// A light primary is refused (links would be unreadable).
	b = Branding{PrimaryColor: "#ffcc00"}
	if got := codes(Errors(b.Check())); !slices.Equal(got, []string{"primary_color:contrast"}) {
		t.Fatalf("light primary: %v", got)
	}
	// A pale accent is only a warning.
	b = Branding{AccentColor: "#f0f0f0"}
	ps := b.Check()
	if len(ps) != 1 || !ps[0].Warning || ps[0].Code != CodeAccent || len(Errors(ps)) != 0 {
		t.Fatalf("pale accent: %v", ps)
	}
	if (Branding{PrimaryColor: "red"}).Validate() == nil || (Branding{PrimaryColor: "#12345"}).Validate() == nil {
		t.Fatal("bad color formats accepted")
	}
	// Automatic text colors always reach AA, on any background.
	for _, c := range []string{"#777777", "#808080", "#0000ff", "#ffff00", "#ff0000", "#00ff00", "#123456"} {
		bg := mustColor(c)
		if r := contrast(textOn(bg), bg); r < 4.5 {
			t.Errorf("text on %s: %.2f", c, r)
		}
		if r := minContrast(forDark(bg), darkBG, darkSurface); r < 4.5 {
			t.Errorf("dark variant of %s: %.2f", c, r)
		}
	}
}

func TestLinksAndContact(t *testing.T) {
	good := []string{"https://example.com/help", "mailto:help@example.com", "tel:+55 11 5555-0100"}
	bad := []string{"http://example.com", "javascript:alert(1)", "https://user:pw@example.com", "//example.com",
		"https://exa mple.com", "data:text/html,x", "mailto:not an address", "tel:call me", "ftp://example.com", "https://"}
	for _, v := range good {
		if !ValidLink(v) {
			t.Errorf("refused %q", v)
		}
	}
	for _, v := range bad {
		if ValidLink(v) {
			t.Errorf("accepted %q", v)
		}
	}
	b := Branding{Support: Support{Email: "x@y", Phone: "abc", URL: "http://x.example"},
		Links: Links{Terms: "javascript:x"}}
	got := codes(b.Check())
	for _, want := range []string{"support_email:email", "support_phone:phone", "support_url:url", "link_terms:url"} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	if TelURL("+55 (11) 5555-0100") != "tel:+551155550100" {
		t.Fatal(TelURL("+55 (11) 5555-0100"))
	}
}

func TestTextLimitsAndLanguages(t *testing.T) {
	b := Branding{OrgName: strings.Repeat("x", MaxOrgName+1), Texts: map[string]Texts{
		"en": {SignInNote: "line one\nline two", Footer: "bad\x07bell"}, "de": {Notice: "x"}}}
	got := codes(b.Check())
	for _, want := range []string{"org_name:too_long", "footer_en:control_chars", "texts:language"} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	if slices.Contains(got, "signin_note_en:control_chars") {
		t.Error("line breaks refused in a multi-line text")
	}
	if (Branding{OrgName: "line\nbreak"}).Validate() == nil {
		t.Error("line break accepted in the name")
	}
	// Fallbacks per field: the language, then English, then any.
	b = Branding{Texts: map[string]Texts{"en": {SignInTitle: "Welcome", Footer: "Footer"}, "pt-BR": {SignInTitle: "Bem-vindo",
		Notice: "Aviso"}}}
	if tx := b.Text("pt-BR"); tx.SignInTitle != "Bem-vindo" || tx.Footer != "Footer" || tx.Notice != "Aviso" {
		t.Fatalf("pt-BR: %+v", tx)
	}
	if tx := b.Text("en"); tx.SignInTitle != "Welcome" || tx.Notice != "Aviso" {
		t.Fatalf("en: %+v", tx)
	}
	n := Branding{OrgName: "  Org ", PrimaryColor: "#ABCDEF", Texts: map[string]Texts{"en": {Help: " a\r\nb "}, "pt-BR": {}}}.Normalize()
	if n.OrgName != "Org" || n.PrimaryColor != "#abcdef" || n.Texts["en"].Help != "a\nb" || len(n.Texts) != 1 {
		t.Fatalf("normalize: %+v", n)
	}
	if !(Branding{}).IsZero() || n.IsZero() {
		t.Fatal("IsZero")
	}
}

func pngBytes(t *testing.T, w, h int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func jpegBytes(t *testing.T, w, h int) []byte {
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, image.NewRGBA(image.Rect(0, 0, w, h)), nil); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// webpVP8X builds a minimal WebP header with the extended chunk.
func webpVP8X(w, h int) []byte {
	b := make([]byte, 30)
	copy(b, "RIFF")
	binary.LittleEndian.PutUint32(b[4:], 22)
	copy(b[8:], "WEBPVP8X")
	binary.LittleEndian.PutUint32(b[16:], 10)
	put24 := func(o, v int) { b[o], b[o+1], b[o+2] = byte(v), byte(v>>8), byte(v>>16) }
	put24(24, w-1)
	put24(27, h-1)
	return b
}

func webpVP8L(w, h int) []byte {
	b := make([]byte, 30)
	copy(b, "RIFF")
	binary.LittleEndian.PutUint32(b[4:], 22)
	copy(b[8:], "WEBPVP8L")
	binary.LittleEndian.PutUint32(b[16:], 10)
	b[20] = 0x2f
	binary.LittleEndian.PutUint32(b[21:], uint32(w-1)|uint32(h-1)<<14)
	return b
}

func ico(w, h int) []byte {
	payload := pngBytesRaw(w, h)
	b := make([]byte, 6+16)
	binary.LittleEndian.PutUint16(b[2:], 1)
	binary.LittleEndian.PutUint16(b[4:], 1)
	b[6], b[7] = byte(w), byte(h)
	binary.LittleEndian.PutUint32(b[6+8:], uint32(len(payload)))
	binary.LittleEndian.PutUint32(b[6+12:], 22)
	return append(b, payload...)
}

func pngBytesRaw(w, h int) []byte {
	var buf bytes.Buffer
	_ = png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, w, h)))
	return buf.Bytes()
}

func TestInspect(t *testing.T) {
	cases := []struct {
		slot string
		data []byte
		typ  string
		code string
	}{
		{SlotLogoLight, pngBytes(t, 200, 50), TypePNG, ""},
		{SlotLogoDark, jpegBytes(t, 120, 40), TypeJPEG, ""},
		{SlotBackground, webpVP8X(1920, 1080), TypeWebP, ""},
		{SlotLogoLight, webpVP8L(300, 100), TypeWebP, ""},
		{SlotFavicon, ico(32, 32), TypeICO, ""},
		{SlotFavicon, pngBytes(t, 64, 64), TypePNG, ""},
		{SlotFavicon, jpegBytes(t, 32, 32), "", CodeImageType},
		{SlotLogoLight, ico(32, 32), "", CodeImageType},
		{SlotLogoLight, []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`), "", CodeSVG},
		{SlotLogoLight, []byte("\xef\xbb\xbf  <?xml version=\"1.0\"?><svg/>"), "", CodeSVG},
		{SlotLogoLight, []byte("<html><body>x</body></html>"), "", CodeImageType},
		{SlotLogoLight, []byte("GIF89a....."), "", CodeImageType},
		{SlotLogoLight, pngBytes(t, 4000, 10), "", CodeImageDims},
		{SlotFavicon, pngBytes(t, 512, 512), "", CodeImageDims},
		{SlotLogoLight, append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 40)...), "", CodeImageCorrupt},
		{SlotLogoLight, make([]byte, 300<<10), "", CodeImageSize},
		{"banner", pngBytes(t, 10, 10), "", CodeSlot},
	}
	for i, c := range cases {
		a, err := Inspect(c.slot, c.data)
		if c.code != "" {
			var se *SlotError
			if !errors.As(err, &se) || se.Code != c.code {
				t.Errorf("case %d (%s): err %v, want %s", i, c.slot, err, c.code)
			}
			continue
		}
		if err != nil || a.Type != c.typ || a.SHA256 != Digest(c.data) || a.Size != len(c.data) || a.Width == 0 {
			t.Errorf("case %d (%s): %+v %v", i, c.slot, a, err)
		}
	}
	a, _ := Inspect(SlotBackground, webpVP8X(1920, 1080))
	if a.Width != 1920 || a.Height != 1080 {
		t.Fatalf("webp size %dx%d", a.Width, a.Height)
	}
	// An asset description outside its slot's limits is refused.
	b := Branding{Assets: map[string]Asset{SlotFavicon: {SHA256: strings.Repeat("a", 64), Type: TypeJPEG, Size: 10, Width: 1, Height: 1}}}
	if b.Validate() == nil {
		t.Fatal("jpeg favicon accepted")
	}
}

func TestCSS(t *testing.T) {
	sha := strings.Repeat("b", 64)
	b := Branding{PrimaryColor: "#1d4ed8", AccentColor: "#f59e0b",
		Assets: map[string]Asset{SlotBackground: {SHA256: sha, Type: TypeJPEG, Size: 10, Width: 10, Height: 10}}}
	css := CSS(b, PageScope, func(a Asset) string { return "/branding/assets/" + a.SHA256 })
	for _, want := range []string{":root {", "--accent: #1d4ed8", "--accent-fg: #ffffff", "--brand-accent: #f59e0b",
		"--brand-accent-fg: #000000", "@media (prefers-color-scheme: dark)", `:root[data-theme="dark"]`,
		`.brand-bg {`, `url("/branding/assets/` + sha + `")`} {
		if !strings.Contains(css, want) {
			t.Errorf("css lacks %q:\n%s", want, css)
		}
	}
	// A URL with unexpected characters is never written into the CSS.
	css = CSS(b, PageScope, func(Asset) string { return `/x");}body{x:url("` })
	if strings.Contains(css, "body{") || strings.Contains(css, "background-image") {
		t.Fatalf("unsafe url written: %s", css)
	}
	if css := CSS(Branding{}, PageScope, nil); strings.Contains(css, "{") {
		t.Fatalf("empty branding should generate no rule: %s", css)
	}
	prev := CSS(Branding{}, PreviewScope, nil)
	if !strings.Contains(prev, ".brand-preview.preview-dark {") || !strings.Contains(prev, "--accent: #2dd4bf") {
		t.Fatalf("preview dark palette: %s", prev)
	}
}

func TestView(t *testing.T) {
	sha := strings.Repeat("c", 64)
	b := Branding{OrgName: "", Support: Support{Phone: "+1 555 0100", Email: "help@example.com"},
		Links:  Links{Help: "tel:+15550100", Privacy: "https://example.com/p"},
		Assets: map[string]Asset{SlotLogoLight: {SHA256: sha, Type: TypePNG}, SlotFavicon: {SHA256: sha, Type: TypeICO}}}
	v := NewView(b, "en", "Samba Conductor", URLs{CSS: "/branding/theme.css", Asset: func(a Asset) string { return "/a/" + a.SHA256 }})
	if v.Name != "Samba Conductor" || v.LogoDark != v.LogoLight || v.FaviconType != TypeICO || v.SupportTel != "tel:+15550100" ||
		v.HelpURL != "tel:+15550100" || !v.HasLinks || !v.HasSupport || v.Background {
		t.Fatalf("%+v", v)
	}
	// html/template keeps the tel: link because it is typed as safe.
	var buf bytes.Buffer
	tp := template.Must(template.New("x").Parse(`<a href="{{.HelpURL}}">h</a><a href="{{.SupportTel}}">t</a>`))
	if err := tp.Execute(&buf, v); err != nil || strings.Contains(buf.String(), "ZgotmplZ") {
		t.Fatalf("%s %v", buf.String(), err)
	}
}

// ---- level 2 ----

var testPartials = []Partial{
	{Name: "brand-header", File: "header.html", Source: `<header><a href="/" data-e2e="nav-link-home">{{.Name}}</a></header>`,
		Required: []string{`data-e2e="nav-link-home"`}},
	{Name: "signin-box", File: "signin-box.html", Source: `<form method="post" action="/login"><input name="username" data-e2e="signin-input-username"></form>`,
		Required: []string{`action="/login"`, `data-e2e="signin-input-username"`}},
}

func testRender(p Partial, body string) (string, error) {
	t, err := template.New("").Parse(Define(p.Name, body))
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, p.Name, map[string]any{"Name": "Org"}); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func writeFile(t *testing.T, dir, name, body string) {
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func levels(fs []Finding) map[string]string {
	out := map[string]string{}
	for _, f := range fs {
		out[f.File] = f.Level
	}
	return out
}

func TestLoadOverrides(t *testing.T) {
	h, s := testPartials[0], testPartials[1]
	dir := t.TempDir()
	// A good override written against the current base.
	writeFile(t, dir, "header.html", h.Header()+"\n"+`<header class="x"><a href="/" data-e2e="nav-link-home">{{.Name}} portal</a></header>`)
	// An override that breaks the contract falls back to the built-in.
	writeFile(t, dir, "signin-box.html", s.Header()+"\n"+`<form method="post" action="/login"><input name="user"></form>`)
	writeFile(t, dir, "notes.txt", "x")
	writeFile(t, dir, "README.md", "x")
	r := Load(dir, testPartials, nil, testRender)
	if r.Bodies["signin-box"] != s.Source || !strings.Contains(r.Bodies["brand-header"], "portal") ||
		!slices.Equal(r.Overridden, []string{"brand-header"}) {
		t.Fatalf("%+v", r)
	}
	lv := levels(r.Findings)
	if lv["header.html"] != LevelOK || lv["signin-box.html"] != LevelError || lv["notes.txt"] != LevelWarning || lv["README.md"] != "" {
		t.Fatalf("%v", r.Findings)
	}
	if !r.HasErrors() {
		t.Fatal("HasErrors")
	}

	// Parse error, execution error, lint and a changed base.
	for name, body := range map[string]string{
		"parse":  `<header>{{.Name</header>`,
		"exec":   `<header>{{.Name.Missing}}</header>`,
		"script": `<header data-e2e="nav-link-home"><script>x</script></header>`,
		"style":  `<header data-e2e="nav-link-home" style="color:red"></header>`,
		"onload": `<header data-e2e="nav-link-home"><img alt="" src="/x" onerror="x"></header>`,
		"nonce":  `<header data-e2e="nav-link-home">{{.Nonce}}</header>`,
		"define": `{{define "x"}}{{end}}<header data-e2e="nav-link-home"></header>`,
		"extimg": `<header data-e2e="nav-link-home"><img alt="" src="https://cdn.example.com/logo.png"></header>`,
		"noalt":  `<header data-e2e="nav-link-home"><img src="/logo.png"></header>`,
		"jsurl":  `<header data-e2e="nav-link-home"><a href="javascript:x">x</a></header>`,
		"post":   `<header data-e2e="nav-link-home"><form action="https://evil.example/">x</form></header>`,
	} {
		d := t.TempDir()
		writeFile(t, d, "header.html", body)
		r := Load(d, testPartials, nil, testRender)
		if r.Bodies["brand-header"] != h.Source || levels(r.Findings)["header.html"] != LevelError {
			t.Errorf("%s: not refused: %v", name, r.Findings)
		}
	}
	// An allowlisted image origin is accepted; no header and an old base
	// are warnings, the override stays in use.
	d := t.TempDir()
	writeFile(t, d, "header.html", `<header data-e2e="nav-link-home"><img alt="" src="https://cdn.example.com/logo.png"></header>`)
	r = Load(d, testPartials, []string{"https://cdn.example.com"}, testRender)
	if !slices.Equal(r.Overridden, []string{"brand-header"}) || levels(r.Findings)["header.html"] != LevelWarning {
		t.Fatalf("allowlisted: %v", r.Findings)
	}
	writeFile(t, d, "header.html", "{{/* samba-conductor template header.html base=0000000000000000 */}}\n"+
		`<header data-e2e="nav-link-home"></header>`)
	r = Load(d, testPartials, nil, testRender)
	if !slices.Equal(r.Overridden, []string{"brand-header"}) || !strings.Contains(r.Findings[0].Message, "changed") {
		t.Fatalf("old base: %v", r.Findings)
	}
	// A missing directory keeps every built-in partial.
	r = Load(filepath.Join(d, "nope"), testPartials, nil, testRender)
	if r.Bodies["brand-header"] != h.Source || levels(r.Findings)[filepath.Join(d, "nope")] != LevelError {
		t.Fatalf("missing dir: %+v", r)
	}
	if r := Load("", testPartials, nil, testRender); len(r.Findings) != 0 || r.Bodies["signin-box"] != s.Source {
		t.Fatal("no directory")
	}
}

func TestCustomCSSAndOrigins(t *testing.T) {
	allowed, err := ParseOrigins([]string{"https://Fonts.Example.com", "https://cdn.example.com:8443/"})
	if err != nil || !slices.Equal(allowed, []string{"https://fonts.example.com", "https://cdn.example.com:8443"}) {
		t.Fatalf("%v %v", allowed, err)
	}
	for _, o := range []string{"http://x.example", "https://x.example/path", "*", "https://*.example.com", "https://a;b"} {
		if _, err := ParseOrigins([]string{o}); err == nil {
			t.Errorf("accepted origin %q", o)
		}
	}
	ok := []string{`@font-face{font-family:X;src:url("https://fonts.example.com/x.woff2")}`, `.brand{background:url(/branding/assets/abc)}`}
	bad := []string{`@import url("/x.css");`, `a{background:url(https://evil.example/x.png)}`, `a{background:url(//evil.example/x)}`,
		`a{background:url("data:image/png;base64,xx")}`, `a{x:expression(alert(1))}`, `</style><script>`}
	for _, c := range ok {
		if err := CheckCSS(c, allowed); err != nil {
			t.Errorf("refused %q: %v", c, err)
		}
	}
	for _, c := range bad {
		if CheckCSS(c, allowed) == nil {
			t.Errorf("accepted %q", c)
		}
	}
	d := t.TempDir()
	writeFile(t, d, CustomCSSFile, ok[0])
	if r := Load(d, testPartials, allowed, testRender); string(r.CustomCSS) != ok[0] {
		t.Fatalf("custom css: %+v", r.Findings)
	}
	writeFile(t, d, CustomCSSFile, bad[1])
	if r := Load(d, testPartials, allowed, testRender); r.CustomCSS != nil || levels(r.Findings)[CustomCSSFile] != LevelError {
		t.Fatalf("bad custom css: %+v", r.Findings)
	}
}
