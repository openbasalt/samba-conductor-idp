// Package branding is the organization look of the pages users see:
// conductor-idp's sign-in, second-factor, consent and logout pages and
// conductor's self-service portal. It holds no HTTP or storage code, so
// both programs (and conductor's admin UI, which edits it) share one set
// of types, limits and checks.
//
// Two levels:
//
//   - Level 1, a Branding document edited from conductor's admin UI:
//     organization name, logos, favicon, colors, texts per language,
//     support contact and links. Colors become CSS custom properties in a
//     generated same-origin stylesheet (CSS), so the strict CSP stays as
//     it is: no inline style, no inline script. Images are checked by
//     content (Inspect): PNG, JPEG, WebP and ICO only, SVG refused.
//   - Level 2, template overrides read from a directory on the server
//     (Load): named partials replace the built-in ones, with html/template
//     auto-escaping, a lint that refuses scripts, inline styles and event
//     handlers, a contract of required data-e2e hooks checked by rendering
//     a sample, and a base hash that reports overrides whose built-in
//     partial changed after an upgrade.
package branding

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Languages are the languages of the texts (the UI's languages).
var Languages = []string{"en", "pt-BR"}

// Asset slots.
const (
	SlotLogoLight  = "logo_light"
	SlotLogoDark   = "logo_dark"
	SlotFavicon    = "favicon"
	SlotBackground = "background"
)

// Slots lists the image slots in display order.
var Slots = []string{SlotLogoLight, SlotLogoDark, SlotFavicon, SlotBackground}

// Bounds of the texts, in characters.
const (
	MaxOrgName     = 100
	MaxSignInTitle = 120
	MaxSignInNote  = 1000
	MaxHelp        = 2000
	MaxFooter      = 500
	MaxNotice      = 500
	MaxEmail       = 254
	MaxPhone       = 32
	MaxURL         = 2048
)

// Branding is the level 1 document. The zero value is the product look.
type Branding struct {
	// OrgName replaces the product name in the header and page titles.
	OrgName string `json:"org_name,omitempty"`
	// PrimaryColor ("#rrggbb") colors buttons, links and the current
	// navigation entry; AccentColor the header line and the notice
	// banner. Empty keeps the product colors.
	PrimaryColor string `json:"primary_color,omitempty"`
	AccentColor  string `json:"accent_color,omitempty"`
	// Texts per language ("en", "pt-BR").
	Texts   map[string]Texts `json:"texts,omitempty"`
	Support Support          `json:"support"`
	Links   Links            `json:"links"`
	// Assets are the images by slot (Slots); the bytes travel and are
	// stored apart, addressed by their SHA-256.
	Assets map[string]Asset `json:"assets,omitempty"`
}

// Texts are the texts of one language. Multi-line texts keep their line
// breaks; nothing is interpreted as markup.
type Texts struct {
	SignInTitle string `json:"signin_title,omitempty"`
	SignInNote  string `json:"signin_note,omitempty"`
	Help        string `json:"help,omitempty"`
	Footer      string `json:"footer,omitempty"`
	// Notice is a banner on every branded page (for example a
	// maintenance window).
	Notice string `json:"notice,omitempty"`
}

// Support is the contact users are pointed to.
type Support struct {
	Email string `json:"email,omitempty"`
	Phone string `json:"phone,omitempty"`
	URL   string `json:"url,omitempty"`
}

// Links are the organization's pages. https, mailto: or tel: only.
type Links struct {
	Help           string `json:"help,omitempty"`
	Terms          string `json:"terms,omitempty"`
	Privacy        string `json:"privacy,omitempty"`
	PasswordPolicy string `json:"password_policy,omitempty"`
}

// Asset describes a stored image (never its bytes).
type Asset struct {
	SHA256 string `json:"sha256"`
	Type   string `json:"type"`
	Size   int    `json:"size"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
}

// IsZero reports whether b is the product look.
func (b Branding) IsZero() bool {
	if b.OrgName != "" || b.PrimaryColor != "" || b.AccentColor != "" || b.Support != (Support{}) || b.Links != (Links{}) || len(b.Assets) > 0 {
		return false
	}
	for _, t := range b.Texts {
		if t != (Texts{}) {
			return false
		}
	}
	return true
}

// Normalize trims the texts, lowercases the colors, turns CRLF into LF and
// drops empty languages, so equal documents compare equal.
func (b Branding) Normalize() Branding {
	trim := func(s string) string { return strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n")) }
	out := Branding{OrgName: trim(b.OrgName), PrimaryColor: strings.ToLower(trim(b.PrimaryColor)),
		AccentColor: strings.ToLower(trim(b.AccentColor)),
		Support:     Support{Email: trim(b.Support.Email), Phone: trim(b.Support.Phone), URL: trim(b.Support.URL)},
		Links: Links{Help: trim(b.Links.Help), Terms: trim(b.Links.Terms), Privacy: trim(b.Links.Privacy),
			PasswordPolicy: trim(b.Links.PasswordPolicy)}}
	for lang, t := range b.Texts {
		n := Texts{SignInTitle: trim(t.SignInTitle), SignInNote: trim(t.SignInNote), Help: trim(t.Help), Footer: trim(t.Footer),
			Notice: trim(t.Notice)}
		if n != (Texts{}) {
			if out.Texts == nil {
				out.Texts = map[string]Texts{}
			}
			out.Texts[lang] = n
		}
	}
	for slot, a := range b.Assets {
		if out.Assets == nil {
			out.Assets = map[string]Asset{}
		}
		out.Assets[slot] = a
	}
	return out
}

// Problem is one finding of Check. Code names it for translation
// ("branding.problem.<code>" in the UIs); Field is the form field.
type Problem struct {
	Field   string
	Code    string
	Arg     string
	Warning bool
}

func (p Problem) String() string {
	s := p.Field + ": " + p.Code
	if p.Arg != "" {
		s += " (" + p.Arg + ")"
	}
	return s
}

// Problem codes.
const (
	CodeTooLong       = "too_long"
	CodeControl       = "control_chars"
	CodeColor         = "color_format"
	CodeContrast      = "contrast"
	CodeAccent        = "accent_contrast"
	CodeURL           = "url"
	CodeEmail         = "email"
	CodePhone         = "phone"
	CodeLanguage      = "language"
	CodeSlot          = "slot"
	CodeAsset         = "asset"
	CodeSVG           = "svg_refused"
	CodeImageType     = "image_type"
	CodeImageSize     = "image_size"
	CodeImageDims     = "image_dimensions"
	CodeImageCorrupt  = "image_corrupt"
	CodeTooManyAssets = "too_many_assets"
)

var (
	colorRE = regexp.MustCompile(`^#[0-9a-f]{6}$`)
	shaRE   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	emailRE = regexp.MustCompile(`^[A-Za-z0-9.!#$%&*+/=?^_{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$`)
	phoneRE = regexp.MustCompile(`^\+?[0-9][0-9 ().-]{2,30}$`)
)

// Check returns every problem of b (call Normalize first). Problems that
// are not warnings make the document invalid; warnings are shown before
// saving.
func (b Branding) Check() []Problem {
	var ps []Problem
	add := func(field, code, arg string, warn bool) {
		ps = append(ps, Problem{Field: field, Code: code, Arg: arg, Warning: warn})
	}
	text := func(field, v string, max int, multiline bool) {
		if utf8.RuneCountInString(v) > max || !utf8.ValidString(v) {
			add(field, CodeTooLong, fmt.Sprint(max), false)
			return
		}
		for _, r := range v {
			if r == '\n' && multiline {
				continue
			}
			if unicode.IsControl(r) || r == ' ' || r == ' ' {
				add(field, CodeControl, "", false)
				return
			}
		}
	}
	text("org_name", b.OrgName, MaxOrgName, false)
	for _, c := range []struct{ field, v string }{{"primary_color", b.PrimaryColor}, {"accent_color", b.AccentColor}} {
		if c.v != "" && !colorRE.MatchString(c.v) {
			add(c.field, CodeColor, "", false)
		}
	}
	if colorRE.MatchString(b.PrimaryColor) {
		p := mustColor(b.PrimaryColor)
		// Links are primary text on the page background and on cards.
		if r := minContrast(p, lightBG, lightSurface); r < 4.5 {
			add("primary_color", CodeContrast, fmt.Sprintf("%.2f", r), false)
		}
	}
	if colorRE.MatchString(b.AccentColor) {
		// Non-text contrast (WCAG 1.4.11) of the header line on the header.
		if r := contrast(mustColor(b.AccentColor), lightSurface); r < 3 {
			add("accent_color", CodeAccent, fmt.Sprintf("%.2f", r), true)
		}
	}
	for lang, t := range b.Texts {
		if !slices.Contains(Languages, lang) {
			add("texts", CodeLanguage, lang, false)
			continue
		}
		f := func(name string) string { return name + "_" + lang }
		text(f("signin_title"), t.SignInTitle, MaxSignInTitle, false)
		text(f("signin_note"), t.SignInNote, MaxSignInNote, true)
		text(f("help"), t.Help, MaxHelp, true)
		text(f("footer"), t.Footer, MaxFooter, true)
		text(f("notice"), t.Notice, MaxNotice, true)
	}
	if v := b.Support.Email; v != "" && (len(v) > MaxEmail || !emailRE.MatchString(v)) {
		add("support_email", CodeEmail, "", false)
	}
	if v := b.Support.Phone; v != "" && (len(v) > MaxPhone || !phoneRE.MatchString(v)) {
		add("support_phone", CodePhone, "", false)
	}
	if v := b.Support.URL; v != "" && !validHTTPS(v) {
		add("support_url", CodeURL, "", false)
	}
	for _, l := range []struct{ field, v string }{{"link_help", b.Links.Help}, {"link_terms", b.Links.Terms},
		{"link_privacy", b.Links.Privacy}, {"link_password_policy", b.Links.PasswordPolicy}} {
		if l.v != "" && !ValidLink(l.v) {
			add(l.field, CodeURL, "", false)
		}
	}
	if len(b.Assets) > len(Slots) {
		add("assets", CodeTooManyAssets, "", false)
	}
	for slot, a := range b.Assets {
		if !slices.Contains(Slots, slot) {
			add("assets", CodeSlot, slot, false)
			continue
		}
		lim := limits[slot]
		if !shaRE.MatchString(a.SHA256) || !slices.Contains(lim.types, a.Type) || a.Size <= 0 || a.Size > lim.bytes ||
			a.Width <= 0 || a.Height <= 0 || a.Width > lim.dim || a.Height > lim.dim {
			add(slot, CodeAsset, "", false)
		}
	}
	slices.SortStableFunc(ps, func(a, b Problem) int { return strings.Compare(a.Field, b.Field) })
	return ps
}

// Errors keeps the problems that are not warnings.
func Errors(ps []Problem) []Problem {
	var out []Problem
	for _, p := range ps {
		if !p.Warning {
			out = append(out, p)
		}
	}
	return out
}

// Validate returns the problems that make b invalid, as one error.
func (b Branding) Validate() error {
	var errs []error
	for _, p := range Errors(b.Check()) {
		errs = append(errs, errors.New(p.String()))
	}
	return errors.Join(errs...)
}

// validHTTPS accepts an absolute https URL with a host and no user info.
func validHTTPS(v string) bool {
	if len(v) > MaxURL || strings.ContainsFunc(v, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return false
	}
	u, err := url.Parse(v)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Opaque == ""
}

// ValidLink accepts an https URL, a mailto: address or a tel: number.
func ValidLink(v string) bool {
	switch {
	case strings.HasPrefix(v, "mailto:"):
		a := strings.TrimPrefix(v, "mailto:")
		return len(a) <= MaxEmail && emailRE.MatchString(a)
	case strings.HasPrefix(v, "tel:"):
		n := strings.TrimPrefix(v, "tel:")
		return len(n) <= MaxPhone && phoneRE.MatchString(n)
	}
	return validHTTPS(v)
}

// TelURL turns a validated phone number into a tel: URL (digits and a
// leading plus only).
func TelURL(phone string) string {
	var b strings.Builder
	b.WriteString("tel:")
	for i, r := range phone {
		if r >= '0' && r <= '9' || r == '+' && i == 0 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Text returns the texts for lang, falling back per field to English and
// then to the other languages, so a text written in one language only
// still shows.
func (b Branding) Text(lang string) Texts {
	order := append([]string{lang, "en"}, Languages...)
	pick := func(get func(Texts) string) string {
		for _, l := range order {
			if v := get(b.Texts[l]); v != "" {
				return v
			}
		}
		return ""
	}
	return Texts{
		SignInTitle: pick(func(t Texts) string { return t.SignInTitle }),
		SignInNote:  pick(func(t Texts) string { return t.SignInNote }),
		Help:        pick(func(t Texts) string { return t.Help }),
		Footer:      pick(func(t Texts) string { return t.Footer }),
		Notice:      pick(func(t Texts) string { return t.Notice }),
	}
}

// AssetHashes lists the SHA-256 of every referenced image.
func (b Branding) AssetHashes() []string {
	var out []string
	for _, a := range b.Assets {
		if !slices.Contains(out, a.SHA256) {
			out = append(out, a.SHA256)
		}
	}
	slices.Sort(out)
	return out
}
