package branding

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Partial is a built-in template fragment that a level 2 override may
// replace.
type Partial struct {
	// Name is the template name ("brand-header").
	Name string
	// File is the override's file name in the template directory
	// ("header.html").
	File string
	// Source is the built-in body (what an override replaces).
	Source string
	// Required are strings the partial's sample rendering must contain:
	// the data-e2e hooks, form fields and actions of the contract.
	Required []string
	// Doc describes the partial in one line.
	Doc string
}

// Base is the hash of the built-in body an override is written against.
func (p Partial) Base() string {
	s := sha256.Sum256([]byte(p.Source))
	return hex.EncodeToString(s[:8])
}

// Header is the first line of an override: it records the base hash.
func (p Partial) Header() string {
	return "{{/* samba-conductor template " + p.File + " base=" + p.Base() + " */}}"
}

// Define wraps a body as the named template definition.
func Define(name, body string) string {
	return `{{define "` + name + `"}}` + body + `{{end}}`
}

// Finding levels.
const (
	LevelOK      = "ok"
	LevelWarning = "warning"
	LevelError   = "error"
)

// Finding is one result of loading or checking the template directory.
type Finding struct {
	File    string
	Partial string
	Level   string
	Message string
}

func (f Finding) String() string {
	s := f.Level + ": " + f.File
	if f.Message != "" {
		s += ": " + f.Message
	}
	return s
}

// Result is what Load decided.
type Result struct {
	// Bodies maps every partial to the body in use: the override when it
	// was accepted, else the built-in one.
	Bodies map[string]string
	// Overridden lists the partials an override replaces.
	Overridden []string
	// CustomCSS is the accepted custom.css (nil: none).
	CustomCSS []byte
	Findings  []Finding
}

// HasErrors reports findings that refused an override or that need a
// review after an upgrade (a changed base).
func (r Result) HasErrors() bool {
	for _, f := range r.Findings {
		if f.Level != LevelOK {
			return true
		}
	}
	return false
}

// Render renders a candidate body of p with sample data, as the program
// would (its functions and shared partials), and returns the HTML.
type Render func(p Partial, body string) (string, error)

// Limits of the template directory's files.
const (
	MaxTemplateFile = 64 << 10
	MaxCustomCSS    = 64 << 10
	// CustomCSSFile is the optional stylesheet loaded after the brand
	// stylesheet on branded pages.
	CustomCSSFile = "custom.css"
)

var headerRE = regexp.MustCompile(`^\{\{/\*\s*samba-conductor template \S+ base=([0-9a-f]{16})\s*\*/\}\}`)

// Load reads the overrides of dir. A file that cannot be read, fails the
// lint, does not parse or render, or breaks the contract is refused (the
// built-in partial stays, with an error finding); a file written against
// another built-in body is used with a warning. An empty dir means no
// overrides.
func Load(dir string, partials []Partial, allowed []string, render Render) Result {
	res := Result{Bodies: map[string]string{}}
	for _, p := range partials {
		res.Bodies[p.Name] = p.Source
	}
	if dir == "" {
		return res
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		res.Findings = append(res.Findings, Finding{File: dir, Level: LevelError, Message: "template directory not readable: " + err.Error()})
		return res
	}
	byFile := map[string]Partial{}
	for _, p := range partials {
		byFile[p.File] = p
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") || strings.HasPrefix(strings.ToUpper(name), "README") {
			continue
		}
		path := filepath.Join(dir, name)
		if name == CustomCSSFile {
			css, err := readLimited(path, MaxCustomCSS)
			if err == nil {
				err = CheckCSS(string(css), allowed)
			}
			if err != nil {
				res.Findings = append(res.Findings, Finding{File: name, Level: LevelError, Message: "refused: " + err.Error()})
				continue
			}
			res.CustomCSS = css
			res.Findings = append(res.Findings, Finding{File: name, Level: LevelOK, Message: "custom stylesheet in use"})
			continue
		}
		p, ok := byFile[name]
		if !ok {
			res.Findings = append(res.Findings, Finding{File: name, Level: LevelWarning, Message: "not a known partial, ignored"})
			continue
		}
		body, fs := checkOverride(path, p, allowed, render)
		res.Findings = append(res.Findings, fs...)
		if body != "" {
			res.Bodies[p.Name] = body
			res.Overridden = append(res.Overridden, p.Name)
		}
	}
	slices.Sort(res.Overridden)
	return res
}

// checkOverride returns the accepted body ("" when refused) and findings.
func checkOverride(path string, p Partial, allowed []string, render Render) (string, []Finding) {
	f := func(level, msg string) Finding {
		return Finding{File: p.File, Partial: p.Name, Level: level, Message: msg}
	}
	raw, err := readLimited(path, MaxTemplateFile)
	if err != nil {
		return "", []Finding{f(LevelError, "refused, using the built-in partial: "+err.Error())}
	}
	body := string(raw)
	var out []Finding
	if issues := Lint(body); len(issues) > 0 {
		return "", []Finding{f(LevelError, "refused, using the built-in partial: "+strings.Join(issues, "; "))}
	}
	out = append(out, baseFinding(body, p)...)
	html, err := render(p, body)
	if err != nil {
		return "", append(out, f(LevelError, "refused, using the built-in partial: does not render: "+err.Error()))
	}
	if issues := CheckOutput(html, p.Required, allowed); len(issues) > 0 {
		return "", append(out, f(LevelError, "refused, using the built-in partial: "+strings.Join(issues, "; ")))
	}
	if len(out) == 0 {
		out = append(out, f(LevelOK, "override in use"))
	}
	return body, out
}

// baseFinding compares the override's recorded base with the built-in.
func baseFinding(body string, p Partial) []Finding {
	m := headerRE.FindStringSubmatch(body)
	switch {
	case m == nil:
		return []Finding{{File: p.File, Partial: p.Name, Level: LevelWarning,
			Message: "in use, but it has no base header; start from `templates show " + p.Name + "` so upgrades can be checked"}}
	case m[1] != p.Base():
		return []Finding{{File: p.File, Partial: p.Name, Level: LevelWarning,
			Message: fmt.Sprintf("in use, but the built-in partial changed since it was written (base %s, now %s): compare with `templates show %s`",
				m[1], p.Base(), p.Name)}}
	}
	return nil
}

func readLimited(path string, max int64) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if st.Size() > max {
		return nil, fmt.Errorf("larger than %d bytes", max)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("larger than %d bytes", max)
	}
	return b, nil
}

// lintRules refuse what the CSP would block anyway or what could weaken
// the page: scripts, other documents, inline styles and event handlers,
// script URLs, the script nonce, and nested template definitions.
var lintRules = []struct {
	re  *regexp.Regexp
	msg string
}{
	{regexp.MustCompile(`(?i)<\s*script`), "a <script> element"},
	{regexp.MustCompile(`(?i)<\s*(iframe|frame|frameset|object|embed|applet|portal)\b`), "an embedded document"},
	{regexp.MustCompile(`(?i)<\s*(base|link|meta)\b`), "a <base>, <link> or <meta> element"},
	{regexp.MustCompile(`(?i)<\s*style`), "a <style> element"},
	{regexp.MustCompile(`(?i)[\s"'/]style\s*=`), "a style attribute"},
	{regexp.MustCompile(`(?i)[\s"'/]on[a-z]+\s*=`), "an event handler attribute"},
	{regexp.MustCompile(`(?i)=\s*["']?\s*(javascript|vbscript|data)\s*:`), "a script or data URL"},
	{regexp.MustCompile(`(?i)\bnonce\b|\.ScriptSRI`), "the script nonce"},
	{regexp.MustCompile(`\{\{-?\s*(define|block)\b`), "a template definition"},
	{regexp.MustCompile(`(?i)<\s*form\b[^>]*\baction\s*=\s*["']?\s*(https?:|//)`), "a form that posts to another site"},
	{regexp.MustCompile(`(?i)\bformaction\s*=`), "a formaction attribute"},
}

// Lint returns why an override's source is refused (none: accepted).
func Lint(src string) []string {
	var out []string
	for _, r := range lintRules {
		if r.re.MatchString(src) {
			out = append(out, "contains "+r.msg)
		}
	}
	return out
}

var (
	imgRE = regexp.MustCompile(`(?is)<img\b[^>]*>`)
	altRE = regexp.MustCompile(`(?i)\salt\s*=`)
	srcRE = regexp.MustCompile(`(?i)\s(src|srcset)\s*=\s*"([^"]*)"`)
)

// CheckOutput checks a sample rendering: the contract's required strings,
// a text alternative on every image, and images only from this origin or
// an allowlisted one (the CSP would block the others).
func CheckOutput(html string, required, allowed []string) []string {
	var out []string
	for _, r := range required {
		if !strings.Contains(html, r) {
			out = append(out, "missing "+r)
		}
	}
	for _, img := range imgRE.FindAllString(html, -1) {
		if !altRE.MatchString(img) {
			out = append(out, "an <img> without alt")
			break
		}
	}
	for _, m := range srcRE.FindAllStringSubmatch(html, -1) {
		for _, cand := range strings.Split(m[2], ",") {
			u := strings.Fields(strings.TrimSpace(cand))
			if len(u) == 0 {
				continue
			}
			if !SameOriginOrAllowed(u[0], allowed) {
				out = append(out, "an image from an origin that is not allowlisted: "+u[0])
			}
		}
	}
	return out
}

// SameOriginOrAllowed accepts a relative URL ("/path", not "//host") or
// an absolute one whose origin is allowlisted.
func SameOriginOrAllowed(raw string, allowed []string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") {
		return true
	}
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") && !strings.HasPrefix(raw, "/\\") {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" && u.Host == "" {
		return err == nil && !strings.Contains(raw, ":")
	}
	return u.Scheme == "https" && slices.Contains(allowed, "https://"+strings.ToLower(u.Host))
}

// ParseOrigins validates an allowlist of origins ("https://host[:port]")
// for images and fonts and returns them normalized.
func ParseOrigins(list []string) ([]string, error) {
	var out []string
	for _, o := range list {
		u, err := url.Parse(strings.TrimSpace(o))
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") ||
			u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(u.Host, " ;,'\"*") {
			return nil, fmt.Errorf("branding: allowed origin %q: want https://host[:port]", o)
		}
		out = append(out, "https://"+strings.ToLower(u.Host))
	}
	return out, nil
}

var (
	cssURLRE  = regexp.MustCompile(`(?i)url\(\s*(?:"([^"]*)"|'([^']*)'|([^)'"\s]*))\s*\)`)
	cssBadRE  = regexp.MustCompile(`(?i)@import|expression\s*\(|javascript:|vbscript:|behavior\s*:|-moz-binding|</|<!--`)
	cssDataRE = regexp.MustCompile(`(?i)url\(\s*["']?\s*data:`)
)

// CheckCSS accepts a custom stylesheet whose url() references stay on
// this origin or an allowlisted one, without @import or script-like
// constructs.
func CheckCSS(css string, allowed []string) error {
	if cssBadRE.MatchString(css) {
		return errors.New("@import, expression(), script URLs and markup are not allowed")
	}
	if cssDataRE.MatchString(css) {
		return errors.New("data: URLs are not allowed")
	}
	for _, m := range cssURLRE.FindAllStringSubmatch(css, -1) {
		u := m[1] + m[2] + m[3]
		if !SameOriginOrAllowed(u, allowed) {
			return fmt.Errorf("url(%s) is not on this origin or an allowed origin", u)
		}
	}
	return nil
}

// Check returns the findings of Load without keeping its result (the
// `templates check` commands).
func Check(dir string, partials []Partial, allowed []string, render Render) []Finding {
	return Load(dir, partials, allowed, render).Findings
}
