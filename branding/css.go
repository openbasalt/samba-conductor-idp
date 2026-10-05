package branding

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// rgb is a color with 8-bit channels.
type rgb struct{ r, g, b float64 }

// The product palette the brand colors are checked and mixed against
// (static/app.css of both programs).
var (
	lightBG      = mustColor("#f6f7f9")
	lightSurface = mustColor("#ffffff")
	darkBG       = mustColor("#0f1419")
	darkSurface  = mustColor("#161d24")
	darkFG       = mustColor("#e6eaee")
	white        = mustColor("#ffffff")
	nearBlack    = mustColor("#000000")
)

func parseColor(s string) (rgb, bool) {
	if !colorRE.MatchString(s) {
		return rgb{}, false
	}
	v, err := strconv.ParseUint(s[1:], 16, 32)
	if err != nil {
		return rgb{}, false
	}
	return rgb{float64(v >> 16 & 0xff), float64(v >> 8 & 0xff), float64(v & 0xff)}, true
}

func mustColor(s string) rgb {
	c, ok := parseColor(s)
	if !ok {
		panic("branding: bad color " + s)
	}
	return c
}

func (c rgb) hex() string {
	clamp := func(v float64) int { return int(math.Max(0, math.Min(255, math.Round(v)))) }
	return fmt.Sprintf("#%02x%02x%02x", clamp(c.r), clamp(c.g), clamp(c.b))
}

// luminance is the WCAG relative luminance.
func (c rgb) luminance() float64 {
	ch := func(v float64) float64 {
		v /= 255
		if v <= 0.04045 {
			return v / 12.92
		}
		return math.Pow((v+0.055)/1.055, 2.4)
	}
	return 0.2126*ch(c.r) + 0.7152*ch(c.g) + 0.0722*ch(c.b)
}

// contrast is the WCAG contrast ratio of two colors (1 to 21).
func contrast(a, b rgb) float64 {
	la, lb := a.luminance(), b.luminance()
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

func minContrast(c rgb, against ...rgb) float64 {
	m := 21.0
	for _, a := range against {
		m = math.Min(m, contrast(c, a))
	}
	return m
}

// mix returns a blend of a and b with weight w of a (0 to 1).
func mix(a, b rgb, w float64) rgb {
	return rgb{a.r*w + b.r*(1-w), a.g*w + b.g*(1-w), a.b*w + b.b*(1-w)}
}

// textOn picks white or black for text on bg, whichever contrasts
// more. One of them always reaches 4.58:1 (the square root of 21), so text
// on a brand color always meets WCAG AA.
func textOn(bg rgb) rgb {
	if contrast(white, bg) >= contrast(nearBlack, bg) {
		return white
	}
	return nearBlack
}

// forDark lightens c (mixing it with white) until it reads as link text on
// the dark theme's background and surface (4.5:1).
func forDark(c rgb) rgb {
	for w := 1.0; w >= 0; w -= 0.05 {
		m := mix(c, white, w)
		if minContrast(m, darkBG, darkSurface) >= 4.5 {
			return m
		}
	}
	return white
}

// Contrast returns the WCAG contrast ratio of two "#rrggbb" colors, or 0
// when one is not a color.
func Contrast(a, b string) float64 {
	ca, ok1 := parseColor(strings.ToLower(a))
	cb, ok2 := parseColor(strings.ToLower(b))
	if !ok1 || !ok2 {
		return 0
	}
	return contrast(ca, cb)
}

// Scope says where the generated rules apply.
type Scope struct {
	// Light is the selector of the light theme (":root").
	Light string
	// DarkAuto is the selector inside "@media (prefers-color-scheme:
	// dark)" (empty: none).
	DarkAuto string
	// Dark is the selector of the explicit dark theme.
	Dark string
	// DarkPalette also sets the product's dark palette in Dark (a preview
	// inside a light page).
	DarkPalette bool
}

// PageScope is the scope of a branded page.
var PageScope = Scope{Light: ":root", DarkAuto: `:root:not([data-theme="light"])`, Dark: `:root[data-theme="dark"]`}

// PreviewScope is the scope of conductor's preview cards.
var PreviewScope = Scope{Light: ".brand-preview", Dark: ".brand-preview.preview-dark", DarkPalette: true}

// CSS generates the brand stylesheet: custom properties that override the
// product palette, and the background image rule. assetURL maps an image
// to its same-origin URL. Every value is a validated color or a URL built
// from a hex digest, so nothing from the document reaches the CSS
// unchecked.
func CSS(b Branding, sc Scope, assetURL func(Asset) string) string {
	var w strings.Builder
	w.WriteString("/* Generated brand stylesheet. */\n")
	light, dark := []string{}, []string{}
	if p, ok := parseColor(b.PrimaryColor); ok {
		pd := forDark(p)
		light = append(light, "--accent: "+p.hex(), "--accent-fg: "+textOn(p).hex(), "--accent-soft: "+mix(p, lightSurface, 0.14).hex())
		dark = append(dark, "--accent: "+pd.hex(), "--accent-fg: "+textOn(pd).hex(), "--accent-soft: "+mix(pd, darkSurface, 0.2).hex())
	}
	if a, ok := parseColor(b.AccentColor); ok {
		v := []string{"--brand-accent: " + a.hex(), "--brand-accent-fg: " + textOn(a).hex()}
		light = append(light, v...)
		dark = append(dark, v...)
	}
	if sc.DarkPalette {
		dark = append([]string{"--bg: " + darkBG.hex(), "--surface: " + darkSurface.hex(), "--surface-2: #1d2630",
			"--fg: " + darkFG.hex(), "--muted: #9aa6b2", "--border: #2c3742", "color-scheme: dark"}, dark...)
		if _, ok := parseColor(b.PrimaryColor); !ok {
			dark = append(dark, "--accent: #2dd4bf", "--accent-fg: #062925", "--accent-soft: #123b37")
		}
	}
	block := func(sel string, decls []string) {
		if sel == "" || len(decls) == 0 {
			return
		}
		w.WriteString(sel + " {\n")
		for _, d := range decls {
			w.WriteString("  " + d + ";\n")
		}
		w.WriteString("}\n")
	}
	block(sc.Light, light)
	if sc.DarkAuto != "" && len(dark) > 0 {
		w.WriteString("@media (prefers-color-scheme: dark) {\n")
		block(sc.DarkAuto, dark)
		w.WriteString("}\n")
	}
	block(sc.Dark, dark)
	if a, ok := b.Assets[SlotBackground]; ok && assetURL != nil && shaRE.MatchString(a.SHA256) {
		u := assetURL(a)
		if safeCSSURL(u) {
			sel := ".brand-bg"
			if sc.Light != ":root" {
				sel = sc.Light + " .brand-bg"
			}
			block(sel, []string{`background-image: url("` + u + `")`, "background-size: cover", "background-position: center",
				"background-attachment: fixed"})
		}
	}
	return w.String()
}

// safeCSSURL accepts the same-origin paths CSS builds (letters, digits,
// "/", "-", "_", ".", "?", "=").
func safeCSSURL(u string) bool {
	if !strings.HasPrefix(u, "/") || strings.HasPrefix(u, "//") {
		return false
	}
	for _, r := range u {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/-_.?=", r)) {
			return false
		}
	}
	return true
}
