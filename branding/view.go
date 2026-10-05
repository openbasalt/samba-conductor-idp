package branding

import (
	"html/template"
)

// View is what the page templates (and level 2 overrides) see of the
// branding, as {{.B}}: everything already validated, resolved for the
// page's language and turned into same-origin URLs. It is nil on pages
// that are not branded (admin pages), so templates test {{if .B}}.
type View struct {
	// Name is the organization name, or the product name when none is set.
	Name string
	// CSS is the generated stylesheet; CustomCSS the optional custom.css
	// of the template directory (empty: none).
	CSS       string
	CustomCSS string
	// LogoLight and LogoDark are image URLs (empty: the product logo).
	// LogoDark falls back to LogoLight.
	LogoLight string
	LogoDark  string
	// Favicon and its type (empty: the product icon).
	Favicon     string
	FaviconType string
	// Background is true when a sign-in background image is set.
	Background bool
	// Texts of the page's language (with fallbacks).
	SignInTitle string
	SignInNote  string
	Help        string
	Footer      string
	Notice      string
	// Support contact. SupportTel and the links are validated URLs
	// (https, mailto: or tel:) typed so that html/template keeps them.
	SupportEmail  string
	SupportMailto template.URL
	SupportPhone  string
	SupportTel    template.URL
	SupportURL    string
	HelpURL       template.URL
	TermsURL      template.URL
	PrivacyURL    template.URL
	PolicyURL     template.URL
	// HasSupport and HasLinks tell whether those blocks have content.
	HasSupport bool
	HasLinks   bool
}

// URLs build the same-origin URLs of a View.
type URLs struct {
	CSS       string
	CustomCSS string
	Asset     func(Asset) string
}

// NewView builds the View of b for one language. Call it only with a
// valid document (Validate): the links are typed as safe URLs here.
func NewView(b Branding, lang, product string, u URLs) *View {
	t := b.Text(lang)
	v := &View{Name: b.OrgName, CSS: u.CSS, CustomCSS: u.CustomCSS, SignInTitle: t.SignInTitle, SignInNote: t.SignInNote,
		Help: t.Help, Footer: t.Footer, Notice: t.Notice, SupportEmail: b.Support.Email, SupportPhone: b.Support.Phone,
		SupportURL: b.Support.URL}
	if v.Name == "" {
		v.Name = product
	}
	asset := func(slot string) (string, string) {
		a, ok := b.Assets[slot]
		if !ok || u.Asset == nil || !shaRE.MatchString(a.SHA256) {
			return "", ""
		}
		return u.Asset(a), a.Type
	}
	v.LogoLight, _ = asset(SlotLogoLight)
	v.LogoDark, _ = asset(SlotLogoDark)
	if v.LogoDark == "" {
		v.LogoDark = v.LogoLight
	}
	v.Favicon, v.FaviconType = asset(SlotFavicon)
	bg, _ := asset(SlotBackground)
	v.Background = bg != ""
	if b.Support.Phone != "" && phoneRE.MatchString(b.Support.Phone) {
		// Digits and a leading plus only (TelURL).
		v.SupportTel = template.URL(TelURL(b.Support.Phone))
	}
	safe := func(s string) template.URL {
		if s == "" || !ValidLink(s) {
			return ""
		}
		// Validated: https, mailto: or tel: only (ValidLink).
		return template.URL(s)
	}
	v.HelpURL, v.TermsURL, v.PrivacyURL, v.PolicyURL = safe(b.Links.Help), safe(b.Links.Terms), safe(b.Links.Privacy),
		safe(b.Links.PasswordPolicy)
	if v.SupportURL != "" && !validHTTPS(v.SupportURL) {
		v.SupportURL = ""
	}
	if v.SupportEmail != "" && !emailRE.MatchString(v.SupportEmail) {
		v.SupportEmail = ""
	}
	if v.SupportEmail != "" {
		// Validated address (emailRE): no character html/template would
		// need to escape inside the URL.
		v.SupportMailto = template.URL("mailto:" + v.SupportEmail)
	}
	v.HasSupport = v.SupportEmail != "" || v.SupportTel != "" || v.SupportURL != ""
	v.HasLinks = v.HelpURL != "" || v.TermsURL != "" || v.PrivacyURL != ""
	return v
}

// SampleView is a fully populated View for checking overrides.
func SampleView() *View {
	return &View{Name: "Example Org", CSS: "/branding/theme.css", LogoLight: "/branding/assets/sample-light",
		LogoDark: "/branding/assets/sample-dark", Favicon: "/branding/assets/sample-icon", FaviconType: TypePNG, Background: true,
		SignInTitle: "Sign in to Example", SignInNote: "Use your network account.", Help: "Forgot your password? Call the helpdesk.",
		Footer: "Example Org, IT department", Notice: "Maintenance on Saturday", SupportEmail: "help@example.com",
		SupportMailto: "mailto:help@example.com", SupportPhone: "+1 555 0100", SupportTel: "tel:+15550100", SupportURL: "https://help.example.com",
		HelpURL: "https://help.example.com", TermsURL: "https://example.com/terms", PrivacyURL: "https://example.com/privacy",
		PolicyURL: "https://example.com/passwords", HasSupport: true, HasLinks: true}
}
