package idpapi

import (
	"bytes"
	"encoding/json"
	"image"
	"image/png"
	"testing"

	"github.com/openbasalt/samba-conductor-idp/branding"
)

func testPNG(w, h int) []byte {
	var buf bytes.Buffer
	_ = png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, w, h)))
	return buf.Bytes()
}

func TestBrandingUpdateParams(t *testing.T) {
	logo := testPNG(100, 30)
	meta, err := branding.Inspect(branding.SlotLogoLight, logo)
	if err != nil {
		t.Fatal(err)
	}
	ok := BrandingUpdateParams{Version: 3, Branding: branding.Branding{OrgName: "Example", PrimaryColor: "#1d4ed8",
		Assets: map[string]branding.Asset{branding.SlotLogoLight: meta}}, Assets: []BrandingAsset{{SHA256: meta.SHA256, Data: logo}}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	// It goes through the strict request decoding.
	req, err := NewRequest("req-00000002", OpBrandingUpdate, testActor, ok)
	if err != nil {
		t.Fatal(err)
	}
	if !req.Op.Mutating() {
		t.Fatal("branding.update must be audited")
	}
	raw, _ := json.Marshal(req)
	if len(raw) > MaxMessageSize {
		t.Fatal("too large")
	}
	other := testPNG(10, 10)
	bad := map[string]func(p *BrandingUpdateParams){
		"digest":  func(p *BrandingUpdateParams) { p.Assets[0].Data = other },
		"missing": func(p *BrandingUpdateParams) { p.Assets = nil },
		"extra": func(p *BrandingUpdateParams) {
			p.Assets = append(p.Assets, BrandingAsset{SHA256: branding.Digest(other), Data: other})
		},
		"duplicate": func(p *BrandingUpdateParams) { p.Assets = append(p.Assets, p.Assets[0]) },
		"description": func(p *BrandingUpdateParams) {
			m := meta
			m.Width = 99
			p.Branding.Assets = map[string]branding.Asset{branding.SlotLogoLight: m}
		},
		"slot": func(p *BrandingUpdateParams) {
			p.Branding.Assets = map[string]branding.Asset{"banner": meta}
		},
		"contrast": func(p *BrandingUpdateParams) { p.Branding.PrimaryColor = "#eeeeee" },
		"url":      func(p *BrandingUpdateParams) { p.Branding.Links.Help = "javascript:alert(1)" },
		"version":  func(p *BrandingUpdateParams) { p.Version = -1 },
		"svg": func(p *BrandingUpdateParams) {
			svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`)
			m := branding.Asset{SHA256: branding.Digest(svg), Type: branding.TypePNG, Size: len(svg), Width: 1, Height: 1}
			p.Branding.Assets = map[string]branding.Asset{branding.SlotLogoLight: m}
			p.Assets = []BrandingAsset{{SHA256: m.SHA256, Data: svg}}
		},
	}
	for name, mut := range bad {
		p := ok
		p.Assets = append([]BrandingAsset(nil), ok.Assets...)
		p.Branding.Assets = map[string]branding.Asset{branding.SlotLogoLight: meta}
		mut(&p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
