package idpapi

import (
	"errors"
	"fmt"
	"time"

	"github.com/openbasalt/samba-conductor-idp/branding"
)

// ---- branding ----

// BrandingAsset is an image's bytes, addressed by their SHA-256.
type BrandingAsset struct {
	SHA256 string `json:"sha256"`
	Data   []byte `json:"data"`
}

// BrandingUpdateParams replaces the branding of the user-facing pages
// with conductor's version Version of it. The update is self-contained:
// it carries every image the document references, and conductor-idp keeps
// exactly those (it checks each one again by content). Version is
// conductor's version number, recorded and shown; conductor is the only
// writer, so the last update wins.
type BrandingUpdateParams struct {
	Version  int64             `json:"version"`
	Branding branding.Branding `json:"branding"`
	Assets   []BrandingAsset   `json:"assets"`
}

// Validate implements Params: the document's own rules, and images that
// match what the document says of them.
func (p BrandingUpdateParams) Validate() error {
	if p.Version < 0 {
		return errors.New("version: not negative")
	}
	if err := p.Branding.Validate(); err != nil {
		return err
	}
	byHash := map[string][]byte{}
	for _, a := range p.Assets {
		if len(a.Data) > branding.MaxAssetBytes || branding.Digest(a.Data) != a.SHA256 {
			return errors.New("assets: an image does not match its digest or is too large")
		}
		if _, dup := byHash[a.SHA256]; dup {
			return errors.New("assets: duplicate image")
		}
		byHash[a.SHA256] = a.Data
	}
	want := p.Branding.AssetHashes()
	if len(want) != len(byHash) {
		return errors.New("assets: give exactly the images the branding references")
	}
	for slot, meta := range p.Branding.Assets {
		data, ok := byHash[meta.SHA256]
		if !ok {
			return fmt.Errorf("assets: missing the %s image", slot)
		}
		got, err := branding.Inspect(slot, data)
		if err != nil {
			return fmt.Errorf("assets: %s: %w", slot, err)
		}
		if got != meta {
			return fmt.Errorf("assets: %s: the image does not match its description", slot)
		}
	}
	return nil
}

// BrandingView is the branding conductor-idp applies.
type BrandingView struct {
	// Version is conductor's version of the document (0: never set, the
	// product look).
	Version   int64             `json:"version"`
	Branding  branding.Branding `json:"branding"`
	UpdatedAt time.Time         `json:"updated_at"`
	UpdatedBy string            `json:"updated_by"`
}
