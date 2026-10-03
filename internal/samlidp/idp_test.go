package samlidp

import (
	"strings"
	"testing"
)

const spMetadata = `<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/metadata">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://sp.example.com/acs-redirect" index="0"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="1"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>`

func TestParseSPMetadata(t *testing.T) {
	sp, err := ParseSPMetadata([]byte(spMetadata))
	if err != nil {
		t.Fatal(err)
	}
	if sp.EntityID != "https://sp.example.com/metadata" || strings.Join(sp.ACSURLs, ",") != "https://sp.example.com/acs" {
		t.Fatalf("%+v", sp)
	}
	if sp.NameIDFormat != NameIDEmail || sp.NameIDSource != SourceEmail {
		t.Fatalf("nameid %s %s", sp.NameIDFormat, sp.NameIDSource)
	}
	if _, err := ParseSPMetadata([]byte("<x/>")); err == nil {
		t.Fatal("garbage accepted")
	}
	if _, err := ParseSPMetadata([]byte(`<!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>`)); err == nil {
		t.Fatal("DTD accepted")
	}
}

func TestValidACS(t *testing.T) {
	for raw, ok := range map[string]bool{"https://sp/acs": true, "http://localhost:8080/acs": true, "http://sp/acs": false,
		"https://u:p@sp/acs": false, "javascript:x": false} {
		if ValidACS(raw) != ok {
			t.Errorf("%s", raw)
		}
	}
}
