package idpapi

import (
	"encoding/json"
	"strings"
	"testing"
)

var testActor = Actor{User: "admin", SID: "S-1-5-21-1-2-3-500", Session: "s-1"}

func TestRequestEnvelope(t *testing.T) {
	if _, err := NewRequest("req-00000001", OpStatus, testActor, nil); err != nil {
		t.Fatal(err)
	}
	cases := map[string]Request{
		"version":   {Version: 99, ID: "req-00000001", Op: OpStatus, Actor: testActor},
		"id":        {Version: ProtocolVersion, ID: "x", Op: OpStatus, Actor: testActor},
		"actor":     {Version: ProtocolVersion, ID: "req-00000001", Op: OpStatus, Actor: Actor{User: "admin", SID: "nope", Session: "s"}},
		"op":        {Version: ProtocolVersion, ID: "req-00000001", Op: "exec", Actor: testActor},
		"unknown":   {Version: ProtocolVersion, ID: "req-00000001", Op: OpClientGet, Actor: testActor, Params: json.RawMessage(`{"id":"cidp_1","x":1}`)},
		"no params": {Version: ProtocolVersion, ID: "req-00000001", Op: OpClientGet, Actor: testActor},
	}
	for name, r := range cases {
		if _, err := r.Decode(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParamsValidation(t *testing.T) {
	bad := []Params{
		SPMetadataParams{URL: "http://sp.example/metadata"},
		SPMetadataParams{},
		KeysRotateParams{Purpose: "oidc", Immediate: true},
		ActivityParams{Days: 0},
		AuditListParams{Limit: 1000},
		ClientPreviewParams{Username: "alice"},
		SettingsUpdateParams{Settings: Settings{SessionIdleMinutes: 1, SessionAbsoluteHours: 1, MFAPolicy: "sometimes"}},
		ClientCreateParams{Input: ClientInput{Name: strings.Repeat("x", 500)}},
	}
	for _, p := range bad {
		if err := p.Validate(); err == nil {
			t.Errorf("%T %+v accepted", p, p)
		}
	}
}

func TestMFARequestValidation(t *testing.T) {
	ok := MFARequest{V: MFAProtocolVersion, Op: MFAOpVerify, UserSID: "S-1-5-21-1-2-3-1105", User: "alice",
		Groups: []string{"S-1-5-21-1-2-3-513"}, Code: "123456"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mut := range []func(*MFARequest){
		func(r *MFARequest) { r.V = 1 },
		func(r *MFARequest) { r.Code = "" },
		func(r *MFARequest) { r.Groups = []string{"Domain Users"} },
		func(r *MFARequest) { r.Op = "enroll" },
		func(r *MFARequest) { r.Op, r.Ceremony = MFAOpKeyFinish, "short" },
	} {
		r := ok
		mut(&r)
		if err := r.Validate(); err == nil {
			t.Errorf("%+v accepted", r)
		}
	}
}
