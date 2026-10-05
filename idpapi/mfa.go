package idpapi

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

// The second-factor socket goes the other way: conductor serves it,
// conductor-idp calls it, so a user has one enrollment (TOTP, recovery
// codes, security keys) and one policy for both. conductor authorizes the
// peer with SO_PEERCRED (only the conductor-idp user), rate limits per
// user and audits every verification in its own log.
//
// One JSON request per connection, one JSON answer line, at most
// MFAMaxMessage bytes each way.
//
//	→ {"v":2,"op":"status","user_sid":"S-1-5-21-…","user":"jdoe","groups":["S-1-5-21-…-513"]}
//	← {"v":2,"enrolled":true,"totp":true,"keys":1,"required":true,"policy":"optional"}
//	→ {"v":2,"op":"verify","user_sid":"…","user":"jdoe","groups":[…],"code":"123456"}
//	← {"v":2,"ok":true,"recovery":false}
//	→ {"v":2,"op":"key.begin","user_sid":"…","user":"jdoe","groups":[…]}
//	← {"v":2,"ceremony":"…","options":{"publicKey":{…}}}
//	→ {"v":2,"op":"key.finish","user_sid":"…","user":"jdoe","groups":[…],"ceremony":"…","response":"{…}"}
//	← {"v":2,"ok":true}
//	← {"v":2,"error":"rate_limited"}
//
// The groups are the user's group SIDs as conductor-idp read them from AD
// (nested, primary group included): conductor maps them to its roles to
// decide whether a second factor is required, exactly as at its own
// sign-in.

// MFAProtocolVersion of the second-factor socket.
const MFAProtocolVersion = 2

// DefaultMFASocket is where conductor serves the second-factor socket.
const DefaultMFASocket = "/run/conductor/mfa.sock"

// MFAMaxMessage bounds one message.
const MFAMaxMessage = 64 << 10

// Second-factor operations.
const (
	MFAOpStatus    = "status"
	MFAOpVerify    = "verify"
	MFAOpKeyBegin  = "key.begin"
	MFAOpKeyFinish = "key.finish"
)

// Second-factor errors.
const (
	MFAErrRateLimited = "rate_limited"
	MFAErrKeyRequired = "key_required"
	MFAErrNoKeys      = "no_keys"
	MFAErrCeremony    = "ceremony"
	MFAErrBadRequest  = "bad_request"
	MFAErrInternal    = "internal"
	MFAErrVersion     = "version"
)

// MFARequest is one call to the second-factor socket.
type MFARequest struct {
	V        int      `json:"v"`
	Op       string   `json:"op"`
	UserSID  string   `json:"user_sid"`
	User     string   `json:"user"`
	Groups   []string `json:"groups"`
	Code     string   `json:"code,omitempty"`
	Ceremony string   `json:"ceremony,omitempty"`
	Response string   `json:"response,omitempty"`
}

var mfaCeremonyRE = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)

// Validate checks a request (conductor's side).
func (r MFARequest) Validate() error {
	switch {
	case r.V != MFAProtocolVersion:
		return errors.New(MFAErrVersion)
	case !sidRE.MatchString(r.UserSID):
		return errors.New("user_sid")
	case r.User == "" || len(r.User) > 256 || strings.ContainsAny(r.User, "\x00\r\n"):
		return errors.New("user")
	case len(r.Groups) > 2000:
		return errors.New("groups")
	case len(r.Code) > 32:
		return errors.New("code")
	case len(r.Response) > 32<<10:
		return errors.New("response")
	}
	for _, g := range r.Groups {
		if !sidRE.MatchString(g) {
			return errors.New("groups")
		}
	}
	switch r.Op {
	case MFAOpStatus, MFAOpKeyBegin:
	case MFAOpVerify:
		if r.Code == "" {
			return errors.New("code")
		}
	case MFAOpKeyFinish:
		if !mfaCeremonyRE.MatchString(r.Ceremony) || r.Response == "" {
			return errors.New("ceremony")
		}
	default:
		return errors.New("op")
	}
	return nil
}

// MFAAnswer is the answer of the second-factor socket.
type MFAAnswer struct {
	V int `json:"v"`
	// status
	Enrolled bool `json:"enrolled,omitempty"`
	TOTP     bool `json:"totp,omitempty"`
	Keys     int  `json:"keys,omitempty"`
	// Required: conductor's policy demands a second factor for this user
	// (administrators, delegated roles, or policy "required").
	Required bool `json:"required,omitempty"`
	// Policy is conductor's policy for users without a role.
	Policy string `json:"policy,omitempty"`
	// KeyRequired: this user must use a security key (TOTP codes are
	// refused; recovery codes stay the emergency path).
	KeyRequired bool `json:"key_required,omitempty"`
	// verify, key.finish
	OK       bool `json:"ok,omitempty"`
	Recovery bool `json:"recovery,omitempty"`
	// key.begin
	Ceremony string          `json:"ceremony,omitempty"`
	Options  json.RawMessage `json:"options,omitempty"`
	Error    string          `json:"error,omitempty"`
}
