package web

import (
	"maps"
	"time"

	"github.com/openbasalt/samba-conductor-idp/idpapi"
)

// runtimeSettings are the settings administrators edit from conductor's
// panel, applied without a restart.
type runtimeSettings struct {
	mfaPolicy string
	consent   map[string]string
}

// ApplySettings makes new settings effective: session lifetimes (for new
// and running sessions), the local 2FA policy and the consent note.
func (s *Server) ApplySettings(st idpapi.Settings) {
	for _, t := range s.allSessions {
		t.setTimeouts(time.Duration(st.SessionIdleMinutes)*time.Minute, time.Duration(st.SessionAbsoluteHours)*time.Hour)
	}
	s.rt.Store(&runtimeSettings{mfaPolicy: st.MFAPolicy, consent: maps.Clone(st.ConsentText)})
}

// mfaPolicy is the local second-factor policy for users without a role.
func (s *Server) mfaPolicy() string { return s.rt.Load().mfaPolicy }

// consentNote is the administrator's note on the consent screen.
func (s *Server) consentNote(lang string) string { return s.rt.Load().consent[lang] }
