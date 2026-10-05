// Package settings merges the configuration file with the settings
// administrators edit from conductor's panel (stored in the database,
// versioned). The file gives the defaults; a saved version overrides them
// as a whole.
package settings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openbasalt/samba-conductor-idp/idpapi"
	"github.com/openbasalt/samba-conductor-idp/internal/config"
	"github.com/openbasalt/samba-conductor-idp/internal/store"
)

// Defaults are the configuration file's values.
func Defaults(c *config.Config) idpapi.Settings {
	return idpapi.Settings{SessionIdleMinutes: c.Session.IdleMinutes, SessionAbsoluteHours: c.Session.AbsoluteHours,
		MFAPolicy: c.MFA.Policy, ConsentText: map[string]string{}}
}

// Load returns the effective settings.
func Load(ctx context.Context, st *store.Store, c *config.Config) (idpapi.SettingsView, error) {
	v := idpapi.SettingsView{Defaults: Defaults(c), MFABackend: c.MFA.Backend, MFAPolicyShared: c.MFA.Backend == config.MFABackendConductor}
	v.Settings = v.Defaults
	row, err := st.GetSettings(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return v, nil
	}
	if err != nil {
		return v, err
	}
	var saved idpapi.Settings
	if err := json.Unmarshal([]byte(row.Data), &saved); err != nil {
		return v, fmt.Errorf("settings: stored settings: %w", err)
	}
	if saved.ConsentText == nil {
		saved.ConsentText = map[string]string{}
	}
	if err := saved.Validate(); err != nil {
		return v, fmt.Errorf("settings: stored settings: %w", err)
	}
	v.Settings, v.Version, v.UpdatedAt, v.UpdatedBy = saved, row.Version, row.UpdatedAt, row.UpdatedBy
	return v, nil
}

// Save stores new settings on top of base (store.ErrStale when another
// change came first) and returns the new version.
func Save(ctx context.Context, st *store.Store, base int64, s idpapi.Settings, by string) (int64, error) {
	if err := s.Validate(); err != nil {
		return 0, err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return 0, err
	}
	return st.SaveSettings(ctx, base, string(b), by)
}
