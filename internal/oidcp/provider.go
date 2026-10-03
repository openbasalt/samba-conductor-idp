package oidcp

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/op"
)

// AccessTokenKey derives the key that encrypts opaque access tokens from
// the master key, so tokens survive a restart without another secret.
func AccessTokenKey(masterKey []byte) ([32]byte, error) {
	var out [32]byte
	k, err := hkdf.Key(sha256.New, masterKey, nil, "conductor-idp access-token v1", 32)
	if err != nil {
		return out, err
	}
	copy(out[:], k)
	clear(k)
	return out, nil
}

// NewProvider builds the OpenID provider on our storage. issuer is the
// public origin (https only).
func NewProvider(issuer string, storage *Storage, cryptoKey [32]byte, logger *slog.Logger) (*op.Provider, error) {
	cfg := &op.Config{
		CryptoKey:                cryptoKey,
		DefaultLogoutRedirectURI: "/logged-out",
		CodeMethodS256:           true,
		AuthMethodPost:           false,
		AuthMethodPrivateKeyJWT:  false,
		GrantTypeRefreshToken:    true,
		RequestObjectSupported:   false,
		SupportedUILocales:       nil,
		SupportedScopes:          SupportedScopes,
		SupportedClaims: []string{
			"sub", "aud", "exp", "iat", "iss", "auth_time", "nonce", "amr", "at_hash", "c_hash", "azp",
			"name", "given_name", "family_name", "preferred_username", "email", "email_verified", "groups",
		},
	}
	opts := []op.Option{op.WithCustomEndpoints(
		op.NewEndpoint(strings.TrimPrefix(AuthorizePath, "/")),
		op.NewEndpoint(strings.TrimPrefix(TokenPath, "/")),
		op.NewEndpoint(strings.TrimPrefix(UserinfoPath, "/")),
		op.NewEndpoint(strings.TrimPrefix(RevokePath, "/")),
		op.NewEndpoint(strings.TrimPrefix(EndSession, "/")),
		op.NewEndpoint(strings.TrimPrefix(KeysPath, "/")),
	)}
	if logger != nil {
		opts = append(opts, op.WithLogger(logger))
	}
	return op.NewProvider(cfg, storage, op.StaticIssuer(strings.TrimRight(issuer, "/")), opts...)
}

// Paths the web server routes to the provider.
var Paths = []string{AuthorizePath, CallbackPath, TokenPath, UserinfoPath, RevokePath, EndSession, KeysPath}

// DiscoveryHandler serves the provider metadata narrowed to what this
// provider accepts: the library also advertises implicit flows, JWT
// grants, introspection and form_post that no client here can use.
func DiscoveryHandler(provider http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		provider.ServeHTTP(rec, r)
		var doc map[string]any
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &doc) != nil {
			w.WriteHeader(rec.Code)
			_, _ = w.Write(rec.Body.Bytes())
			return
		}
		doc["response_types_supported"] = []string{"code"}
		doc["grant_types_supported"] = []string{"authorization_code", "refresh_token"}
		doc["response_modes_supported"] = []string{"query"}
		doc["code_challenge_methods_supported"] = []string{"S256"}
		doc["token_endpoint_auth_methods_supported"] = []string{"client_secret_basic", "none"}
		doc["revocation_endpoint_auth_methods_supported"] = []string{"client_secret_basic", "none"}
		doc["id_token_signing_alg_values_supported"] = []string{string(keyAlg)}
		doc["request_parameter_supported"] = false
		doc["request_uri_parameter_supported"] = false
		doc["claims_parameter_supported"] = false
		for _, k := range []string{"introspection_endpoint", "introspection_endpoint_auth_methods_supported",
			"introspection_endpoint_auth_signing_alg_values_supported", "token_endpoint_auth_signing_alg_values_supported",
			"revocation_endpoint_auth_signing_alg_values_supported", "request_object_signing_alg_values_supported",
			"device_authorization_endpoint", "check_session_iframe"} {
			delete(doc, k)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_ = json.NewEncoder(w).Encode(doc)
	}
}
