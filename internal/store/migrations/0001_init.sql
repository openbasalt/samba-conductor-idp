-- conductor-idp schema. Times are INTEGER Unix nanoseconds (UTC) so range
-- comparisons are exact; the audit log keeps a fixed-width text time
-- because it is part of the hashed row.

CREATE TABLE clients (
    id                TEXT PRIMARY KEY,           -- client_id
    name              TEXT NOT NULL,
    kind              TEXT NOT NULL CHECK (kind IN ('confidential', 'public')),
    secret_hash       TEXT NOT NULL DEFAULT '',   -- SHA-256 of the secret (confidential only)
    redirect_uris     TEXT NOT NULL,              -- JSON array, exact match
    post_logout_uris  TEXT NOT NULL DEFAULT '[]', -- JSON array, exact match
    scopes            TEXT NOT NULL,              -- JSON array of scopes the client may get
    allowed_groups    TEXT NOT NULL DEFAULT '[]', -- JSON array of group SIDs
    allow_all_users   INTEGER NOT NULL DEFAULT 0,
    first_party       INTEGER NOT NULL DEFAULT 0, -- skips the consent screen
    groups_claim      TEXT NOT NULL DEFAULT 'none' CHECK (groups_claim IN ('none', 'names', 'sids')),
    groups_filter     TEXT NOT NULL DEFAULT '[]', -- JSON array of SIDs; empty = every group
    require_mfa       INTEGER NOT NULL DEFAULT 0,
    enabled           INTEGER NOT NULL DEFAULT 1,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL,
    secret_rotated_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE auth_requests (
    id                    TEXT PRIMARY KEY,
    client_id             TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    redirect_uri          TEXT NOT NULL,
    state                 TEXT NOT NULL DEFAULT '',
    nonce                 TEXT NOT NULL DEFAULT '',
    scopes                TEXT NOT NULL,
    response_type         TEXT NOT NULL,
    response_mode         TEXT NOT NULL DEFAULT '',
    code_challenge        TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    prompt                TEXT NOT NULL DEFAULT '[]',
    max_age               INTEGER,                -- seconds, NULL = none
    login_hint            TEXT NOT NULL DEFAULT '',
    ui_locales            TEXT NOT NULL DEFAULT '',
    browser_hash          TEXT NOT NULL DEFAULT '', -- binds the request to one browser
    subject               TEXT NOT NULL DEFAULT '', -- set when the user is authenticated
    auth_time             INTEGER NOT NULL DEFAULT 0,
    amr                   TEXT NOT NULL DEFAULT '[]',
    created_at            INTEGER NOT NULL,
    expires_at            INTEGER NOT NULL
);
CREATE INDEX auth_requests_expires ON auth_requests(expires_at);

CREATE TABLE auth_codes (
    code_hash       TEXT PRIMARY KEY,
    auth_request_id TEXT NOT NULL,
    expires_at      INTEGER NOT NULL,
    used_at         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX auth_codes_request ON auth_codes(auth_request_id);

CREATE TABLE refresh_tokens (
    id         TEXT PRIMARY KEY,
    chain_id   TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    client_id  TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    subject    TEXT NOT NULL,
    scopes     TEXT NOT NULL,
    audience   TEXT NOT NULL,
    amr        TEXT NOT NULL DEFAULT '[]',
    auth_time  INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,              -- idle expiry of this token
    chain_expires_at INTEGER NOT NULL,        -- absolute expiry of the chain
    rotated_at INTEGER NOT NULL DEFAULT 0,
    revoked_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX refresh_tokens_chain ON refresh_tokens(chain_id);
CREATE INDEX refresh_tokens_subject ON refresh_tokens(subject, client_id);

CREATE TABLE access_tokens (
    id         TEXT PRIMARY KEY,
    chain_id   TEXT NOT NULL DEFAULT '',      -- refresh chain or auth request id
    client_id  TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    subject    TEXT NOT NULL,
    scopes     TEXT NOT NULL,
    audience   TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX access_tokens_chain ON access_tokens(chain_id);
CREATE INDEX access_tokens_subject ON access_tokens(subject, client_id);

CREATE TABLE signing_keys (
    id         TEXT PRIMARY KEY,
    purpose    TEXT NOT NULL CHECK (purpose IN ('oidc', 'saml')),
    alg        TEXT NOT NULL,
    private    BLOB NOT NULL,                 -- sealed with the master key
    cert       BLOB,                          -- DER certificate (SAML)
    created_at INTEGER NOT NULL,
    retire_at  INTEGER NOT NULL DEFAULT 0     -- 0 = not scheduled
);

CREATE TABLE consents (
    subject    TEXT NOT NULL,
    client_id  TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    scopes     TEXT NOT NULL,
    granted_at INTEGER NOT NULL,
    PRIMARY KEY (subject, client_id)
);

CREATE TABLE totp (
    user_key   TEXT PRIMARY KEY,               -- the user's objectGUID
    secret     BLOB NOT NULL,                  -- sealed, bound to user_key
    last_step  INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE TABLE recovery_codes (
    user_key  TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    used_at   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_key, code_hash)
);

CREATE TABLE enroll_links (
    token_hash TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE saml_sps (
    entity_id         TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    acs_urls          TEXT NOT NULL,              -- JSON array (HTTP-POST binding)
    nameid_format     TEXT NOT NULL,
    nameid_source     TEXT NOT NULL,
    attributes        TEXT NOT NULL DEFAULT '[]', -- JSON array of {name, source}
    allowed_groups    TEXT NOT NULL DEFAULT '[]',
    allow_all_users   INTEGER NOT NULL DEFAULT 0,
    encrypt_assertion INTEGER NOT NULL DEFAULT 0,
    encryption_cert   BLOB,                       -- DER, when encrypting
    idp_initiated     INTEGER NOT NULL DEFAULT 0,
    default_relay     TEXT NOT NULL DEFAULT '',
    require_mfa       INTEGER NOT NULL DEFAULT 0,
    enabled           INTEGER NOT NULL DEFAULT 1,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
);

CREATE TABLE saml_pending (
    id           TEXT PRIMARY KEY,
    entity_id    TEXT NOT NULL,
    request_id   TEXT NOT NULL,
    payload      BLOB NOT NULL,                    -- the decoded AuthnRequest
    relay_state  TEXT NOT NULL DEFAULT '',
    browser_hash TEXT NOT NULL,
    received_at  INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    UNIQUE (entity_id, request_id)
);

CREATE TABLE audit (
    id         INTEGER PRIMARY KEY,
    ts         TEXT NOT NULL,
    actor_sid  TEXT NOT NULL,
    actor_name TEXT NOT NULL,
    action     TEXT NOT NULL,
    target     TEXT NOT NULL,
    detail     TEXT NOT NULL,
    result     TEXT NOT NULL,
    ip         TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL
);
CREATE INDEX audit_ts ON audit(ts);
CREATE INDEX audit_action ON audit(action);
