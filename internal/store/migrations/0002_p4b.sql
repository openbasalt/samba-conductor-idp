-- P4b: single logout endpoints and signing certificates of service
-- providers, settings edited from conductor's panel, and the SAML session
-- participants needed for single logout.

ALTER TABLE saml_sps ADD COLUMN slo_url TEXT NOT NULL DEFAULT '';
ALTER TABLE saml_sps ADD COLUMN slo_binding TEXT NOT NULL DEFAULT '';
ALTER TABLE saml_sps ADD COLUMN signing_cert BLOB;

CREATE TABLE settings (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    version    INTEGER NOT NULL,
    data       TEXT NOT NULL,                 -- JSON of idpapi.Settings
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL
);

CREATE INDEX audit_target ON audit(target);
