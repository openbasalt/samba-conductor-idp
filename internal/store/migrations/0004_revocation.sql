-- Security hardening (decisions D18 to D20): per-client email_verified,
-- the password version (AD pwdLastSet) a sign-in was made with, user
-- revocations and browsers known to have signed in to an account.

-- email_verified is asserted only for clients that opt in.
ALTER TABLE clients ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0;

-- pwd_set is the account's pwdLastSet (FILETIME) when the password was
-- verified; 0 for rows written before this migration. A different value in
-- AD means the password was changed or reset since.
ALTER TABLE auth_requests ADD COLUMN pwd_set INTEGER NOT NULL DEFAULT 0;
ALTER TABLE refresh_tokens ADD COLUMN pwd_set INTEGER NOT NULL DEFAULT 0;
ALTER TABLE access_tokens ADD COLUMN pwd_set INTEGER NOT NULL DEFAULT 0;
CREATE INDEX auth_requests_subject ON auth_requests(subject);

-- A revocation ends every session and token of the account that started
-- before revoked_at (password or second factor changed, explicit revoke).
CREATE TABLE user_revocations (
    subject    TEXT PRIMARY KEY,              -- objectGUID
    revoked_at INTEGER NOT NULL,
    reason     TEXT NOT NULL
);

-- Browsers that completed a password sign-in for an account (hash of the
-- browser cookie): they are not subject to the account-wide failure limit,
-- so failures from elsewhere cannot lock the owner out.
CREATE TABLE known_devices (
    username     TEXT NOT NULL,               -- lower-case sAMAccountName
    browser_hash TEXT NOT NULL,
    last_seen    INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    PRIMARY KEY (username, browser_hash)
);
