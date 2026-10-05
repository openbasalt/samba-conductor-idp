-- Branding of the user-facing pages, pushed by conductor through the
-- management API (branding.update) and kept here so the pages keep their
-- look when conductor is down. One row; the images it references are the
-- only rows of branding_assets.
CREATE TABLE branding (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    version     INTEGER NOT NULL,   -- conductor's version of the document
    data        TEXT    NOT NULL,   -- JSON of branding.Branding
    updated_at  INTEGER NOT NULL,
    updated_by  TEXT    NOT NULL
);
CREATE TABLE branding_assets (
    sha256       TEXT PRIMARY KEY,
    content_type TEXT NOT NULL,
    data         BLOB NOT NULL
);
