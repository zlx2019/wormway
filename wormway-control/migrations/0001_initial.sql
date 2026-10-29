-- Versions of the dynamic settings. The newest row is the configuration in effect; a rollback
-- adds a copy of an older row instead of deleting newer ones.
CREATE TABLE config_versions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    -- RFC 3339 timestamp in UTC, such as 2026-10-28T09:57:05.247Z.
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    -- Who made the change.
    source     TEXT    NOT NULL CHECK (source IN ('api', 'ui', 'cli', 'file')),
    comment    TEXT    NOT NULL DEFAULT '',
    -- The dynamic settings as normalized JSON.
    content    TEXT    NOT NULL
);

-- Small values of this instance, such as its ID.
CREATE TABLE kv (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
