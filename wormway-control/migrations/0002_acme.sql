-- ACME accounts, one per directory: the credentials that instant-acme writes, private key
-- included.
CREATE TABLE acme_accounts (
    directory   TEXT PRIMARY KEY,
    credentials TEXT NOT NULL,
    -- RFC 3339 timestamp in UTC.
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Certificates issued through ACME, by the name of the certificate in the configuration. A
-- certificate stays usable while the configuration asks for the same host names from the same
-- directory.
CREATE TABLE acme_certificates (
    name      TEXT PRIMARY KEY,
    -- The directory that issued it.
    directory TEXT NOT NULL,
    -- The host names it was ordered for, as a sorted JSON array.
    domains   TEXT NOT NULL,
    -- The certificate chain, leaf first, and its private key, as PEM.
    chain     TEXT NOT NULL,
    key       TEXT NOT NULL,
    -- RFC 3339 timestamp in UTC.
    issued_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
