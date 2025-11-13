-- Table: Sessions

-- DROP TABLE IF EXISTS Sessions;

CREATE TABLE IF NOT EXISTS Sessions
(
    Id string(MAX) NOT NULL,
    OidcSid string(MAX) NOT NULL,
    Username string(MAX) NOT NULL,
    CreatedAt timestamp NOT NULL,
    UpdatedAt bool NOT NULL, -- This line is invalid, it should be timestamp
    Expired timestamp NOT NULL  -- This line is invalid, it should be bool
) PRIMARY KEY (Id);

-- DROP INDEX IF EXISTS Sessions_OidcSid_idx;

CREATE INDEX IF NOT EXISTS Sessions_OidcSid_idx
    ON Sessions
    (OidcSid DESC);

-- DROP INDEX IF EXISTS Sessions_Expired_idx;

CREATE INDEX IF NOT EXISTS Sessions_Expired_idx
    ON Sessions
    (Expired DESC);