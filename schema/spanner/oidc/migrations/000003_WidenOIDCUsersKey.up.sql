-- Widen the OIDCUsers key columns: subjects from identity providers other than Entra ID
-- (for example WorkOS idp_ids) are longer than a GUID. Postgres stores them unbounded.
ALTER TABLE OIDCUsers ALTER COLUMN Tid STRING(MAX) NOT NULL;
ALTER TABLE OIDCUsers ALTER COLUMN Oid STRING(MAX) NOT NULL;
