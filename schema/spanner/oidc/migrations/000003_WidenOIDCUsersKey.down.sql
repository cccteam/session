-- Fails while any key value is longer than 36 characters.
ALTER TABLE OIDCUsers ALTER COLUMN Oid STRING(36) NOT NULL;
ALTER TABLE OIDCUsers ALTER COLUMN Tid STRING(36) NOT NULL;
