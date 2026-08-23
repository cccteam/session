INSERT INTO "OIDCUsers" ("Id", "Tid", "Oid", "Username", "CreatedAt", "UpdatedAt")
VALUES ('11111111-2222-3333-4444-555555555555', 'tid-1', 'oid-existing', 'old@example.com', '2024-01-01 00:00:00', '2024-01-01 00:00:00');

INSERT INTO "OIDCUserData" ("UserId", "Email", "DisplayName", "Theme")
VALUES ('11111111-2222-3333-4444-555555555555', 'old@example.com', 'Old Name', 'dark');
