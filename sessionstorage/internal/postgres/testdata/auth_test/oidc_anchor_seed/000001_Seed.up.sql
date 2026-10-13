-- A legacy Azure group as the upgrade finds it: two anchored users and a live session of
-- one of them.
INSERT INTO "OIDCUsers" ("Id", "Tid", "Oid", "Username", "CreatedAt", "UpdatedAt")
VALUES ('11111111-2222-3333-4444-555555555555', 'tid-1', 'oid-old', 'old@lakeside.edu', '2024-01-01 00:00:00', '2024-01-02 00:00:00'),
       ('66666666-7777-8888-9999-aaaaaaaaaaaa', 'tid-1', 'oid-other', 'other@lakeside.edu', '2024-01-03 00:00:00', '2024-01-04 00:00:00');

INSERT INTO "Sessions" ("Id", "OidcSid", "Username", "CreatedAt", "UpdatedAt", "Expired")
VALUES ('bbbbbbbb-cccc-dddd-eeee-ffffffffffff', 'sid-old', 'old@lakeside.edu', NOW(), NOW(), false);
