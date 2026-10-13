INSERT INTO OIDCUsers (Id, Tid, Oid, Username, CreatedAt, UpdatedAt)
VALUES ('11111111-2222-3333-4444-555555555555', 'tid-1', 'oid-old', 'old@lakeside.edu', '2024-01-01T00:00:00Z', '2024-01-02T00:00:00Z'),
       ('66666666-7777-8888-9999-aaaaaaaaaaaa', 'tid-1', 'oid-other', 'other@lakeside.edu', '2024-01-03T00:00:00Z', '2024-01-04T00:00:00Z');

INSERT INTO Sessions (Id, OidcSid, Username, CreatedAt, UpdatedAt, Expired)
VALUES ('bbbbbbbb-cccc-dddd-eeee-ffffffffffff', 'sid-old', 'old@lakeside.edu', CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), false);
