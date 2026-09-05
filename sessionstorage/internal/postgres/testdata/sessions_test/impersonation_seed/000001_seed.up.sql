INSERT INTO "Sessions" ("Id", "Username", "CreatedAt", "UpdatedAt", "Expired")
    VALUES
        ('11111111-1111-1111-1111-111111111111', 'bob@partner.org', '2026-08-27 10:00:00', '2026-08-27 10:05:00', false),
        ('22222222-2222-2222-2222-222222222222', 'alice@example.com', '2026-08-27 09:00:00', '2026-08-27 09:30:00', true),
        ('33333333-3333-3333-3333-333333333333', 'plain_user', '2026-08-27 10:00:00', '2026-08-27 10:05:00', false),
        ('44444444-4444-4444-4444-444444444444', 'carol@partner.org', '2026-08-27 10:00:00', '2026-08-27 10:05:00', false),
        ('66666666-6666-6666-6666-666666666666', 'dave@example.com', '2026-08-27 10:00:00', '2026-08-27 10:05:00', false);

INSERT INTO "SessionCustomData" ("SessionId", "CustomString")
    VALUES
        ('11111111-1111-1111-1111-111111111111', 'admin');

INSERT INTO "SessionImpersonations" ("SessionId", "ActorUsername", "ActorRealm", "SourceSessionId", "PrincipalKind", "PrincipalUser", "PrincipalRole", "Mask", "Reason", "StartedAt", "ExpiresAt", "EndedAt", "EndReason")
    VALUES
        ('11111111-1111-1111-1111-111111111111', 'alice@example.com', 'admin-portal', '55555555-5555-5555-5555-555555555555', 'User', 'bob@partner.org', NULL, 'List,Read', 'ticket JRN-1', '2026-08-27 10:00:00', '2026-08-27 11:00:00', NULL, NULL),
        ('22222222-2222-2222-2222-222222222222', 'alice@example.com', NULL, NULL, 'Role', NULL, 'PartnerViewer', NULL, NULL, '2026-08-27 09:00:00', '2026-08-27 10:00:00', '2026-08-27 09:30:00', 'Logout'),
        ('44444444-4444-4444-4444-444444444444', 'alice@example.com', NULL, NULL, 'User', 'carol@partner.org', NULL, '', NULL, '2026-08-27 10:00:00', '2026-08-27 11:00:00', NULL, NULL),
        ('66666666-6666-6666-6666-666666666666', 'dave@example.com', NULL, NULL, 'Role', NULL, 'Editor', NULL, NULL, '2026-08-27 10:00:00', '2026-08-27 11:00:00', NULL, NULL);
