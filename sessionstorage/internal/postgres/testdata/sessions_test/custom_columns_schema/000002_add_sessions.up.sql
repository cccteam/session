INSERT INTO "Sessions" ("Id", "Username", "CreatedAt", "UpdatedAt", "Expired")
    VALUES
        ('11111111-1111-1111-1111-111111111111', 'custom_user_1', '2024-01-01 10:00:00', '2024-01-01 10:05:00', false),
        ('22222222-2222-2222-2222-222222222222', 'custom_user_2', '2024-01-02 11:00:00', '2024-01-02 11:05:00', true),
        ('33333333-3333-3333-3333-333333333333', 'custom_user_3', '2024-01-03 12:00:00', '2024-01-03 12:05:00', false);

INSERT INTO "SessionCustomData" ("SessionId", "CustomString", "CustomInt", "CustomBool", "CustomFloat", "CustomTimestamp")
    VALUES
        ('11111111-1111-1111-1111-111111111111', 'admin', 10, true, 99.5, '2024-06-15 08:30:00'),
        ('22222222-2222-2222-2222-222222222222', 'viewer', 5, false, 42.0, '2024-03-20 14:00:00');
