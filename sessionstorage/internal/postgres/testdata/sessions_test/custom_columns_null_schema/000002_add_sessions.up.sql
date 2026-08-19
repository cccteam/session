INSERT INTO "Sessions" ("Id", "Username", "CreatedAt", "UpdatedAt", "Expired")
    VALUES
        ('44444444-4444-4444-4444-444444444444', 'null_user_1', '2024-01-04 10:00:00', '2024-01-04 10:05:00', false);

INSERT INTO "SessionCustomData" ("SessionId", "CustomString", "CustomInt", "CustomBool", "CustomFloat", "CustomTimestamp")
    VALUES
        ('44444444-4444-4444-4444-444444444444', 'partial', NULL, NULL, NULL, NULL);
