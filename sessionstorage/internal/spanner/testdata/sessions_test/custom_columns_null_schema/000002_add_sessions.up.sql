INSERT INTO Sessions (Id, Username, CreatedAt, UpdatedAt, Expired)
    VALUES
        ('44444444-4444-4444-4444-444444444444', 'null_user_1', '2024-01-04T10:00:00Z', '2024-01-04T10:05:00Z', false);

INSERT INTO SessionCustomData (SessionId, CustomString, CustomInt, CustomBool, CustomFloat, CustomTimestamp)
    VALUES
        ('44444444-4444-4444-4444-444444444444', 'partial', NULL, NULL, NULL, NULL);
