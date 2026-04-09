INSERT INTO Sessions (Id, Username, CreatedAt, UpdatedAt, Expired)
    VALUES
        ('11111111-1111-1111-1111-111111111111', 'custom_user_1', '2024-01-01T10:00:00Z', '2024-01-01T10:05:00Z', false),
        ('22222222-2222-2222-2222-222222222222', 'custom_user_2', '2024-01-02T11:00:00Z', '2024-01-02T11:05:00Z', true);

INSERT INTO SessionCustomData (SessionId, CustomString, CustomInt, CustomBool, CustomFloat, CustomTimestamp)
    VALUES
        ('11111111-1111-1111-1111-111111111111', 'admin', 10, true, 99.5, '2024-06-15T08:30:00Z'),
        ('22222222-2222-2222-2222-222222222222', 'viewer', 5, false, 42.0, '2024-03-20T14:00:00Z');
