INSERT INTO Sessions (Id, Username, CreatedAt, UpdatedAt, Expired)
    VALUES
        ('11111111-1111-1111-1111-111111111111', 'collision_user_1', '2024-01-01T10:00:00Z', '2024-01-01T10:05:00Z', false),
        ('22222222-2222-2222-2222-222222222222', 'collision_user_2', '2024-01-02T11:00:00Z', '2024-01-02T11:05:00Z', true);

INSERT INTO SessionCustomData (SessionId, Expired)
    VALUES
        ('11111111-1111-1111-1111-111111111111', 'custom_not_expired'),
        ('22222222-2222-2222-2222-222222222222', 'custom_expired');
