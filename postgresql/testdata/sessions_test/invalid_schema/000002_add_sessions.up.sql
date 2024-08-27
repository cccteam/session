INSERT INTO "Sessions" ("Id", "OidcSid", "Username", "CreatedAt", "UpdatedAt", "Expired") 
    VALUES 
        ('session 1', 'oidc session 1', 'test user 1', '2019-02-01 05:10:20+00:00', FALSE, '2020-01-02 08:05:03+00:00'),
        ('session 4', 'oidc session 4', 'test user 1', '2019-02-02 05:10:20+00:00', TRUE, '2020-01-02 08:05:03+00:00'),
        ('session 3', 'oidc session 3', 'test user 2', '2018-05-03 01:02:03+00:00', TRUE, '2020-01-02 08:05:03+00:00'),
        ('session 6', 'oidc session 6', 'test user 2', '2018-05-04 01:02:03+00:00', FALSE, '2020-01-02 08:05:03+00:00'),
        ('session 5', 'oidc session 5', 'test user 1', '2019-02-03 05:10:20+00:00', FALSE, '2020-01-02 08:05:03+00:00');