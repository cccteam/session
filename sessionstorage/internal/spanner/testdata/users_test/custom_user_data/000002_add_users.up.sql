INSERT INTO SessionUsers (Id, Username, PasswordHash, Disabled)
VALUES
    ('27b43588-b743-4133-8730-e0439065a844', 'dataUser', NULL, FALSE),
    ('54918893-2342-4621-8673-79520a84b84f', 'noDataUser', NULL, FALSE);

INSERT INTO UserCustomData (UserId, Locale, Theme, LoginCount)
VALUES ('27b43588-b743-4133-8730-e0439065a844', 'en-AU', 'dark', 3);
