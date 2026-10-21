-- The tenants' declarations for the tenant policy scenarios: what each tenant admits,
-- read by the application's reader in the sign-in's transaction. Directories lists the
-- tenant's directories as method:connection, comma-separated.
CREATE TABLE TenantDeclarations (
    Tenant        STRING(MAX) NOT NULL,
    Directories   STRING(MAX) NOT NULL,
    DirectoryOnly BOOL NOT NULL,
) PRIMARY KEY (Tenant);
