-- The tenants' declarations for the tenant policy scenarios: what each tenant admits,
-- read by the application's reader in the sign-in's transaction. Directories lists the
-- tenant's directories as method:connection, comma-separated.
BEGIN;

CREATE TABLE "TenantDeclarations"
(
    "Tenant" character varying NOT NULL,
    "Directories" character varying NOT NULL,
    "DirectoryOnly" boolean NOT NULL,
    CONSTRAINT "TenantDeclarations_pkey" PRIMARY KEY ("Tenant")
);

COMMIT;
