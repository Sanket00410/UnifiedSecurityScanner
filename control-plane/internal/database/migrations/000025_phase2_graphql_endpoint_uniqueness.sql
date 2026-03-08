ALTER TABLE api_endpoints
    DROP CONSTRAINT IF EXISTS api_endpoints_tenant_id_api_asset_id_method_path_key;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'api_endpoints_tenant_asset_method_path_operation_unique'
    ) AND NOT EXISTS (
        SELECT 1
        FROM pg_class
        WHERE relname = 'api_endpoints_tenant_asset_method_path_operation_unique'
    ) THEN
        ALTER TABLE api_endpoints
            ADD CONSTRAINT api_endpoints_tenant_asset_method_path_operation_unique
                UNIQUE (tenant_id, api_asset_id, method, path, operation_id);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_api_endpoints_tenant_asset_operation
    ON api_endpoints (tenant_id, api_asset_id, method, path, operation_id);
