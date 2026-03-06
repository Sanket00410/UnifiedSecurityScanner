CREATE INDEX IF NOT EXISTS normalized_findings_tenant_severity_idx
    ON normalized_findings (tenant_id, (LOWER(COALESCE(finding_json->>'severity', ''))));

CREATE INDEX IF NOT EXISTS normalized_findings_tenant_status_idx
    ON normalized_findings (tenant_id, (LOWER(COALESCE(finding_json->>'status', ''))));

CREATE INDEX IF NOT EXISTS normalized_findings_tenant_priority_idx
    ON normalized_findings (tenant_id, (LOWER(COALESCE(finding_json->'risk'->>'priority', ''))));

CREATE INDEX IF NOT EXISTS normalized_findings_tenant_layer_idx
    ON normalized_findings (tenant_id, (LOWER(COALESCE(finding_json->'source'->>'layer', ''))));

CREATE INDEX IF NOT EXISTS normalized_findings_tenant_overdue_idx
    ON normalized_findings (tenant_id, ((COALESCE(LOWER(finding_json->'risk'->>'overdue'), 'false') = 'true')));

CREATE INDEX IF NOT EXISTS normalized_findings_search_text_idx
    ON normalized_findings
    USING GIN (
        TO_TSVECTOR(
            'simple',
            COALESCE(finding_json->>'title', '') || ' ' ||
            COALESCE(finding_json->>'description', '') || ' ' ||
            COALESCE(finding_json->>'category', '') || ' ' ||
            COALESCE(finding_json->'asset'->>'asset_id', '') || ' ' ||
            COALESCE(finding_json->'asset'->>'asset_name', '')
        )
    );
