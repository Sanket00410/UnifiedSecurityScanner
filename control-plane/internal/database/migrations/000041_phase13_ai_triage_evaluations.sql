CREATE TABLE IF NOT EXISTS ai_triage_evaluations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    triage_request_id TEXT NOT NULL,
    verdict TEXT NOT NULL DEFAULT 'needs_review',
    grounded BOOLEAN NOT NULL DEFAULT TRUE,
    hallucination_score DOUBLE PRECISION NOT NULL DEFAULT 0,
    policy_violations_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    evaluator TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT ai_triage_evaluations_request_fk
        FOREIGN KEY (triage_request_id)
        REFERENCES ai_triage_requests (id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ai_triage_evaluations_tenant_created_idx
    ON ai_triage_evaluations (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS ai_triage_evaluations_tenant_verdict_idx
    ON ai_triage_evaluations (tenant_id, verdict, created_at DESC);
