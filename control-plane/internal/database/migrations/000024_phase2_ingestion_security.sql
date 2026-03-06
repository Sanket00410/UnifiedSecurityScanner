ALTER TABLE ingestion_sources
    ADD COLUMN IF NOT EXISTS webhook_secret_encrypted TEXT NOT NULL DEFAULT '';

ALTER TABLE ingestion_sources
    ADD COLUMN IF NOT EXISTS signature_required BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE ingestion_sources
SET signature_required = FALSE
WHERE signature_required IS NULL;
