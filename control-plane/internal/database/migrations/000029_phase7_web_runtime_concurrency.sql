ALTER TABLE web_crawl_policies
    ADD COLUMN IF NOT EXISTS max_concurrency BIGINT NOT NULL DEFAULT 8;
