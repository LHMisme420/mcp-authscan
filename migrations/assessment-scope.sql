-- Additive sales-intake schema. Apply in development; review the additive
-- production schema diff in Publish. Not run by app startup or build scripts.
CREATE TABLE IF NOT EXISTS public.vata_assessment_scope_requests (
    id TEXT PRIMARY KEY CHECK (id ~ '^[a-f0-9]{64}$'),
    payload JSONB NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    email_reference TEXT
);
