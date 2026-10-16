-- Explicit Preview preparation only; never an automatic startup migration.
CREATE TABLE IF NOT EXISTS public.vata_test_webhook_receipts (
    event_id TEXT PRIMARY KEY,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
