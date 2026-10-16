-- Additive application metadata only. Never stores subscription state or Stripe secrets.
-- Apply explicitly before opting production into VATA_BILLING_MODE=live.
CREATE TABLE IF NOT EXISTS public.vata_billing_customers (
    account_id integer NOT NULL REFERENCES public.vata_accounts(id) ON DELETE CASCADE,
    stripe_account_id text NOT NULL,
    livemode boolean NOT NULL,
    customer_id text NOT NULL,
    PRIMARY KEY (account_id, stripe_account_id, livemode),
    UNIQUE (stripe_account_id, livemode, customer_id)
);
CREATE TABLE IF NOT EXISTS public.vata_billing_webhook_receipts (
    stripe_account_id text NOT NULL,
    livemode boolean NOT NULL,
    endpoint_url text NOT NULL,
    event_id text NOT NULL,
    event_type text NOT NULL,
    processed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (stripe_account_id, livemode, endpoint_url, event_id)
);
