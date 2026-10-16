-- Isolated test database only. Deliberately no production migration helper.
CREATE TABLE public.vata_accounts (
  id integer PRIMARY KEY, clerk_user_id text UNIQUE, stripe_customer_id text,
  subscription_tier text, subscription_expires_at timestamptz
);
CREATE TABLE public.vata_memberships (user_id text, account_id integer, label text, joined_at timestamptz);
CREATE TABLE public.vata_scan_usage (account_id integer, month date, scans integer);
CREATE TABLE public.vata_team_invites (
  id integer, account_id integer, token_hash text, expires_at timestamptz, used_at timestamptz, revoked_at timestamptz
);
CREATE TABLE public.vata_api_tokens (
  id integer, account_id integer, user_id text, name text, token_hash text,
  created_at timestamptz, last_used_at timestamptz, revoked_at timestamptz
);
CREATE TABLE public.vata_scan_schedules (
  id integer, account_id integer, created_by text, target_url text, frequency text,
  next_run_at timestamptz, enabled boolean, lease_until timestamptz,
  last_run_at timestamptz, last_error text, created_at timestamptz
);
INSERT INTO public.vata_accounts VALUES (1, 'user_fixture', NULL, 'free', NULL);
CREATE ROLE startup_reader LOGIN;
GRANT CONNECT ON DATABASE postgres TO startup_reader;
GRANT USAGE ON SCHEMA public TO startup_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO startup_reader;
ALTER ROLE startup_reader SET default_transaction_read_only = on;
