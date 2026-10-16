-- Apply in development, then let Replit Publish apply the production schema diff.
-- This durable receipt prevents an enabled bootstrap flag from recreating a
-- namespace if all of its snapshots are subsequently lost or deleted.
CREATE TABLE IF NOT EXISTS public.vata_findings_initializations (
    namespace text PRIMARY KEY,
    sha256 text NOT NULL CHECK (length(sha256) = 64),
    initialized_at timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON public.vata_findings_initializations FROM PUBLIC;
