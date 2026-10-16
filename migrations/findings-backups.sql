-- Apply through the reviewed development/production schema process, not startup.
-- This stores complete private SQLite snapshots; it does not migrate SQLite rows.
CREATE TABLE IF NOT EXISTS public.vata_findings_backups (
    namespace text NOT NULL,
    generation bigint GENERATED ALWAYS AS IDENTITY,
    sha256 text NOT NULL CHECK (length(sha256) = 64),
    payload bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (namespace, generation)
);
-- No public API exposes this table. Restrict SQL access to the service role.
REVOKE ALL ON public.vata_findings_backups FROM PUBLIC;
