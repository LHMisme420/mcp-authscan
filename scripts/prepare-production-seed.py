"""Prepare an explicitly empty, operator-run import. Never connects to PostgreSQL."""
import base64
import hashlib
import html
import json
from pathlib import Path
import sqlite3
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from mcp_authscan.findings_schema import initialize_database


def main():
    output = ROOT / "generated-artifacts"
    output.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="vata-empty-seed-") as directory:
        source = Path(directory) / "empty.sqlite"
        initialize_database(source)
        with sqlite3.connect(source) as conn:
            assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            tables = {row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            assert tables == {"organizations", "findings", "scan_runs", "compliance_reports"}
            for table in tables:
                assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
        payload = source.read_bytes()
    checksum = hashlib.sha256(payload).hexdigest()
    encoded = base64.b64encode(payload).decode("ascii")
    verification = """SELECT 'production-findings' AS namespace,
       count(*) AS snapshot_count,
       max(generation) AS latest_generation,
       max(created_at) AS latest_snapshot_at
FROM public.vata_findings_backups
WHERE namespace = 'production-findings';"""
    sql = f"""-- VATA: single-statement EMPTY findings seed for the PRODUCTION SQL runner.
-- No account/ownership changes, schema creation, deletes or snapshot overwrites.
-- Generation 0 is reserved for this seed. Normal identity generations start at 1,
-- so even a concurrently committed snapshot cannot be superseded by an empty seed.
WITH writer AS MATERIALIZED (
    SELECT pg_try_advisory_xact_lock(
        hashtextextended('vata-findings:production-findings', 0)
    ) AS acquired
), seeded AS (
    INSERT INTO public.vata_findings_backups(namespace, generation, sha256, payload)
    OVERRIDING SYSTEM VALUE
    SELECT 'production-findings', 0, '{checksum}', decode('{encoded}', 'base64')
    FROM writer
    WHERE writer.acquired AND NOT EXISTS (
        SELECT 1 FROM public.vata_findings_backups
        WHERE namespace = 'production-findings'
    )
    ON CONFLICT (namespace, generation) DO NOTHING
    RETURNING namespace
)
SELECT CASE
    WHEN NOT (SELECT acquired FROM writer) THEN 'BLOCKED_WRITER_ACTIVE'
    WHEN EXISTS (SELECT 1 FROM seeded) THEN 'SEEDED'
    ELSE 'ALREADY_EXISTS'
END AS result,
'production-findings' AS namespace,
(SELECT count(*) FROM public.vata_findings_backups
 WHERE namespace = 'production-findings') + (SELECT count(*) FROM seeded) AS snapshot_count;
"""
    (output / "production-findings-seed.sql").write_text(sql)
    (output / "production-findings-verify.sql").write_text(verification + "\n")
    guide = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VATA — one-time production seed</title>
<style>
body{{font:16px/1.55 system-ui,sans-serif;background:#f3f1ea;color:#172922;margin:0}}
main{{max-width:820px;margin:40px auto;padding:30px;background:white;border:1px solid #d6ded8;border-radius:14px}}
h1{{font-size:30px;line-height:1.2}}h2{{font-size:20px;margin-top:30px}}
button{{background:#185b49;color:white;border:0;border-radius:7px;padding:12px 18px;cursor:pointer;font:inherit;margin:5px 8px 5px 0}}
code,pre,textarea{{font-family:ui-monospace,monospace}}code{{overflow-wrap:anywhere}}
textarea{{box-sizing:border-box;width:100%;height:160px;padding:12px;border:1px solid #b8c5bd;border-radius:6px;font-size:12px}}
.notice{{padding:14px 18px;border-left:4px solid #a36b12;background:#fff6df}}
.meta{{padding:12px 18px;background:#edf4f0;border-radius:8px}}
#status{{min-height:24px;color:#185b49}}li{{margin:10px 0}}small{{color:#4f6258}}
</style></head><body><main>
<small>VATA · OPERATOR INSTRUCTIONS · NOT YET RUN IN PRODUCTION</small>
<h1>Single-statement production import</h1>
<p class="notice"><strong>This replaces the old BEGIN/COMMIT script.</strong>
There is now only one SQL statement. Replace all old editor text with this version.</p>
<p>This import contains an empty SQLite snapshot. It does not contain credentials,
findings, scan history, or account records.</p>
<div class="meta"><strong>Namespace:</strong> <code>production-findings</code><br>
<strong>Snapshot size:</strong> {len(payload):,} bytes<br>
<strong>SHA-256:</strong> <code>{checksum}</code></div>
<p class="notice"><strong>Select Production before running.</strong> The script cannot tell
which database you selected. Workspace <code>DATABASE_URL</code> targets development.
Do not publish until the production verification query reports a snapshot.</p>
<h2>1. Run the import in Production</h2>
<ol><li>In Replit, open <strong>Database</strong>, select the <strong>Production</strong>
database, then open its SQL runner.</li>
<li>Use <strong>Copy import SQL</strong> below. Replace all text in the SQL
editor with the copied statement, then click the main green Run button.
Do not add <code>BEGIN;</code> or <code>COMMIT;</code>.
The download is an alternative if copying is unavailable.</li>
<li>For a new namespace, expect one result row with <code>result = SEEDED</code>
and <code>snapshot_count = 1</code>.
<code>ALREADY_EXISTS</code> means an existing snapshot was left untouched.
Return either result to Agent for a production read-only check before publishing.</li></ol>
<button id="copy">Copy import SQL</button><button id="download">Download SQL file</button>
<p id="status" role="status" aria-live="polite"></p>
<details><summary>Show import SQL / manual copy fallback</summary>
<p>Select all text in this box and copy it.</p><textarea id="sql" readonly aria-label="Complete production import SQL">{html.escape(sql)}</textarea></details>
<h2>2. Verify the production snapshot</h2>
<textarea id="verify" readonly aria-label="Production verification query">{html.escape(verification)}</textarea>
<button id="copyVerify">Copy verification query</button>
<h2>3. Only then publish</h2>
<p>Return the verification result to Agent for a production read-only check.
Then publish with PostgreSQL durability enabled and <strong>Max machines = 1</strong>.
Startup restores an existing snapshot; it does not create a missing one.
The empty snapshot deliberately does not carry over old local-only findings.
PostgreSQL account ownership remains untouched.</p>
<h2>If the import fails</h2>
<ul><li><strong>BLOCKED_WRITER_ACTIVE:</strong> an existing instance holds the findings writer lock.
No seed is inserted.
Do not kill database sessions or disable the lock. Return the error to Agent.</li>
<li><strong>Missing table or permission denied:</strong> stop and return the error.
Do not add runtime schema creation or paste credentials into chat.</li>
<li><strong>Any transaction error:</strong> run <code>ROLLBACK;</code> if the SQL runner
keeps the session in an aborted transaction, then return the error. Do not publish yet.</li></ul>
<p><small>This file does not connect to any service. Copying or downloading does not execute SQL.</small></p>
</main><script>
async function copy(id) {{
 const field=document.getElementById(id);
 try {{ await navigator.clipboard.writeText(field.value); document.getElementById('status').textContent='Copied. Paste into the Production database SQL runner.'; }}
 catch {{ field.closest('details')?.setAttribute('open',''); field.focus(); field.select(); document.getElementById('status').textContent='Copy is unavailable here. The SQL text is selected; copy it manually.'; }}
}}
document.getElementById('copy').onclick=()=>copy('sql');
document.getElementById('copyVerify').onclick=()=>copy('verify');
document.getElementById('download').onclick=()=>{{
 const url=URL.createObjectURL(new Blob([document.getElementById('sql').value],{{type:'text/plain'}}));
 const a=document.createElement('a');a.href=url;a.download='production-findings-seed.sql';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}};
</script></body></html>"""
    (output / "production-findings-seed-guide.html").write_text(guide)
    print(json.dumps({"namespace": "production-findings", "snapshot_bytes": len(payload),
                      "sha256": checksum, "sqlite_rows": 0,
                      "sql_file": "generated-artifacts/production-findings-seed.sql",
                      "guide": "generated-artifacts/production-findings-seed-guide.html",
                      "production_write_performed": False}, indent=2))


if __name__ == "__main__":
    main()
