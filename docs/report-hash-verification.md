# Verify a compliance report's content hash

After publishing, first export a PDF from the **deployed**, signed-in dashboard
and confirm its Report Integrity section says **schema version 2**, includes a
SHA-256 hash, and contains the verification instructions. A local PDF does not
verify the deployed release.

For unchanged workspace data, download a second PDF and save the JSON from
`/api/reports/pdf?format=json` on that same deployed site. Authentication and
workspace access checks are identical to the PDF endpoint.

Save the JSON response as `report.json` and recompute:

```python
import hashlib
import json

with open("report.json", encoding="utf-8") as source:
    export = json.load(source)

payload = json.dumps(
    export["canonical_report"],
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=True,
    allow_nan=False,
).encode("utf-8")
digest = hashlib.sha256(payload).hexdigest()
assert digest == export["content_hash"]
print(digest)
```

Compare that digest with the hashes in both PDFs, not with a hash of the PDF
files themselves. Export timestamps and PDF metadata may differ.

## Hashed content

`canonical_report` contains:

- `schema_version`: `2`.
- `scan_runs`: newest-first scan records, each with `target`, `status`,
  `total_checks`, `findings_count`, `started_at`, `completed_at`, `attested_at`.
- `severity_counts`: counts for **all** findings in the workspace.
- `findings`: up to the 1,000 most recent findings, newest first (timestamp
  descending, then ID descending). Each includes `server_name`, `rule`,
  `vector_type`, `severity`, `description`, `remediation`, `created_at`.

Keep array order, null values and string contents exactly as exported. Sort
object keys recursively through `sort_keys=True`; do not sort the arrays.
The PDF and JSON use the same database snapshot within each request, but
separate requests can differ if a scan, finding or authorization changes.
Stop making changes while collecting comparison exports.

This checksum binds the exported findings to their recorded scan context. It
is not a signature, proof of origin, certification, or a hash of every row in
the database. Older findings beyond the PDF limit are represented only by
aggregate severity counts.
