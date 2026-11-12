Issuer-binding benchmark
Expected verdicts for the local decoy in runissuerbinding.py.

The decoy imitates the flaw described in GHSA-qx49-fqc8-xw99 / CVE-2026-115563: a client that accepts authorization-server metadata without checking that it echoes the URL it was fetched from. It is a local imitation of that flaw, not the real package.

The version boundary comes from the advisory. Against probe set 2026.11.11.1, mcp 4.1.1 is expected to FAIL and 4.1.2 is expected to PASS.

A run passes only when every case matches. A case that disagrees is recorded as it reported, not adjusted until it agrees.
