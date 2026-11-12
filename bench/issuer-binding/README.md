Issuer-binding benchmark
Expected verdicts for the local decoy in run_issuer_binding.py.

The decoy imitates the flaw described in GHSA-qx49-fqc8-xw99 / CVE-2026-115563: a client that accepts authorization-server metadata without checking that it echoes the URL it was fetched from. It is a local imitation of that flaw, not the real package.

The boundary is two variables, not one: the client library version, and whether an issuer is supplied. Against probe set 2026.11.11.1 both versions FAIL when none is supplied. With one supplied, 4.1.2 PASSes and 4.1.1 is EXCLUDED because that version takes no issuer argument.

A run passes only when every case matches. A case that disagrees is recorded as it reported, not adjusted until it agrees.
