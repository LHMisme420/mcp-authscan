Issuer-binding benchmark
Expected verdicts for the local decoy in run_issuer_binding.py.

The decoy imitates the flaw described in GHSA-qx49-fqc8-xw99 / CVE-2026-115563: a client that accepts authorization-server metadata without checking that it echoes the URL it was fetched from. It is a local imitation of that flaw, not the real package.

The boundary is two variables, not one: the client library version, and whether an issuer is supplied. Against probe set 2026.11.11.1 both versions FAIL when none is supplied. With one supplied, 4.1.2 PASSes and 4.1.1 is EXCLUDED because that version takes no issuer argument.

A run passes only when every case matches. A case that disagrees is recorded as it reported, not adjusted until it agrees.
python3 -m venv /tmp/b411
/tmp/b411/bin/pip install fastmcp==4.1.1
python3 -m venv /tmp/b412
/tmp/b412/bin/pip install fastmcp==4.1.2

/tmp/b411/bin/python run_issuer_binding.py
/tmp/b412/bin/python run_issuer_binding.py
/tmp/b412/bin/python run_issuer_binding.py --expect-issuer
/tmp/b411/bin/python run_issuer_binding.py --expect-issuer


Held constant: mcp 2.3.0. The refusal in the PASS case is raised by mcp.client.auth.extensions.client_credentials (_require_metadata_for_configured_issuer); fastmcp 4.1.2 forwards issuer to it, and 4.1.1 has no issuer parameter (signature-411.txt). Observed record: runs/20261114T225452Z, verified by its SHA256SUMS. Expected file sha256 after the fixture-name fix: 22bf57bb1497b01560d0f8d44a6bbfd55e80b43603fd73d34ee6c516fb81194b.
