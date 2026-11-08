# Adding a client binding row

This tests one thing about an MCP **client**: when a protected resource points at
an authorization server whose issuer does not match what the client was told to
expect, does the client hand over its credentials anyway?

You do **not** launch the decoy. `client_check` starts its own decoy
authorization server in-process, drives your client against it, and rules on what
the decoy captured — never on what the client claims. You provide two things: a
venv with the scanner, and a venv with the client under test.

## 1. Runner venv (the scanner)

From a clone of this repo:

```bash
python3 -m venv .runner
.runner/bin/pip install .          # installs mcp-authscan (1.1.20)
```

## 2. Client venv (the SDK under test)

A separate venv holding only the client you are measuring:

```bash
python3 -m venv .cut
.cut/bin/pip install "mcp==1.30.0"  # <- the client + version this row is for
```

## 3. Produce the row

Two runs. Both rows matter.

```bash
# Refusal path — client is told to expect a different issuer than the decoy advertises.
# --expect-issuer MUST be a full http(s) URL; a bare hostname is rejected and yields EXCLUDED.
.runner/bin/python -m mcp_authscan.client_check \
  --client-kind python --client-python .cut/bin/python \
  --client-name "python-sdk 1.30.0" \
  --expect-issuer "https://legit.example.com"

# Default path — no expectation set. This is the stored-credential branch, and it is where FAILs live.
.runner/bin/python -m mcp_authscan.client_check \
  --client-kind python --client-python .cut/bin/python \
  --client-name "python-sdk 1.30.0 default"
```

The two runs make **different claims about the same client**. With
`--expect-issuer`, the client is told which issuer to expect, and the refusal
logic can engage — a PASS means it declined to present credentials to the
mismatched issuer. Without it, the check exercises the **stored-credential
branch**: whether the client hands an already-stored credential to whatever token
endpoint the discovered authorization server advertises, issuer match or not. A
PASS on one is not a PASS on the other. A reviewer will ask which branch a row
measured, so the `--client-name` records it.

## Verdicts

- **FAIL** (exit 1) — the decoy captured a `POST /token` carrying an
  `Authorization` header. The client sent credentials to an issuer that did not
  match the protected resource.
- **PASS** (exit 0) — the client read the protected-resource metadata and
  presented no credential. Note: a client that never attempts the grant at all
  also PASSes here — PASS means "no credential reached the decoy," not "the client
  actively refused."
- **EXCLUDED** (exit 2) — neither happened. **This means the run measured
  nothing, not that the client is safe.** Read the `reason` field: it quotes the
  client's last stderr line (a provider not importable in the client venv, a wrong
  `--client-python`, or a bare-hostname `--expect-issuer`). An EXCLUDED row is not
  a valid submission.

## Submitting

Open a PR adding your row as `conformance/client-binding/<client>-<version>.json`
and **paste the full terminal transcript** — the exact command and its JSON
output — into the PR description. A row without a reproduced transcript is not
merged. If your steps produce EXCLUDED, the submission is incomplete; fix the
client venv until you get PASS or FAIL.

## Reproduced rows (produced by running the steps above)

Both rows are python-sdk 1.30.0. The PASS is the refusal path — the client was
told to expect a different issuer. The FAIL is the stored-credential branch — no
expectation set. Same client, two branches; a PASS on one is not a PASS on the
other.

```json
{"check": "client-issuer-binding", "kind": "python", "client": "python-sdk 1.30.0",
 "verdict": "PASS",
 "reason": "client read the protected-resource metadata and presented no credential to the token endpoint",
 "touches": ["/mcp", "/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server"],
 "captured": []}

{"check": "client-issuer-binding", "kind": "python", "client": "python-sdk 1.30.0 default",
 "verdict": "FAIL",
 "reason": "client presented an Authorization header to the decoy token endpoint, whose issuer did not match the protected resource (authorization: Basic...dA==)",
 "touches": ["/mcp", "/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server", "POST /token", "/mcp"],
 "captured": [{"path": "/token", "authorization": "Basic...dA==", "body_keys": ["grant_type", "resource"]}]}
```

## Scope

This covers single-verdict **client-credentials** binding rows from
`client_check`. The three-column `matrix.json`
(`metadata_issuer` / `credential_binding` / `token_response_iss`) is produced by a
separate conformance harness and is **not** covered by this guide. Node client
rows (`--client-kind node`) are not yet documented here.
