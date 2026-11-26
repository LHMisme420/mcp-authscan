# Deployment Acknowledgment Proof (DAP)

> This signed report records an acknowledgment challenge observed at the designated
> publication location for the named target. It does not establish tenant ownership,
> independently prove that the recorded network request occurred, demonstrate
> authorization security, or establish the deployment's current security posture.

That statement is embedded verbatim in every acknowledgment record (`statement`),
and the offline verifier rejects a record that alters it.

## Roles and flow

1. **Reviewer** issues a challenge and keeps a copy:

   ```
   mcp-authscan challenge create --target https://mcp.example.com/mcp \
       --output challenge.json [--ttl 3600] [--binding-scope dedicated-host|shared-provider-host|unknown]
   ```

   The nonce is `secrets.token_hex(32)` (256 bits). `challenge_id` is the SHA-256 of the
   canonical JSON (sorted keys, no whitespace) of every other field: `schema`, `nonce`,
   `target`, `publication_path`, `binding_scope`, `created_at`, `expires_at`. Changing any
   field, including the expiry, invalidates the identifier. The output file is never
   overwritten.

2. **Deployment controller** publishes the nonce, alone, at
   `https://<target origin>/.well-known/mcp-authscan-challenge`. The body must be exactly
   the 64-character nonce, optionally followed by one `\n` or `\r\n`. The origin is the
   target's own scheme, host and port. Nothing is rewritten: an `http://` target, a
   target with credentials, a query or a fragment is refused, not adjusted.

3. **Operator** checks the publication (optional) and then scans:

   ```
   mcp-authscan challenge verify --challenge challenge.json [--allow-private]
   mcp-authscan https://mcp.example.com/mcp --deployment-challenge challenge.json \
       --sign --json --contact ... --authorized-by ... --auth-basis ...
   ```

   `--deployment-challenge` keeps its existing meaning for a 64-hex value (it binds
   authentication assurance). Any other value is read as a `deployment-challenge-v1` file.
   A challenge file requires `--sign`. It combines with `--authentication-assurance`:
   the run produces one sig_version 5 report whose signature covers both the assurance
   (inside `content_observed`) and the acknowledgment. Give `--deployment-challenge` twice
   to bind assurance to a 64-hex challenge as well; the DAP nonce is never used as an
   assurance challenge. If either component cannot be signed, no report is written. A challenge that is
   malformed, altered, not yet valid, or issued for a different target stops the run
   with exit 2. No scan runs and no report is written.

4. **Reviewer** verifies offline against the challenge *they* issued:

   ```
   mcp-authscan challenge verify-report --report report.json --challenge challenge.json \
       [--trust-anchor keys.json] [--live [--allow-private]]
   ```

## Fetch constraints

The publication fetch uses the scanner's existing DNS-pinned transport
(`oauth_probes_v2.open_pinned`). There is no second HTTP client.

- one DNS resolution. Every address returned must be globally routable unless
  `--allow-private` is given explicitly. Private, loopback, link-local, CGNAT and
  metadata (169.254.169.254) destinations are refused by default. The socket connects
  to the address that was checked, so a later rebinding answer is never consulted.
- certificate and hostname validation via `ssl.create_default_context()`.
- no redirects: a 3xx is recorded as `NOT_OBSERVED`, and its `Location` is never fetched.
- no proxy (`ProxyHandler({})`; proxy environment variables are ignored), no
  credentials, no cookies, a `GET` with only `User-Agent`, `Accept` and
  `Cache-Control`.
- a 1024-byte body cap (both the declared `Content-Length` and the bytes read), and a
  total deadline (default 10 s, maximum 30 s).

## Verdicts

These are separate from the assurance verdicts (CURRENT / STALE / REGRESSED /
INCONCLUSIVE), which are unchanged.

| Result | Meaning |
|---|---|
| `ACKNOWLEDGED` | HTTP 200 over verified TLS, inside the validity window, body exactly the nonce |
| `NOT_OBSERVED` | DNS failure, refused destination, TLS failure, timeout, redirect, non-200, oversize |
| `MISMATCH` | HTTP 200 over verified TLS, but the body is not the nonce |
| `EXPIRED` | the observation is at or after `expires_at` (no request is made) |
| `INVALID` | malformed or altered challenge or record, wrong target, unsigned or unverifiable report |

The same function (`deployment_ack.evaluate`) decides the result when the scan observes it
and again when the offline verifier recomputes it. A signed record whose stated result
differs from what its own observation supports is `INVALID`.

## Signature form: sig_version 5

The record is stored as `deployment_acknowledgment`. It is outside `report_hash`, so graded
hashes are unchanged, and inside a new signature form:

`{"sig_version": 5, "evidence", "report", "probes", "provenance", "content_observed" (operations, or null), "deployment_acknowledgment"}`

Forms 1-4 are byte-for-byte unchanged and now **refuse** a report that carries a
`deployment_acknowledgment` field, because they do not cover it. An unsigned record can't
ride along under an older signature. Existing signed reports, historical release reports
and the packaged trust anchor are untouched.

A form-5 `content_observed` that declares no operations is signed as `null`. Any other
`content_observed` in a form-5 report (for example an `authentication_assurance` block
without operations) is refused as uncovered rather than left outside the signature.

## Policy gate

`policy_check` reads component coverage from the verification engine, not from the
declared `sig_version`. Signed operations and authentication assurance count only when an
authentic form-4 signature, or form-5 signature over a report that declares operations,
covers `content_observed`. `min-sig-version: N` additionally requires every component that
form N signs to be verified, so a form-5 report without operations does not satisfy
`min-sig-version: 4`.

A policy can require the acknowledgment explicitly:

```json
{"deployment-acknowledgment-required": true,
 "deployment-acknowledgment-challenge": { ...the reviewer-issued challenge... }}
```

The gate then runs `deployment_ack.verify_report` against that challenge and REJECTs
(`DEPLOYMENT-ACKNOWLEDGMENT`) unless the offline verdict is `ACKNOWLEDGED`. A challenge
given without the requirement, or a malformed challenge, is a policy error (REJECT). The
gate never makes a network request; reviewer-side live confirmation stays a separate
`verify-report --live` step. The same signed record verifies every time it is presented:
offline verification has no replay registry. Single-use consumption applies to the
authentication-assurance challenge through `--challenge-db`.

## Offline verification checks

`verify-report` (`deployment_ack.verify_report`) returns `INVALID` unless all of these pass.
If they do, it returns the recomputed result.

- report integrity (`report_hash`, `evidence_hash`) and an Ed25519 signature by a key in
  the trust anchor, declared as sig_version 5, with `deployment_acknowledgment` covered.
- **challenge binding**: the embedded challenge is valid and its `challenge_id`
  recomputes. The record's `challenge_id`, `nonce` and `binding_scope` match it.
- **reviewer challenge**: the embedded challenge is byte-identical (canonical JSON) to the
  one the reviewer supplied. This is what establishes reviewer participation. A
  scanner-generated challenge alone establishes nothing about the reviewer.
- **target identity**: the report `target`, the recorded `requested_target`, the challenge
  target, the publication origin and the publication URL all agree.
- **observation record**: GET, no credentials, no redirects, no proxy, the fixed body cap,
  and the unaltered limitations and statement.
- **response digest**: the SHA-256 and length of the recorded body match.
- **result recomputation**, including the validity window against the signed
  `observed_at`.

Offline verification proves that the record is unaltered and was signed by a trusted
key. It is **not** independent proof that the network request happened. The output says
so in `network_request`.

`--live` is a separate, explicitly requested check. It requires network access, makes a
fresh fetch under the same destination protections, and is reported as
`live_confirmation`. It never changes the offline verdict.

## Binding scope and multi-tenant limits

`binding_scope` is declared by the reviewer when the challenge is created
(`dedicated-host`, `shared-provider-host` or `unknown`; default `unknown`). It is bound
into `challenge_id`. It is **never inferred from a hostname**.

A challenge on a shared hosting domain shows control of the publication location. It does
not necessarily show control of a particular MCP tenant. On any host, acknowledgment says
nothing about whether authorization is secure.

## Single use

A challenge is valid for its window and for its one target. The reviewer enforces single
use by accepting one report per `challenge_id`. Replay against another target, and use
outside the window, are rejected by the verifier.
