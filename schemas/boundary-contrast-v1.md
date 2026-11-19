# boundary-contrast-v1

**Status:** Draft, normative. Specified, not implemented: no code emits or verifies it yet.
**Depends on:** [observation-v1](observation-v1.md) (EXCLUDED and NOT_OBSERVED keep their meanings from §3 there)

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Purpose

Boundary Contrast v1 does not determine whether an MCP implementation is vulnerable. It establishes reproducible behavioral differences against server-declared expectations, using independently qualified controls. Nothing in this document lets AuthScan claim more than what an MCP boundary demonstrably did.

## 2. Scope and authorization

Contrast is a separate mode, not a flag on an ordinary scan. Ordinary scans stay credentialless.

A contrast run MUST NOT start without an operator-supplied credential and a written grant naming:

- the endpoint;
- the credential;
- the eligible operations;
- the paired anonymous and credentialed requests;
- the varying dimension of each pair;
- the number of repetitions;
- the assessment window;
- the request ceiling.

AuthScan MUST NOT register a client, issue a token, escalate a privilege, or acquire a credential itself.

Eligible operations in v1 are `initialize`, `tools/list`, `resources/list` and `prompts/list`. If authorization for an operation cannot be established without changing state, that operation is EXCLUDED with the prerequisite `non-mutating baseline unavailable`. There is no sandbox flag, no accept-risk flag and no mutation exception: judging whether a claimed sandbox is isolated is a different trust problem.

## 3. The experiment

**Canonical request.** Records method, route, transport, declared dimensions, operation and session establishment, plus a request equivalence id computed over exactly those fields.

**Canonical observation.** Only fields declared volatile in advance are stripped: date, request id, trace id, session nonce, server timing, and ordering where the response is semantically unordered. An undeclared difference MUST NOT be normalized.

**Sessions.** Every execution gets a fresh session. Session establishment is part of the pair and is never shared between candidate and control.

**Ordering.** One repetition runs the pair in both orders: candidate then control, and control then candidate. Cache and ordering effects therefore cannot pass as an authorization effect.

**Repetitions.** The default is three repetitions, so six candidate and six control executions per pair. All canonical candidate observations MUST be equivalent to each other, and likewise all control observations. Ten repetitions is a higher-confidence mode, not the default. The request ceiling in the grant counts every execution, session establishment included.

**One dimension.** Exactly one declared dimension varies within a pair. If a second dimension differs, the pair is NOT_OBSERVED, not a contrast.

## 4. Baseline qualification

A credential being accepted is not proof of authorization. Before the baseline takes part in a contrast, authorization for the target operation MUST be demonstrated: an observed ALLOW on that same operation, in the same scope and context as the contrast, in every repetition.

If that is not shown, the operation is EXCLUDED with the prerequisite `credential capability not verified`.

If the credential stops working mid-run, the result is NOT_OBSERVED with the reason `CREDENTIAL_INVALIDATED_DURING_ASSESSMENT`. The run MUST NOT continue against a moving baseline.

## 5. Expectations and the probe search

An expectation is stored with its provenance, never as a single field:

| Field | Content |
|---|---|
| outcome | the expected behavior |
| basis | `server_declaration` or `normative_rule` (the latter cannot produce a result in v1, see §6) |
| source_uri | where the declaration was fetched |
| fetched_at | fetch time |
| document_sha256 | hash of the whole document fetched |
| quoted_field | the exact field relied on |
| document_covers | what that document claims to cover |
| observation_ids | the observations supporting the expectation |

Report language MUST take this form: *the declaration observed at assessment time stated X; controlled observations demonstrated Y.*

If the declaration changes during the assessment, the result is NOT_OBSERVED with the reason `DECLARATION_CHANGED_DURING_ASSESSMENT`.

Known-probe search runs only after a result is established. It annotates the result and never decides it. It reports `NOT_FOUND`, or `MATCHED` with the probe id, always together with the probe-set version, the dimensions searched and the dimensions not searched. A probe-search result is never written as `NONE`.

## 6. Levels, terminals and the warning

Every result carries its evidence level on its face:

- **L1 OBSERVATION**: something happened and was recorded.
- **L2 VERIFIED ASYMMETRY**: one controlled dimension varied, both sides were stable, and a behavioral difference was shown.
- **L3 DECLARED CONTRAST**: an L2 difference contradicts a contemporaneously observed declaration.
- **L4 NORMATIVE CONTRAST**: reserved. Present in the schema, unreachable in v1.

Each level meets its own requirements. No level inherits certainty from the one below.

Terminals: `EXCLUDED`, `NOT_OBSERVED`, `NO_ASYMMETRY`, `VERIFIED_ASYMMETRY`, `VERIFIED_DECLARED_CONTRAST`.

The counterexample field is `NOT_ESTABLISHED` in every terminal except `VERIFIED_DECLARED_CONTRAST`, where it is `ESTABLISHED`. In v1 the severity field is always `NONE`, and so is the interpretation field.

Required warning, printed verbatim on every contrast report:

> Boundary Contrast v1 is intentionally low-yield. A result of NO_ASYMMETRY across all eligible operations is a valid and expected assessment outcome. Absence of a verified asymmetry must never cause eligibility, baseline, repetition or equivalence requirements to be relaxed.
