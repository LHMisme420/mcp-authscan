# boundary-contrast-v1

**Status:** Draft, normative. Specified, not implemented: no code emits or verifies it yet.
**Depends on:** [observation-v1](observation-v1.md) (EXCLUDED and NOT_OBSERVED keep their meanings from §3 there), [boundary-ledger-v1](boundary-ledger-v1.md) (§7)

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

The assessment window and request ceiling in the grant are hard bounds. If either is reached before a pair completes, that pair's result MUST be NOT_OBSERVED with the reason `BUDGET_EXHAUSTED_DURING_PAIR` or `WINDOW_EXPIRED_DURING_PAIR`, and MUST NOT be graded on the executions that completed. A completed candidate beside an incomplete control is an observation, never an asymmetry.

A run that ends with unresolved pairs MUST report how many there are and MUST NOT summarise the run as complete.

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

Known-probe search runs only after a result is established. It never changes the terminal; it decides only the counterexample field (§6). It reports `NOT_FOUND`, or `MATCHED` with the probe id, always together with the probe-set version, the dimensions searched and the dimensions not searched. A probe-search result is never written as `NONE`.

## 6. Levels, terminals and the warning

Every result carries its evidence level on its face:

- **L1 OBSERVATION**: something happened and was recorded.
- **L2 VERIFIED ASYMMETRY**: one controlled dimension varied, both sides were stable, and a behavioral difference was shown.
- **L3 DECLARED CONTRAST**: an L2 difference contradicts a contemporaneously observed declaration.
- **L4 NORMATIVE CONTRAST**: reserved. Present in the schema, unreachable in v1.

Each level meets its own requirements. No level inherits certainty from the one below.

Terminals: `EXCLUDED`, `NOT_OBSERVED`, `NO_ASYMMETRY`, `VERIFIED_ASYMMETRY`, `VERIFIED_DECLARED_CONTRAST`.

The counterexample field depends on two things, not one. It is `ESTABLISHED` only when the terminal is `VERIFIED_DECLARED_CONTRAST` and the known-probe search returns `NOT_FOUND` for that established result. When the same terminal is reached and the search returns `MATCHED`, the counterexample field MUST be `NOT_ESTABLISHED`, and the result MUST record the probe id that explains it together with the probe-set version. In every other terminal the counterexample field is `NOT_ESTABLISHED`. A declared contrast is a verified fact about behavior. A counterexample additionally claims that the existing probe set does not account for that fact, and only the search can establish that.

In v1 the severity field is always `NONE`, and so is the interpretation field.

Required warning, printed verbatim on every contrast report:

> Boundary Contrast v1 is intentionally low-yield. A result of NO_ASYMMETRY across all eligible operations is a valid and expected assessment outcome. Absence of a verified asymmetry must never cause eligibility, baseline, repetition or equivalence requirements to be relaxed.

## 7. Evidence carriage

A contrast result MUST be carried in the same report envelope as an ordinary scan result. It MUST be hashed over the same canonical bytes, signed with the same report key and schema, and committed as a ledger row under the same rules ([boundary-ledger-v1](boundary-ledger-v1.md)), so a third party verifies it with the same published verifier and the same published keys.

A contrast result that is unsigned, unledgered, or hashed under a different scheme MUST NOT be issued as an assessment deliverable. It MAY exist as a local working artifact and MUST then be labelled one.

The report MUST name the contrast method version, the canonicalization version, the probe-set version and the calibration version beside the ledger chain it commits to, so a reader can reconstruct which scheme produced the result.
