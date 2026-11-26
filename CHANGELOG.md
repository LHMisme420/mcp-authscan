# Changelog

## Severity calibration

- **Zero-auth severity now reflects the demonstrated surface, not the absence of auth** (calibration 2026.11.05.1). A zero-auth finding is graded by what the response demonstrated: CRITICAL only when a returned tool's name shows a write, delete, or execute action; HIGH when tools were returned but none names such an action; MEDIUM otherwise, including a response that demonstrated no tools or did not parse. Record-level data in the body is not inspected (a loose content check re-creates over-grading); the finding's `severity_basis` states what decided the grade, and the report footer names the calibration version. Previously any zero-auth response was graded CRITICAL on the absence of auth alone.
- **Severity calibration is versioned separately** (`SEVERITY_CALIBRATION_VERSION`, 2026.11.05.1), not by the probe set: the probes themselves are unchanged, so `PROBE_SET_VERSION` stays 2026.11.05.1. The calibration version is stamped in any report containing a zero-auth finding, so two reports can be compared honestly even though the same probe can now yield a different severity.
- **Behaviour change for `--fail-on critical`**: a zero-auth finding that demonstrates no write/execute surface is now MEDIUM, not CRITICAL, so a CI gate set to `--fail-on critical` that previously failed on such a finding will no longer fail on it. This is intended. Gate on `--fail-on high` (or lower) to keep failing on zero-auth findings regardless of demonstrated surface.

All notable changes to the `mcp-authscan` scanner are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/); this project
aims to follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.1.47] - 2026-11-26

### Added
- Policy-based assurance with CURRENT, STALE, REGRESSED and INCONCLUSIVE verdicts.
- Deployment Acknowledgment Proof using reviewer-issued challenges.
- Signed deployment acknowledgment and authentication-assurance evidence in one report.
- Ed25519 signature form 5, preserving historical signature forms.
- Offline acknowledgment verification and optional reviewer-side live confirmation.
- Real cryptographic regression tests using ephemeral keys.

### Security and evidence limitations
- CURRENT means verified evidence satisfies a declared policy; it does not establish current deployment security.
- REGRESSED identifies changed graded content, not necessarily worsening security.
- A signed challenge observation does not independently prove the network request occurred.
- Deployment acknowledgment establishes evidence of control over a publication location, not necessarily tenant ownership or authorization.
- Scanner-reported timestamps do not independently establish when a scan occurred.

### Validation
- Full regression suite: 1,150 passed, 3 skipped, 114 subtests passed.
- Focused release tests: 106 passed.
- Clean wheel installation verified.



## [1.1.46] - 2026-11-25

**Published PyPI wheel SHA-256:**
`19d405f2962276d8909a6f08fd02fe21349d9c52f224c3ef9e69b634f6ae1f87`

Artifact: `mcp_authscan-1.1.46-py3-none-any.whl`.

### Added

- Controlled MCP initialization authentication assurance, including credentialed-before, anonymous, synthetic-invalid, and credentialed-after observations.
- Deployment challenge functionality and freshness validation.
- Additional authentication-assurance policy-gate handling.

### Verification evidence

Six regression tests passed against the installed published 1.1.46 wheel:

- Three DNS rebinding and destination-safety tests.
- Two negative authentication-challenge tests: nonsense scheme and absent header.
- One valid Bearer challenge control.

The receipt and test scripts are published with the
[official v1.1.46 GitHub Release](https://github.com/LHMisme420/mcp-authscan/releases/tag/v1.1.46).

These tests confirm the specified behaviors in 1.1.46.
DNS-pinned live-scan transport and Bearer-only preflight behavior
were already present in 1.1.44; they are not claimed as newly
introduced in 1.1.46.

### Limitations

- Historical fail-before/pass-after regression evidence remains pending.
- The preflight challenge fixtures use mocked HTTP responses.
- Client security testing remains separate from the primary CLI.
- Receipt hash matching establishes file identity, not independent
  attestation of test execution.

## [1.1.45] - 2026-11-25

**Published PyPI wheel SHA-256:**
`a28c2b3ea2625adae10ead784e17b260d48741d543651ce9fa5b86482b118ace`

Artifact: `mcp_authscan-1.1.45-py3-none-any.whl`.

This version was published on PyPI. No corresponding
GitHub v1.1.45 tag was found during the release audit.

### Added

- **Report hash `verdict-v4`: the graded hash now commits to every probe row.** `report_hash` covers the verdict-v3 totals and findings plus, per probe, `probe_id`, `name`, `status`, `http_status`, `prerequisite_met`, `limitation` and `severity`, sorted, duplicates kept. The scheme name is inside the preimage, so relabeling a v4 report as v3 reads ALTERED. Observed headers, body excerpts, detail, endpoint, timestamps and request ids stay outside it. The CLI scanner writes verdict-v4; the web exporter still writes verdict-v3.
- **Separate evidence hash `probe-evidence-v1`.** `evidence_hash` covers `probe_id`, `name` and `body_sha256` per probe row, kept out of the graded hash because response bodies can carry server-varying bytes. Required with verdict-v4; integrity reads ALTERED if either hash differs, and the result names which (`graded_verdict`, `evidence_verdict`).
- **Verifier output names both hashes and both schemes**: `report_verify` lines end `[scheme: verdict-v4=<hash> evidence probe-evidence-v1=<hash>]`; `verify` prints `HASH_SCHEME`, `EVIDENCE_HASH` and `EVIDENCE_HASH_SCHEME`.
- **Gate: `min-graded-scheme`** policy key, like `min-sig-version`. Unset by default. `REJECT GRADED-SCHEME` below the floor, `POLICY-INVALID` for an unknown scheme.
- verdict-v3 and the 1.1.21-1.1.24 legacy format verify exactly as before.

### Artifact inspection

The published 1.1.45 wheel contains both verdict-v4 graded
hash functionality and the probe-evidence-v1 hashing implementation.

Both are absent from the inspected 1.1.44 wheel and present
in the inspected 1.1.46 wheel.

This establishes implementation presence, not separate
end-to-end behavioral verification of 1.1.45.

## [1.1.44] - 2026-11-24

**Wheel sha256: `d01d148feba8199bdc9aadd2109680744eb8eb791c0dd629f1c77e749d3350c3`** (`mcp_authscan-1.1.44-py3-none-any.whl`). This is the release's anchor, recorded in `release/anchors.tsv`. The wheel is byte-reproducible from commit `2862302` with `SOURCE_DATE_EPOCH=1795550673`, `python -m build --no-isolation --wheel`, build 1.6.1, setuptools 84.2.1 and wheel 0.48.0.

### Changed
- **Live-scan fetches are routed through the DNS-pinned transport.** The preflight, the RFC 8414 discovery fallback, the discovery init POST and the remaining live-scan requests now resolve once, check every resolved record, and connect only to the address that was checked, closing the resolve-then-reconnect rebind window; destination safety is split from the ALLOWED_HOSTS scope check. The probe set and grading are unchanged (`PROBE_SET_VERSION` 2026.11.23.1).

## [1.1.42] - 2026-11-24

**Wheel sha256: `f2477745d7e66b5fa1a262b9dc64ba6078daee655bcdabb1dcae832b7ce0e115`** (`mcp_authscan-1.1.42-py3-none-any.whl`). This is the release's anchor, recorded in `release/anchors.tsv`. The wheel is byte-reproducible from commit `7353ba4` with `SOURCE_DATE_EPOCH=1795533480`, `python -m build --no-isolation --wheel`, build 1.6.1, setuptools 84.2.1 and wheel 0.48.0.

### Security
- **The policy gate now requires the signature to actually cover probe statuses.** A policy that omitted `min-sig-version` let probe statuses be graded from a report whose signature does not cover them (a valid `sig_version` 1 or 2 signature). The gate now requires the verification engine's `probe_statuses` verdict to be VERIFIED, as a backstop after the existing `min-sig-version` check, so a policy can no longer waive it and an unsigned or lower-signature report can never reach a CLEAN verdict (GHSA-jvh3-qvpr-qm8q class).

### Fixed
- **`python -m mcp_authscan.report_verify` no longer reports PASS on an unsigned report.** Its exit came from a local failure-word list that had drifted from the engine's authoritative set, so UNSIGNED, KEY NOT VALID and SIGNATURE NOT CHECKED all returned exit 0. The exit is now taken from the engine's verdict (`verification.passed`) and requires a verified signature; hash-only reproduction remains available via `python -m mcp_authscan.verify`.
- **The policy gate could hash different bytes than the signature covered.** `evaluate` parsed the report from its path and then re-opened the same path to hash it, a time-of-check/time-of-use gap. The report is now read once and the same bytes feed both the signature and the hash checks.
- **Nested package version metadata was out of sync.** `tests/test_cli_packaging` builds the wheel from `mcp_authscan/pyproject.toml`, which lagged behind `__version__` and the root `pyproject.toml`; a wheel built that way shipped mismatched version metadata. All four version sites are now synced.

### Changed
- **`fail-on` has a built-in `HIGH` floor.** A policy may tighten it (reject at a lower severity) but can no longer loosen it above HIGH: a policy that set `fail-on: critical` to tolerate HIGH findings will now reject them.
- **No `fail-on` declared plus a HIGH or CRITICAL finding now reads CONDITIONAL**, naming the top severity, instead of CLEAN. The CLI exit code is unchanged (0).

### Compatibility
- A policy relying on `fail-on: critical` to pass HIGH findings will now reject them. A report with a HIGH or CRITICAL finding and no `fail-on` now yields CONDITIONAL, not CLEAN. `python -m mcp_authscan.report_verify` exits non-zero on unsigned or legacy reports where it previously exited 0.

## [1.1.40] - 2026-11-23

**Wheel sha256: `38c70351c4bd26a67c09c39469dac7e773d3cd85110c82e1015b8440c6a4a4fc`** (`mcp_authscan-1.1.40-py3-none-any.whl`). This is the release's anchor, recorded in `release/anchors.tsv`. The wheel is byte-reproducible from commit `2a73264` with `SOURCE_DATE_EPOCH=1795461035`, `python -m build --no-isolation --wheel`, build 1.6.1, setuptools 84.2.1 and wheel 0.48.0.

### Fixed
- **Exit code agrees with the report's findings.** `decide_exit` ran before the tools-digest step appended a ZERO-AUTH finding, so a server that advertised OAuth but accepted unauthenticated `initialize` and `tools/list` could report a HIGH finding while exiting 5 (`not_observed_present`) instead of 1, with that exit inside the hashed report. The exit is now decided after the last finding. Present in 1.1.39 and earlier.
- **A halted scan never prints PASS.** When discovery stopped (`halted_discovery_incomplete`), one concluded probe was enough for `VERDICT PASS`; it is now `INCONCLUSIVE` unless a MEDIUM-or-higher finding grades it.
- **Machine-readable stdout for non-MCP targets.** The not-an-MCP-target exit (4) printed a text `VERDICT NOT_OBSERVED` line on stdout under `--json`, `--html` and `--sarif`; it now goes to stderr there. `--brief` is unchanged.

### Compatibility
- CI gates may see exit 1 where 1.1.39 returned 5 for the same server: that server has a finding at or above `--fail-on`.


### Changed
- **One verdict engine**: `mcp_authscan.verification` decides every report verdict, offline. The CLI (`python -m mcp_authscan.verify`), the web route (`verify_upload` behind `server/reportVerification.ts`), and the `report_verify.verify` / `report_verify.authenticity` adapters used by the policy gate, `report_verify.main` and verify-mcp all call it. The Node server no longer verifies signatures (`verifyAuthenticity` is removed); it validates the engine's JSON and reshapes it.
- **Fixed stage order**: catalog → format → integrity → authenticity. A catalog or format failure stops evaluation; integrity and authenticity are both reported once the report is readable, and `failed_stage` names the first failure in that order.
- **Catalog attested on every result**, including the site's: the packaged probe-set catalog must match its pinned SHA-256 (`f055f8b9…`), and each result says whether the declared probe set is IN CATALOG, RELEASES ONLY (named by `releases.py`, e.g. `1.1.0`), or a WEB SOURCE DIGEST (the web app's `web-source-sha256:` stamp, which the catalog does not describe). Any other probe set is UNKNOWN PROBE SET, a format failure.
- **Pinned key history** (`mcp_authscan/key_history.json`, SHA-256 pinned in code): signatures are checked against it by default, on the CLI too. Each key is anchored to the commit that published or withdrew it. `ed25519-1ed8ee728c587846` (published 553af4b, withdrawn eef3a85, reason not recorded) is withdrawn; `9b79936f…` is active. A withdrawn key rejects every signature (`KEY NOT VALID`): reports carry no signed signing time, so no date in a report is used to select a key. `/keys.json` must equal the history's active keys (tested).
- **Probe statuses**: every result states whether they are verified. Only a verified `sig_version` 3 or 4 signature covers them; a valid sig_version 1 or 2 signature now says probe statuses NOT VERIFIED instead of reading as authentic. A flipped probe status under a 3/4 signature is graded hash INTACT, authenticity SIGNATURE INVALID, with the reason naming the components outside report_hash.
- `python -m mcp_authscan.verify`: `--json` prints the engine result; `--require-signature`; `--keys` accepts a key-history-v1 file or a published keys list (and still requires a signature). Authenticity failures print `AUTHENTICITY` (was `SIGNATURE_INVALID`).

## [1.1.39] - 2026-11-22

**Wheel sha256: `ecbf55d5fe94064eaf3980483f8508c8b815ab560af0b5422119405e72833307`** (`mcp_authscan-1.1.39-py3-none-any.whl`). This is the release's anchor, recorded in `release/anchors.tsv`. The wheel is byte-reproducible from commit `def16f9` with `SOURCE_DATE_EPOCH=1795353158`, `python -m build --no-isolation --wheel`, build 1.6.1, setuptools 84.2.1 and wheel 0.48.0.

### Added
- **`require-manifest-pin`** policy key, `true` in the default policy. A report whose signed provenance does not match a pinned release manifest is `REJECT MANIFEST-PIN`, with the pin status and `tool_version` as the reason. Provenance is inside the `sig_version` 3 and 4 signatures, so the pin status cannot be edited unnoticed.
- A release cannot carry its own pin (pins are added after each release), so a report from the gate's own, not-yet-pinned version is compared with the gate's installed source (`build_provenance()`): a match is `MANIFEST MATCHES INSTALLED`, a mismatch is `REJECT MANIFEST-PIN: MANIFEST NOT INSTALLED`, and an install the gate cannot read fails closed.

### Compatibility
- Under the default policy, a report must come from a pinned release (1.1.33 to 1.1.38 are pinned) or from the gate's own installed version. Reports below `sig_version` 3 carry no provenance and were already rejected by `min-sig-version: 3`.
- A gate run from a source checkout without an installed distribution cannot read its own manifest, so it rejects same-version reports.

## [1.1.38] - 2026-11-22

**Wheel sha256: `31f13824bc3c5f9b8cf60791ddafaf9555b53ba5d3462d67f910d7c652be28a1`** (`mcp_authscan-1.1.38-py3-none-any.whl`). This is the release's anchor, recorded in `release/anchors.tsv`. The wheel is byte-reproducible from commit `59167e7` with `SOURCE_DATE_EPOCH=1795350712`, `python -m build --no-isolation --wheel`, build 1.6.1, setuptools 84.2.1 and wheel 0.48.0.

### Added
- **`sig_version` 4** adds `content_observed` to the signed bytes, including a new `operations` list of the MCP operations that succeeded: `initialize` when the session was established, each `*/list` when its result list was parsed. Signed scans that observed content are now `sig_version` 4.
- `report_verify` adds an `[operations: signed | NOT VERIFIED …]` label, and labels probes `signed` for `sig_version` 3 and 4 (previously 3 only).

### Changed
- With `scope.operations` declared in the policy, `CLEAN` requires a `sig_version` 4 report whose signed operations include every scope operation. Any other report gets at most `CONDITIONAL SCOPE`, and the detail names the missing operations or says `sig_version` 4 is required. `CLEAN` is reachable again under the default policy for scans that establish an MCP session.
- A `sig_version` 3 signature cannot cover `operations`: operations added to a v3 report make its signature invalid.

### Compatibility
- **Gates and verifiers older than 1.1.38 cannot verify `sig_version` 4 reports.** They treat version 4 as unknown, so an older gate returns `REJECT SIGNATURE-INVALID` (fail-safe). Upgrade every verifier, including the server behind the site's report verification, before relying on reports signed by 1.1.38.
- Reports with `sig_version` 1 to 3 verify exactly as before.

## [1.1.37] - 2026-11-22

**Wheel sha256: `c1dac26363727ed0fea5068c5ab9aaab7701124bf5e70a07ede4b6f0236a9244`** (`mcp_authscan-1.1.37-py3-none-any.whl`). This is the release's anchor, recorded in `release/anchors.tsv`. The wheel is byte-reproducible from commit `7f01baf` with `SOURCE_DATE_EPOCH=1795338905`, `python -m build --no-isolation --wheel`, build 1.6.1, setuptools 84.2.1 and wheel 0.48.0.

### Fixed
- 1.1.36 shipped without its entry in `mcp_authscan/releases.py`, so `python -m mcp_authscan.releases` reported the installed version as not matching probe set `2026.11.21.1`. The table now lists 1.1.35, 1.1.36 and 1.1.37. Informational only: the gate, the verifier and the scanner were not affected.
- `mcp_authscan/pyproject.toml` still said `1.1.35` in 1.1.36 while the package said 1.1.36, so a wheel built from it carried the wrong version. It is bumped with the root `pyproject.toml` again; `docs/RELEASING.md` names both files (a correction made on 2026-11-22 had wrongly removed the inner one).
- Manifest pins for 1.1.35 (`a17048a221cebd7601f1713a1bc32728495b534eba851a1487ecef5efffc726f`) and 1.1.36 (`522f31b61ab06f6e7af482bb83c53014db021573f8d04baa7d5c562712eafd0e`), computed with `build_provenance()` from the published wheels. The same method reproduces the existing 1.1.34 pin.
- README states the current source version.

### Process
- `docs/RELEASING.md`: run the full suite on the release commit and do not tag unless it exits 0. 1.1.36 was tagged after a build and a guard check but without the suite, which is how the version-parity failures above shipped.

## [1.1.36] - 2026-11-22

**Wheel sha256: `c3d08c1d77b11d5e2955817dd15f666dc73a2e0a06e4d3247c469b4268eb9739`** (`mcp_authscan-1.1.36-py3-none-any.whl`). This is the release's anchor, recorded in `release/anchors.tsv`. The wheel is byte-reproducible from commit `b4cc856` with `SOURCE_DATE_EPOCH=1795338189`, `python -m build --no-isolation --wheel`, build 1.6.1, setuptools 84.2.1 and wheel 0.48.0.

### Breaking
- A policy that declares `scope.operations` now grants at most `CONDITIONAL SCOPE`. `CLEAN` requires the declared scope to be proven by signed report content, and no signed field records the observed operations yet: `content_observed` is outside `report_hash` and the signature, so an edit to it still verifies. The default policy declares a scope, so `CLEAN` is not reachable under it. Signing the observed operations is planned.

### Changed
- Before 1.1.36, a report whose required probes all read `PASS` was `CLEAN` whether or not the declared scope was ever observed. This is a hardening of what `CLEAN` claims, not a fix for a forgery: the earlier gate never read the scope at all.
- README documents the policy gate, its verdicts, the `sig_version` 3 requirement and the scope rule.
- The public-push guard accepts reviewed test-fixture values by exact sha256 (`scripts/public-push-allowlist.txt`); provider-shaped tokens are never exempt. A stray `keycloak` gitlink was removed.

### Yanked
- 1.1.27 to 1.1.34 are yanked on PyPI: 1.1.28 onward are affected by GHSA-jvh3-qvpr-qm8q, and none of 1.1.27 to 1.1.34 was published through the anchored workflow. Exact-version installs still work.

## [1.1.35] - 2026-11-22

**Wheel sha256: `649441628d9b5c2a7541278b1d1524294183de00a9ee55f84050f83510f38e6d`** (`mcp_authscan-1.1.35-py3-none-any.whl`). This is the release's anchor, recorded in `release/anchors.tsv`. The wheel is byte-reproducible from commit `cfa6645` with `SOURCE_DATE_EPOCH=1795332969`, `python -m build --no-isolation --wheel`, build 1.6.1, setuptools 84.2.1 and wheel 0.48.0. To compare: `pip download --no-deps mcp-authscan==1.1.35 && sha256sum mcp_authscan-1.1.35-py3-none-any.whl`.

### Security
- **Key-free verdict forgery in the policy gate ([GHSA-jvh3-qvpr-qm8q](https://github.com/LHMisme420/mcp-authscan/security/advisories/GHSA-jvh3-qvpr-qm8q)), affecting 1.1.28 to 1.1.34.** Probe statuses in reports below `sig_version` 3 are covered by neither `report_hash` nor the signature, and the gate accepted any `sig_version`. Editing one probe status in a genuine signed report turned `REJECT` into `ACCEPT` (1.1.28 to 1.1.30) or `CLEAN` (1.1.32 to 1.1.34) while integrity still read `MATCH`. The default policy now sets `min-sig-version: 3`, and a report below it is `REJECT`.
- `report_verify` labels every line `[probes: signed]` only for a `sig_version` 3 report whose signature was checked with `--keys`, and `[probes: NOT VERIFIED ...]` otherwise. `report_hash` itself is unchanged; covering probes in the hash requires a new hash scheme.

### Breaking
- Genuine `sig_version` 1 and 2 reports are now rejected by the default policy. Rescan with 1.1.33 or later.

### Fixed
- Policy `fail-on` (default `high`): findings at or above it, or with an unknown severity, are `REJECT`. Previously severity was never graded.
- `forbidden-findings` matches exact rule IDs or separator-delimited families; `CORS-1` no longer matches `CORS-10`.
- `acceptable-verdicts` in the default policy is `["PASS"]`, matching what the gate enforces (the gate does not read this key).
- `report_verify` no longer crashes on a missing or corrupt report; it prints `NOT REPRODUCIBLE`. Output is one line per report again.
- `pytest.ini` no longer replaces pytest's default `norecursedirs`; a plain `pytest` collects and runs the full suite (758 passed, 3 skipped at `cfa6645`).
- Tests for modules archived in `e1755f1` are disabled with a reason, not deleted.

### Release integrity
- 1.1.27 to 1.1.34 were published to PyPI without an entry in `release/anchors.tsv`. The `release` workflow refused those tags and the wheels were uploaded outside it, so their hashes are not anchored. 1.1.35 is published through the anchored workflow. For 1.1.34, the published `policy_check.py`, `policy-default.json` and `report_verify.py` were confirmed byte-identical to tag `v1.1.34`.

## [1.1.34] - 2026-11-21 [YANKED]

Yanked on 2026-11-22. Published to PyPI outside the anchored release workflow, so `release/anchors.tsv` has no entry and no reproducible wheel hash is recorded. Entries below are reconstructed from the commits between tags; commit hashes are given so each line can be checked. Affected by [GHSA-jvh3-qvpr-qm8q](https://github.com/LHMisme420/mcp-authscan/security/advisories/GHSA-jvh3-qvpr-qm8q); upgrade to 1.1.35 or later.

- Policy gate: required probes must be `PASS`, sufficiency is checked per required probe by name, and the module CLI guard is fixed (`654e85b`, `42f9819`).
- Manifest pin for 1.1.33, `ebac9035…` (`42f9819`).
- Resolved CodeQL clear-text alerts #207, #209, #210, #211 and #169 (`f45cf3b`).
- Dependencies: authlib `>=1.9.8,<2.0.0`, coverage 7.17.3, ruff 0.17.5 (`eb8cd25`, `6042907`, `9bf12ab`).

## [1.1.33] - 2026-11-20 [YANKED]

Yanked on 2026-11-22. Published to PyPI outside the anchored release workflow, so `release/anchors.tsv` has no entry and no reproducible wheel hash is recorded. Entries below are reconstructed from the commits between tags; commit hashes are given so each line can be checked. Affected by [GHSA-jvh3-qvpr-qm8q](https://github.com/LHMisme420/mcp-authscan/security/advisories/GHSA-jvh3-qvpr-qm8q); upgrade to 1.1.35 or later.

- **`sig_version` 3**: the signature covers the probes and a provenance block (`tool_version`, `tool_manifest`) in addition to the evidence binding and the graded report. Provenance names the package version, and reports with evidence sign this form (`6384de2`, `db16fbb`). This is the first release whose signatures cover probe statuses.
- README, release table and the package `pyproject.toml` moved to 1.1.33 (`fc2b8b2`).
- verify-mcp 0.1.4 unwraps a wrapped `keys.json` (`904442b`).

## [1.1.32] - 2026-11-20 [YANKED]

Yanked on 2026-11-22. Published to PyPI outside the anchored release workflow, so `release/anchors.tsv` has no entry and no reproducible wheel hash is recorded. Entries below are reconstructed from the commits between tags; commit hashes are given so each line can be checked. Affected by [GHSA-jvh3-qvpr-qm8q](https://github.com/LHMisme420/mcp-authscan/security/advisories/GHSA-jvh3-qvpr-qm8q); upgrade to 1.1.35 or later.

- The policy gate CLI exits non-zero on `REJECT` (`24188b8`).

## [1.1.31] - 2026-11-20 [YANKED]

Yanked on 2026-11-22. Published to PyPI outside the anchored release workflow, so `release/anchors.tsv` has no entry and no reproducible wheel hash is recorded. Entries below are reconstructed from the commits between tags; commit hashes are given so each line can be checked. Affected by [GHSA-jvh3-qvpr-qm8q](https://github.com/LHMisme420/mcp-authscan/security/advisories/GHSA-jvh3-qvpr-qm8q); upgrade to 1.1.35 or later. 1.1.31 was also yanked earlier, separately.

- Three-outcome policy gate (`REJECT`, `CONDITIONAL`, `CLEAN`), replacing `REJECT`/`ACCEPT`; version parity; full suite green (`d9f3cdc`).

## [1.1.30] - 2026-11-20 [YANKED]

Yanked on 2026-11-22. Published to PyPI outside the anchored release workflow, so `release/anchors.tsv` has no entry and no reproducible wheel hash is recorded. Entries below are reconstructed from the commits between tags; commit hashes are given so each line can be checked. Affected by [GHSA-jvh3-qvpr-qm8q](https://github.com/LHMisme420/mcp-authscan/security/advisories/GHSA-jvh3-qvpr-qm8q); upgrade to 1.1.35 or later.

- Commit `90329ec`, "signing required". The commit message does not say more; see the commit for what it changed.

## [1.1.29] - 2026-11-20 [YANKED]

Yanked on 2026-11-22. Published to PyPI outside the anchored release workflow, so `release/anchors.tsv` has no entry and no reproducible wheel hash is recorded. Entries below are reconstructed from the commits between tags; commit hashes are given so each line can be checked. Affected by [GHSA-jvh3-qvpr-qm8q](https://github.com/LHMisme420/mcp-authscan/security/advisories/GHSA-jvh3-qvpr-qm8q); upgrade to 1.1.35 or later.

- Commit `6220c71`, "defaults for one argument". The commit message does not say more; see the commit for what it changed.

## [1.1.28] - 2026-11-20 [YANKED]

Yanked on 2026-11-22. Published to PyPI outside the anchored release workflow, so `release/anchors.tsv` has no entry and no reproducible wheel hash is recorded. Entries below are reconstructed from the commits between tags; commit hashes are given so each line can be checked. Affected by [GHSA-jvh3-qvpr-qm8q](https://github.com/LHMisme420/mcp-authscan/security/advisories/GHSA-jvh3-qvpr-qm8q); upgrade to 1.1.35 or later.

- First release with the policy gate (`mcp_authscan.policy_check`) and a default policy (`c72e702`).

## [1.1.27] - 2026-11-20 [YANKED]

Yanked on 2026-11-22. Published to PyPI outside the anchored release workflow, so `release/anchors.tsv` has no entry and no reproducible wheel hash is recorded. Entries below are reconstructed from the commits between tags; commit hashes are given so each line can be checked. Not affected by GHSA-jvh3-qvpr-qm8q: it has no policy gate.

- Source for the verify MCP server; the verify tool is confined to the evidence directory and checks the tool name; verify packaging, module name and guard (`b59b455`, `d224f6d`, `2403222`, `4bb24cc`, `cb2f0e6`, `7aeae05`/`1fb9422`/`e4f00c1`).
- OAuth probes restored (`c592d52`).
- Sample report updated to the 1.1.26 verified run (`ffb3b00`).
- Commit `58a346f` is titled "sig_version 3: signature covers probes", but the tagged 1.1.27 code signs only `sig_version` 1 and 2. No release signed probes before 1.1.33.

## [1.1.26] - 2026-11-19

**Wheel sha256: `f1ea12271e270125564ba1825587da444f893898e0ac0b8cd3c358e6d9667037`** (`mcp_authscan-1.1.26-py3-none-any.whl`). This is the release's anchor, recorded in `release/anchors.tsv`. The wheel is byte-reproducible from commit `b1dccef` with `SOURCE_DATE_EPOCH=1795093151`, `python -m build --no-isolation --wheel`, build 1.6.1, setuptools 84.2.1 and wheel 0.48.0. To compare: `pip download --no-deps mcp-authscan==1.1.26 && sha256sum mcp_authscan-1.1.26-py3-none-any.whl`. No sdist is published for this release: the sdist is not byte-reproducible, so it cannot be an anchor.

1.1.26 ships the committed source of the audited 1.1.25 build (evidence package, signed reports, `report_verify`, severity calibration `2026.11.07.1`, content probe `2026.11.03.1`) plus three probe-set fixes, so its probe set is `2026.11.19.3`, not `2026.11.16.1`: **2026.11.19.1** ends a false clean (token-cors and password-grant use the operator's client; password-grant passes only on `unsupported_grant_type`), **2026.11.19.2** stops a single raising probe from ending the scan with exit 4 and no report, **2026.11.19.3** makes token-cors EXCLUDED with a named reason when the target offers no client_credentials grant. See "Probe set stamps". The Python suite (711 tests, 114 subtests) and the site tests pass at the anchor commit, the first time in this cycle the whole suite has been green; the four exit-code and version tests need the installed `mcp-authscan` command on PATH. New tests cover token, secret and signing-key leakage through `--sign` with the ledger and through `--acquire-token`. It is the first release in this repository whose published wheel was built from a commit and checked against a recorded hash before upload: the release workflow refuses to upload, or to create a GitHub release, unless the wheel it builds and the wheel on PyPI both match the anchor for the tag.

## [1.1.25] - 2026-11-19 [YANKED]

**Yanked. The wheel on PyPI is not this entry's build and does not correspond to any commit.** What follows below this notice describes the audited build anchored at `b0b4f2d0…`, which was never uploaded.

The PyPI wheel (`d8cdff8dfb656feec73ea9761cffb0c3a76191aa62158d191bbb036bfc37b532`, uploaded 2026-11-19 11:08 UTC) was built by hand from a local working tree, without `SOURCE_DATE_EPOCH`, at tag `v1.1.25` = `88218d1`. That commit is on no branch and does not descend from the audited history. Against the audited build the wheel:

- has no `mcp_authscan.evidence` package and no `evidence_emit`, so none of the signing, ledger or surface-state features listed below are installed;
- ships different `report_signing`, `report_verify` and ten other modules, plus `boundary`, `boundary_live` and `originprobe`, which the audited build does not have;
- ships a `content_probe.py` that no commit contains: `CONTENT_PROBE_VERSION` moved to `2026.11.18.1` while the injection-directive pattern lost `you must`, `always (call|use|read|send)` and `before (using|calling) this tool`. The stamp moved; the probe got weaker; nothing was committed or reviewed;
- still reports probe set `2026.11.16.1`, so a report stamped `2026.11.16.1` from 1.1.25 does not name reproducible code.

This is the failure mcp-authscan exists to catch, a published claim that does not match what shipped, and the project's own release produced it. The published hash `b0b4f2d0…` described a wheel that was audited but never uploaded; the wheel that was uploaded was never audited. The tag `v1.1.25` is left at `88218d1` as the record of the yanked build. Use 1.1.26.

**Wheel sha256: `b0b4f2d0456b0aaee95913b5c4f53c056af406477f960706e975df2b81183be5`** (`mcp_authscan-1.1.25-py3-none-any.whl`). This is the release's anchor. The wheel is byte-reproducible from commit `c60b174` with `SOURCE_DATE_EPOCH=1795083301`, `python -m build --no-isolation`, build 1.6.1, setuptools 84.2.1 and wheel 0.48.0. To compare: `pip download --no-deps mcp-authscan==1.1.25 && sha256sum mcp_authscan-1.1.25-py3-none-any.whl`. The sdist is not byte-reproducible (setuptools' tarball varies per build), so it is not an anchor.

Ships probe set `2026.11.16.1`, which no earlier release carried. Its recorded change (tests/probe_set_fingerprints.json): merged alternate-transport target probes and updated OAuth grading while retaining schema-3 report serialization. `python -m mcp_authscan.releases` maps any report's `probe_set_version` to the releases that ship it.

### Compatibility
- Reports from 1.1.21 to 1.1.24 (hash_scheme `verdict-v3` with no `schema_version`) still verify. They are checked with that format's own algorithm, reproduced verbatim from the 1.1.24 verifier, and are never reinterpreted as schema 3. They read **`LEGACY MATCH` / `LEGACY MISMATCH`, never plain `MATCH`**, with `UNSIGNED (pre-1.1.25 algorithm, releases 1.1.21-1.1.24)` on the line where a signed schema-3 report reads `SIGNED BY`. `verify_upload` keeps `INTACT`/`ALTERED`, and its reason says `LEGACY … unsigned`. This format was never signed, so it never reads as signed. Real 1.1.24 reports are kept as test fixtures (tests/fixtures/compat).
- Signed schema-3 reports made before `sig_version` existed verify unchanged. A signed fixture from main 1a7d08c is kept.

### Added
- `python -m mcp_authscan.report_verify [--keys KEYS.json] REPORT.json` prints integrity and authenticity per report. Without `--keys`, a signed report reads `SIGNATURE NOT CHECKED`, never `SIGNED BY`.
- `python -m mcp_authscan.releases [REPORT.json | --stamp STAMP]`: probe set to release mapping, read from the published wheels.
- Evidence protocol (schemas/EVIDENCE.md): security-state-v1 and observation-v1 written next to each completed live scan; `evidence` binding (v3) signed into `--sign` reports; boundary-ledger-v1 rows recorded for signed runs; boundary-delta-v1 with `AUTHORIZATION_REGRESSION`.
- `--sign` is fail-closed: the key comes from `$MCP_AUTHSCAN_SIGNING_KEY`, else `~/.config/mcp-authscan/report-signing.pem`. A missing key exits 2 before any request, and a failure to sign exits 4 with no report.

### Changed (unreleased on main since 1.1.24, first released here)
- Single-scan web and CLI exports share the exact `verdict-v3` schema-3 canonical hash. Covered fields include probe version, coverage, severity counts and complete finding descriptions/remediation; timestamps and session/header metadata are excluded. Separate web single-scan PDF/JSON exports preserve the existing organization summary. Earlier hashes are not silently reinterpreted.
- Probe set stamp `2026.11.15.1` records the report-contract change tracked by the source fingerprint guard; no probe execution or grading behavior changed.

### Added
- Rate limiting is now probed and reported: a 429 inside the authorised budget passes, no 429 inside it is not observed, and a scan with no budget is excluded with the reason named.

### Fixed
- The probe-set stamp guard now covers the target probes as well as the OAuth set, so a CORS or rate-limit change moves the stamp test instead of slipping past it.

## [1.1.20] - 2026-11-02

### Fixed
- A live scan with no OAuth probe records no longer reports drift or content findings as failed probes. Source scans still report their findings count.

### Docs
- The OWASP coverage page no longer says the scanner cannot read tool descriptions, prompts or resources.

## [1.1.11] - 2026-11-02

### Added
- Text and HTML reports now say whether the tools/list digest was captured, and name the reason when it was not.
- The digest stays outside the report hash; it moves no verdict and no coverage count.

## [1.1.12] - 2026-11-02

### Fixed
- The User-Agent reports the installed package version instead of a hardcoded 2.0.0.

## [1.1.13] - 2026-11-02

### Changed
- The README states that ten probes run by default and that cross-tenant isolation needs MCPAUTHSCAN_CROSS_TENANT=1.

## [1.1.17] - 2026-11-02

- README: review offer moved below Versions.
## [1.1.18] - 2026-11-02

### Changed
- A halted scan now prints its report and exits 5 instead of 3 with no report.
- discovery_status is recorded in the payload and the saved report.
- Exit contract stamp is now 2026.11.02.4.

## [1.1.19] - 2026-11-02

### Fixed
- A refused tools/list capture no longer exits 6 after the scan has run, and it now uses the same allowed host set as the scan.
- The printed hash statement now names the tools_digest block among its exclusions.

## [1.1.16] - 2026-11-02

### Added
- Surface drift: a scan captures a digest of the server's tools, prompts, resources and its own instructions, then reports each item that differs from a recorded baseline as added, removed or changed.
- --surface-baseline FILE writes a baseline when the file does not exist, and compares against it when it does.
- Drift findings use rule MCPD-1 at medium severity, carrying the baseline path, the item key and the before and after text as evidence. Drift never counts as a pass and stays outside the ten OWASP categories.
- The text report states whether the surface was pinned, unchanged, changed or not compared, with the reason when it was not compared.

### Fixed
- Drift findings were written to a list the report does not read, so they were missing from the text report and the JSON payload while still appearing in the surface record.
- A scan that stopped at OAuth discovery said it was reporting content findings and then printed none. It now lists them, with evidence, before it stops.
- Installed metadata and the README still recorded 1.1.14 while the source was 1.1.15.

## Historical probe-set notes (previously unversioned)

### Probe set stamps

- 2026.11.21.1: `oauth_probes_v2.ALLOW_PRIVATE_TARGETS` has a module-level default (False, the same as `monolith.ALLOW_PRIVATE_TARGETS`). Before it, a probe called without `monolith.main()` first (a library caller, or a test run outside pytest's conftest) raised `NameError`, which the probe's broad except recorded as NOT_OBSERVED with `Request failed: name 'ALLOW_PRIVATE_TARGETS' is not defined`. CLI scans were not affected: `main()` sets the flag before any probe runs, so no CLI report is regraded. Also removed with no fingerprint change: a dead first definition of `probe_resource_authorization_servers` (shadowed by the second) and a duplicate `_NoRedirect`. tests/test_probe_module_defaults.py.
- 2026.11.19.3: token-cors [4] is EXCLUDED, prerequisite "a client_credentials grant the token endpoint accepts", limitation "No client-credentials grant (unsupported_grant_type)", when the token endpoint answers `unsupported_grant_type`: a positive statement that the target offers no such grant, the same bucket and reason as token-audience [11]. Previously NOT_OBSERVED, so a server built correctly without client_credentials scanned as incomplete (exit 5, coverage below 1.0). Other 4xx errors stay NOT_OBSERVED. tests/test_credential_grant_client.py, tests/test_verdict_contract.py (plain mode, 9004).
- 2026.11.19.2: **one probe can no longer end a scan.** Every probe runs through `_common.isolated`: a probe that raises is NOT_OBSERVED for that probe alone, with the exception named (redacted) in its limitation and on stderr, and the scan writes its report. Scope refusals still exit 6. From 367ea5f (stamp 2026.11.16.1) probe 15 built a PASS from a 401 with no body and no headers, record() refused it, and the scan ended `Internal scan error`, exit 4, no report. Probe 15 now records the headers its verdict rests on. tests/probe_set_fingerprint.py reads the probe order through `isolated(...)`; the order component is unchanged from 2026.11.19.1. tests/test_probe_isolation.py.
- 2026.11.19.1: **fixes a false clean.** token-cors [4] and password-grant [6] now send the operator's client when MCPAUTHSCAN_CLIENT_ID is set, and the registered client only when it is not; the report records which (`client_registration[].credential_grant_client_source`). password-grant grades PASS only on `unsupported_grant_type`; any other 4xx error is NOT_OBSERVED. From a18ad02 (stamp 2026.11.11.1) through 2026.11.16.1 the freshly registered client was sent instead, and a server issuing client_credentials and password-grant tokens to its own client, with credentialed CORS on the token endpoint, graded VERDICT PASS with zero findings. Reports from those probe sets that show token-cors NOT_OBSERVED or password-grant PASS with `Error: invalid_request` (or any error other than unsupported_grant_type) did not evaluate those properties. tests/test_credential_grant_client.py.
- 2026.11.10.2: preflight now records serverInfo.name, serverInfo.version and the negotiated protocolVersion from the unauthenticated initialize it already performs. NOT_OBSERVED when the response carries no result. No new request, no new host contacted.

- 2026.11.10.1: recorded a probe set change that landed between 2026-11-07 and 2026-11-10 without a stamp bump; every component recomputed from the tree at the time of recording, fingerprint e2c0850f. No PASS or FAIL verdict changed, and no past report is regraded.
- 2026.11.02.1: the User-Agent reports the installed package version; no verdict or coverage change.
- 2026.11.04.2: password-grant and client-auth report NOT_OBSERVED rather than EXCLUDED when the response carries no usable token; no PASS or FAIL verdict changed.
- 2026.11.06.1: coverage changed on a zero-auth target. The OAuth probes are now recorded as EXCLUDED with the OAuth discovery prerequisite named, instead of being dropped from the declared set, so in_scope is the full probe set and coverage stops reading 1.00 on a run that tested one endpoint. ZERO-AUTH maps to MCP07 instead of unmapped, and a category with no mapped rule reports no-probe rather than covered. The zero-auth severity basis no longer says no tools were demonstrated when the response simply carried no tool list to grade. No PASS or FAIL verdict changed.
- 2026.11.05.1: verdicts changed. jwks-keys reports NOT_OBSERVED rather than FAIL when the JWKS endpoint returns a non-2xx status, an empty body or no keys array, and records the real HTTP status instead of 200; jwks-keys FAILs when any key is symmetric (kty=oct), including mixed sets that previously passed. token-cors reports NOT_OBSERVED rather than EXCLUDED on a 4xx without an OAuth error body, and NOT_OBSERVED rather than PASS on a 2xx with an empty body; with --acquire-token it FAILs on a reflected hostile Origin (previously NOT_OBSERVED) and PASSes only when an access token was obtained. token-cache-control judges only a token-endpoint response (a 2xx carrying access_token, or a 2xx or 4xx with an OAuth error body; RFC 6749 5.1 requires no-store on token responses) and redacts the recorded body: a 5xx, a failed request or an out-of-scope URL reports NOT_OBSERVED rather than EXCLUDED, and a 2xx, an empty body or a non-OAuth response reports NOT_OBSERVED rather than PASS or FAIL.
`PROBE_SET_VERSION` (reported as `probe_set_version`) names the probe set that produced a report.
From 2026.10.30.1 a stamp is `YYYY.MM.DD.N`: the America/New_York date the probe set changed and a
per-day counter starting at 1, so two probe sets changed on one day get distinct stamps.
`tests/test_probe_set_stamp.py` fails when the probe set changes and the stamp does not
(fingerprints in `tests/probe_set_fingerprints.json`, computed by `tests/probe_set_fingerprint.py`).

Earlier stamps used the date alone. Five of them were mis-dated: each took the calendar day after
the previous stamp instead of the day its probe set changed. Commit times are America/New_York.

| Stamp | Commit | Committed | Change |
|---|---|---|---|
| 1.1.0 | tags v1.1.3 to v1.1.5 | 2026-10-25 to 2026-10-26 | semver-style stamp, replaced by dates |
| 2026.10.28 | d4372c9 (tags v1.1.6 to v1.1.8) | 2026-10-28 08:27 | correctly dated: resource probes hardened to four-branch verdicts |
| 2026.10.29 | 39bd45e | 2026-10-29 12:17 | correctly dated: contract rules for pkce-s256 and redirect-uri-exact |
| 2026.10.30 | 4a75f7c | 2026-10-29 13:26 | **mis-dated**: probes 7-8 take a dynamically registered client first, environment client as fallback, tokens revoked before the report |
| 2026.10.31 | a68c144 | 2026-10-29 15:40 | **mis-dated**: password-grant PASS on any named 4xx OAuth error except invalid_grant; token-cors non-verdict wording |
| 2026.11.01 | 07d77a0 | 2026-10-29 17:31 | **mis-dated**: dynamic registration asks for grant_types authorization_code and refresh_token |
| 2026.11.02 | a4612ef | 2026-10-29 18:19 | **mis-dated**: revocation always sends client_secret (empty for a public client) and a non-2xx reads "revocation not confirmed"; client removal only by RFC 7592 DELETE |
| 2026.11.02.2 | commit adding this row | 2026-11-02 | no probe added or altered; the egress guard honours the allowed_hosts it is given and refuses a URL with no hostname, so what every probe may reach changed |
| 2026.11.02.3 | commit adding this row | 2026-11-02 | exit contract: no probe attempted but at least one content finding now produces a report with coverage null and exits by the findings, was exit 3 with no report |
| 2026.11.03 | f1d4fb3 | 2026-10-30 02:37 | **mis-dated**, never on main or in a release: client_secret_basic (HTTP Basic, RFC 6749 2.3.1) at the token exchange, environment-client token-cors and password-grant, and revocation |
| 2026.10.30.1 | this change | 2026-10-30 | the 2026.11.03 probe set re-stamped under the new scheme; no probe changed |
| 2026.10.30.2 | commit adding this row | 2026-10-30 | [DEBUG] stderr lines (discovery endpoints, token-cache-control) only with --verbose; no verdict changed |
| 2026.10.30.3 | commit adding this row | 2026-10-30 | Elapsed Time excludes the attended --acquire-token wait on stdin; no verdict changed |
| 2026.10.31.2 | commit adding this row | 2026-10-31 | monolith ALLOW_PRIVATE_TARGETS defaults to false, so the egress guard fails closed for callers other than main |
| 2026.10.31.1 | commit adding this row | 2026-10-31 | the shared 5xx rule is applied once to every oauth probe record, so a 5xx on any probe reads NOT_OBSERVED |
| 2026.10.30.4 | commit adding this row | 2026-10-30 | _apply_client_secret: one helper places the client secret for the token exchange, default token-cors and password-grant; requests and verdicts unchanged |
| 2026.10.30.5 | f707170 | 2026-10-30 | **withdrawn**: issued by f707170 for a report-arithmetic change, same probe set as .4; any report carrying .5 ran the .4 probe set. The change it was issued for: Coverage is PASS+FAIL over testable probes (in_scope - EXCLUDED), was over in_scope; JSON and text share counts.coverage(); zero testable exits 5 |
| 2026.10.31.3 | 38ed39d | 2026-10-31 05:50 | probe 10 cross-tenant added and parked behind MCPAUTHSCAN_CROSS_TENANT, declared set stays nine; token-cors on a plain scan EXCLUDED naming the missing client credential |
| 2026.10.31.4 | b175070 | 2026-10-31 06:01 | jwks-keys reports NOT_OBSERVED when the JWKS endpoint cannot be fetched, was EXCLUDED; a failed fetch is an attempt not observed, not a missing prerequisite |
| 2026.11.01.7 | a9b7faa | 2026-11-01 | probe 11 revokes the audience token after the presentation, so PASS means a foreign-audience token was refused rather than a revoked one; no probe added, verdict meaning changed |
| 2026.11.01.5 | bdf49d2 | 2026-11-01 | probe 6 password-grant takes the client the run resolved, falling back to the environment; no verdict changed |
| 2026.11.01.6 | dc2ebff | 2026-11-01 | probe 11 token-audience asks with the resolved client and records EXCLUDED, prerequisite named, when the token endpoint refuses the grant |

The fingerprint no longer hashes report accounting (the counts and coverage assignments in
`monolith.main`); every recorded fingerprint was recomputed without it, and the current stamp is
2026.10.30.4 again. `tests/test_probe_set_fingerprint_scope.py` checks that report-accounting edits
leave the fingerprint alone and probe logic or severity edits move it.

No release tag (v1.1.4 to v1.1.8) carries a future-dated stamp. Reports already produced keep
their stamp: read 2026.10.30, 2026.10.31, 2026.11.01 and 2026.11.02 as four successive probe sets
of 2026-10-29. The old date-only 2026.10.30 and the new 2026.10.30.1 are different probe sets.

### Terminology
- Probes 7-8 (pkce-s256, redirect-uri-exact) have **unmet prerequisites** (require 
  registered client to test), so they return EXCLUDED status. This is distinct from
  "out-of-scope" — both terms refer to tests that cannot run, but prerequisites define
  the verdict semantics (EXCLUDED, not NOT_OBSERVED) per the 2026-10-23 amendment.

### Added
- Hosted app: a per-scan **authorization attestation**. The `/api/scan(s/mcp)`
  endpoint now requires `authorized: true` and records the attestation to a
  `scan_authorizations` audit table; the dashboard adds a required "I'm
  authorized to test this target" checkbox. Prevents the hosted scanner from
  being used against systems the user doesn't own.
- Opt-in RCE-precondition checks (`--checks all`): unauthenticated MCP config
  endpoint (CRITICAL) and missing Host/Origin validation / DNS-rebinding (HIGH).
- Fleet scanning: multiple target URLs or `--targets FILE`, scanned concurrently
  with an aggregated report.
- `--fail-on <severity>` exit-code gating for CI.
- SARIF 2.1.0 output (`--format sarif`) for code-scanning dashboards.
- `-H/--header` to attach an identifying header required by some bug-bounty
  programs.
- `research/mcp_stdio_rce/`: local-only mocks, a safe detector CLI, and a lab
  guide for the OX Security MCP STDIO RCE classes.
- End-to-end detection regression suites; ruff/mypy/coverage quality gates wired
  into CI (lint, types, tests+coverage on a 3.8/3.12 matrix).
- `CONTRIBUTING.md`, `CODEOWNERS`, and an "Authorization — read before you scan"
  section in the README.

### Changed
- Source-mode JSON now writes `"coverage": null` (was `0`): no probe ran, so coverage does not apply, and null is
  the honest value. A live run with zero testable probes also writes null and exits 5. The text, HTML, SARIF and
  compliance-PDF renderers never print it (checked with a null payload); the text report prints no coverage number.

### Fixed
- Auth-finding accuracy: a `200` on an MCP path is now a zero-auth finding
  unless it is a human-facing HTML web page (SPA/docs catch-all). This fixes
  both a false positive (HTML pages flagged) and a false negative (an empty
  unauthenticated `200` no longer suppressed).
- Declared the web-app Python dependencies (`requirements-web.txt`) and added a
  CI `web-tests` job; the 52 flask-backed tests now run in CI.
- Portability: rewrote 336 `package-lock.json` `resolved` URLs that pointed at a
  Replit-internal mirror (`package-firewall.replit.internal`) back to the public
  npm registry, so `npm ci` works outside Replit. Added a CI `node-build` job
  (install, build client+server, run the self-contained TS suites); service-
  backed TS suites remain deploy-environment integration tests.
- Packaging: `pip install` no longer fails on flat-layout auto-discovery; added
  the `mcp-authscan` console entry point.
- Removed a broken `keycloak` submodule gitlink that aborted CI checkout.

### Known Issues
- **5xx Response Handling (Deferred to 1.1.7)**: When an OAuth endpoint returns
  5xx (server error), the scanner currently evaluates the response as if it
  contained a verdict. This causes probes that make HTTP requests (token-cors,
  token-cache-control, jwks-keys, password-grant, client-auth) to potentially
  publish FAIL findings about missing headers or invalid tokens when the server
  is actually unreachable or overloaded. A 5xx response cannot carry a verdict
  about CORS policy or authentication behavior. A systematic response handler
  that checks for 5xx before probe-specific logic will be implemented in 1.1.7.

### Removed
- Exploit/recon scripts and result artifacts targeting specific named third
  parties, which contradicted the project's authorization stance.

## [1.0.0]
- Baseline: MCP auth/CORS scanner with text/JSON reports and CWE/OWASP/NIST
  compliance mappings.

