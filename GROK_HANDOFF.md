# mcp-authscan — Handoff

**Repo:** `github.com/LHMisme420/mcp-authscan`
**Working branch:** `claude/adoring-galileo-ubd7mo` (all work below is pushed here; open a PR to `main` when ready)
**Latest commit:** `760ad4c`

A security scanner for **MCP (Model Context Protocol) server** deployments. It has
two engines plus a hosted web app. Everything below is live on the working branch.

---

## 1. What the tool is (two engines)

### A. Heuristic source scanner — `mcp_authscan.py` (repo root)
Regex/pattern rules over source code (`scan <dir>`) and live endpoints (`scan <url>`).
Rules are lettered (A1–A10, B1–B3, C1–C3…): OAuth/redirect flaws, hardcoded creds,
authn-without-authz, PKCE issues, SSRF *surface*, etc. Emits text / JSON / SARIF.

Key design rule established this session: **honesty of severity.**
- "Surface/review-list" rules (A4 SSRF-surface, A5, B3, medium-confidence B1) emit at
  **INFO / needs-review** and never trip `--fail-on`. They point a human at something,
  they don't claim a vuln.
- Definitive detectors (A1–A3, B1 explicit-skip/plain-downgrade, …) keep their severity
  and gate CI.
- Suppressions: inline `# authscan:ignore [RULE ...]` and a repo-level `.authscan-ignore`
  (`path-glob[:RULE,...]`).

### B. Taint (dataflow) engine — `mcp_authscan/taint_scan.py` + `mcp_authscan/semgrep_rules/*.yaml`
Opt-in `--taint` flag. Built on **Semgrep taint mode**. Reports a finding only when it
traces untrusted input → dangerous sink with **no sanitizer on the path** — something
regex can't decide. These are HIGH-confidence detectors and **gate** `--fail-on`.

- Optional dependency: `pip install 'mcp-authscan[taint]'`. If Semgrep is absent,
  `--taint` prints a note and skips (never errors).
- **Scope honesty:** OSS Semgrep taint is **intra-function**. Cross-function / cross-file
  needs Semgrep **Pro** — wired as `--taint --pro` (needs `SEMGREP_APP_TOKEN` +
  `semgrep install-semgrep-pro`; falls back gracefully). Pro was NOT runnable in the dev
  sandbox (no token); its cross-function tests are `@skipUnless` and verify in a Pro env.

---

## 2. The 15 taint detector classes (all TS/JS + Python, some + Go)

| ID | Class | CWE | Notes on precision |
|----|-------|-----|--------------------|
| T1-SSRF | Server-side request forgery | 918 | sanitizer = host/scheme allowlist, URL validator |
| T2-CMDI | OS command injection | 78 | incl. non-`shell=True` argv RCE + stdlib `rfile.read` body; `shlex.quote`/allowlist = sanitizer (NOT `shlex.split`) |
| T3-PATH | Path traversal | 22 | sanitizer = basename / `secure_filename` / `filepath.Base` |
| T4-SQLI | SQL injection | 89 | sink focus = query STRING arg, so parameterized queries stay silent |
| T5-SSTI | Template injection | 1336 | fires on user-controlled *template*, not template *data* |
| T6-EVAL | Code eval | 95 | `eval`/`Function`/`vm`/`exec` |
| T7-DESER | Unsafe deserialization | 502 | pickle/marshal/`yaml.load` (1-arg)/node-serialize; `yaml.safe_load` silent |
| T8-XSS | Cross-site scripting | 79 | scoped to raw-HTML sinks (`innerHTML`, `Markup`), NOT `res.send` (JSON FP trap) |
| T9-REDIR | Open redirect | 601 | sanitizer = `isSafeRedirect`/`is_safe_url` |
| T10-XXE | XML external entity | 611 | Python; lxml/minidom/sax; `defusedxml` silent |
| T11-PROTO | Prototype pollution | 1321 | JS/TS; recursive deep-merge sinks only (not shallow `Object.assign`) |
| T12-NOSQLI | NoSQL injection | 943 | JS/TS; sanitizer = primitive cast (`String()`/`ObjectId()`) |
| T13-REDOS | Regex injection / ReDoS | 1333 | sink focus = PATTERN arg; `re.escape`/`escapeStringRegexp` silent |
| T14-LDAP | LDAP injection | 90 | scoped to LDAP-specific methods + ldap3 `search_filter=` kwarg |
| T15-XPATH | XPath injection | 643 | lxml `.xpath()` / JS `xpath.select` |

Each has `*_vuln` + `*_safe` fixtures in `tests/fixtures/taint/`. Cross-function (Pro)
fixtures live in `tests/fixtures/taint/crossfn/`.

---

## 3. Precision discipline (the most important norm to keep)

**More rules only help if they don't cry wolf.** Every class is gated by:
1. A `*_vuln` fixture that MUST fire and a `*_safe` fixture that MUST stay silent.
2. A **zero-false-positive run on real repos** before shipping.

Real-repo FP runs are done with the full ruleset against four live MCP servers:
- `cloudflare/mcp` (TS)
- `startreedata/mcp-pinot` (Python)
- `googleapis/genai-toolbox` (Go, 533 files)
- `mongodb-js/mongodb-mcp-server` (TS, 614 files)

**Current result: 0 findings on all four.** This discipline caught two real latent bugs
this session — an over-broad `$R.body` source that matched *response* bodies (fixed by
pinning JS sources to `req`/`request`/`ctx`), and an LDAP sink matching Python's
`re.search` (fixed by scoping to LDAP-specific methods). Keep running real repos; don't
trust green tests alone.

---

## 4. How to run / develop

```bash
pip install -e .                      # core
pip install 'mcp-authscan[taint]'     # + Semgrep taint engine

# heuristic source scan
python3 mcp_authscan.py <dir> --fail-on high
python3 mcp_authscan.py <url>          # live endpoint scan

# + taint
python3 mcp_authscan.py <dir> --taint
python3 mcp_authscan.py <dir> --taint --pro   # cross-function (needs SEMGREP_APP_TOKEN)

# tests (taint tests skip if Semgrep not installed)
python3 -m unittest tests.test_taint_engine      # 36 tests (34 pass + 2 Pro-skipped)
python3 tests/verify_ground_truth.py             # heuristic seed regression (32/32)
python3 tests/benchmark.py                        # heuristic precision/recall (needs network; P=R=1.0)
```

**CI** (`.github/workflows/ci.yml`): self-scan `--fail-on high`, ground-truth, `ruff check
mcp_authscan research`, `mypy mcp_authscan`, web-tests (`python3 -m unittest`), node-build,
coverage (fail_under=80; `taint_scan.py` is coverage-omitted like other subprocess wrappers).
Note: CI does NOT install the `[taint]` extra, so taint tests skip in CI and the benchmark
is a local/manual tool.

**Adding a taint class** (the repeatable recipe):
1. New `mcp_authscan/semgrep_rules/<name>-taint.yaml` — `mode: taint`, metadata `rule: TN-…`,
   `confidence: HIGH`. JS request sources are `req`/`request`/`ctx` (never generic `$R.`).
   Use `focus-metavariable` on the dangerous ARG so safe idioms (parameterized/cast) stay silent.
   Watch the YAML gotcha: a `{ key: $V }` pattern needs quoting (`: ` breaks the scalar).
2. `*_vuln` + `*_safe` fixtures in `tests/fixtures/taint/`.
3. Validate: vuln fires, safe silent.
4. **FP-check on the four real repos — must be 0** (or justify/tune every hit).
5. Add asserts in `tests/test_taint_engine.py`; update README "Taint analysis" + CHANGELOG.
6. Commit + push to the working branch.

---

## 5. Also done earlier this session (context)
- Hosted web app (`app.py`) gained a required **authorization attestation** (`authorized:true`
  → 403 otherwise; logged to a `scan_authorizations` audit table) so it can't be used to scan
  systems the user doesn't own. (There was also a separate, user-owned production-deploy
  advisory-lock/two-phase-startup effort on the Replit copy — unrelated to the scanner engine.)
- Heuristic false-positive cleanup on `cloudflare/mcp`: 15 findings → 1 honest INFO.

---

## 6. Open next steps (not started)
- **CRLF / HTTP header injection** (CWE-113) — the main remaining dataflow class; skipped
  for FP risk (request value → `res.setHeader` is often safe). Do with care.
- **Pattern-based (non-taint) checks**: hardcoded secrets, weak crypto, insecure randomness.
  Different style — can't trace intent, inherently noisier. Would fit as heuristic rules.
- **Semgrep Pro**: if a token is available, run `--taint --pro` to light up the cross-function
  tests and get cross-file reach (e.g. a source handler + sink helper in different files).
- Optional: React `dangerouslySetInnerHTML` XSS as a separate `tsx` rule (removed from the JS
  XSS rule because the JSX pattern fails to parse under `languages: [javascript]`).

**Guiding principle to preserve:** precision over coverage. A green scan must mean something.
Never add or loosen a rule without the real-repo zero-FP check.
