# Differential coverage: mcp-authscan vs established SAST

Established general-purpose SAST tools run over the **same pinned benchmark corpus**,
to test the thesis that they miss the auth-LOGIC bugs mcp-authscan targets. "Caught"
means a finding at the actual vulnerable file; generic/adjacent patterns are noted.
Reproduce: `python3 tests/differential.py` (install bandit/gosec/semgrep first).

| repo | lang | mcp-authscan | bandit | gosec | semgrep |
|------|------|--------------|--------|-------|---------|
| lucky-aeon | Go | CATCH A1/A2/A3 | n/a (Go) | TODO (run on box) | TODO |
| webrix | TS | CATCH B1 | n/a | n/a (Go) | TODO |
| atrawog | Py | CATCH B3 | MISS (1 finding, unrelated FP) | n/a | TODO |
| metamcp | TS | CATCH A7 | n/a | n/a | TODO |
| mcp-pinot | Py | CATCH A10 | MISS (347 findings; flags bind-0.0.0.0, not auth) | n/a | TODO |
| akshay5995 | Py | review B2 | MISS (996 findings; all generic "hardcoded password" FPs) | n/a | TODO |
| mcpjungle | Go | review A4 | n/a | TODO | TODO |
| docker-oauth-helpers | Go | review A4 | n/a | TODO | TODO |

**Result so far (bandit, real runs):** on the Python detector-positives, bandit caught
**0/2** auth-logic bugs while emitting 347 and 996 findings respectively - it flags
generic patterns (bind-all, string literals that look like passwords) and never models
OAuth/authz semantics. gosec/semgrep columns complete when run on a host with a Go
toolchain and semgrep registry access.
