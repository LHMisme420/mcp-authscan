"""Optional taint-analysis engine (Semgrep) for the source scanner.

The regex rules in ``mcp_authscan.py`` match shapes and approximate guards. This
module adds real dataflow: within a function body it reports an SSRF or command-
injection finding only when Semgrep traces a source->sink path from untrusted input
to a dangerous sink AND no sanitizer clears the taint on the way -- a determination
no single regex can make (regex cannot tell whether the value reaching the sink was
validated first). OSS Semgrep's taint engine is intra-FUNCTION; following a tainted
value across function calls or files requires the paid Semgrep Pro engine, so a
source and sink split across functions is out of scope here (a documented upgrade
path, not a silent miss).

Semgrep is an optional dependency (``pip install 'mcp-authscan[taint]'``). When it
is not installed the engine is skipped with a clear note rather than failing, so
the core scanner never depends on it.
"""
import json
import logging
import shutil
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

RULES_DIR = Path(__file__).resolve().parent / "semgrep_rules"

# Semgrep severity -> scanner severity. Taint findings carry a proven path, so they
# are detectors (they gate), not review-list surface.
_SEV = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}


class TaintEngineUnavailable(RuntimeError):
    """Raised when --taint is requested but Semgrep is not installed."""


def semgrep_available():
    return shutil.which("semgrep") is not None


def _snippet(lines_text, line_no):
    """A 3-line context window around line_no, matching the regex scanner's format."""
    if not lines_text:
        return ""
    lines = lines_text.splitlines()
    lo, hi = max(0, line_no - 2), min(len(lines), line_no + 1)
    return "\n".join(f"  {i + 1}: {lines[i]}" for i in range(lo, hi))


def run_taint_scan(target, timeout=120, strict=False):
    """Run the bundled taint rules over ``target`` and return finding dicts shaped
    like the regex scanner's (rule/severity/confidence/title/file/line/evidence/
    snippet/ref). Returns [] when Semgrep is absent unless ``strict`` is set, in
    which case it raises TaintEngineUnavailable."""
    if not semgrep_available():
        if strict:
            raise TaintEngineUnavailable(
                "Semgrep is not installed. Install the taint extra: "
                "pip install 'mcp-authscan[taint]'")
        print("[taint] Semgrep not installed; skipping taint analysis "
              "(pip install 'mcp-authscan[taint]').", file=sys.stderr)
        return []
    if not RULES_DIR.is_dir():
        logger.error("Taint rules directory missing at %s", RULES_DIR)
        return []
    cmd = [
        "semgrep", "--json", "--quiet", "--metrics=off", "--disable-version-check",
        "--timeout", str(timeout), "--config", str(RULES_DIR), str(target),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 60)
    except subprocess.TimeoutExpired:
        print("[taint] Semgrep timed out; taint results omitted.", file=sys.stderr)
        return []
    except OSError as exc:
        logger.error("Unable to launch Semgrep: %s", exc)
        return []
    try:
        payload = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        logger.error("Semgrep returned unparseable output: %s", (proc.stderr or "")[:300])
        return []
    findings = []
    for r in payload.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        rule = meta.get("rule") or r.get("check_id", "").split(".")[-1]
        sev = _SEV.get(str(extra.get("severity", "")).upper(), "HIGH")
        line = r.get("start", {}).get("line", 0)
        findings.append({
            "rule": rule,
            "severity": sev,
            "confidence": str(meta.get("confidence", "HIGH")).upper(),
            "title": extra.get("message", "Taint dataflow finding").strip().split("\n")[0],
            "file": r.get("path", ""),
            "line": line,
            "evidence": f"source->sink dataflow path ({meta.get('cwe', ['?'])[0] if isinstance(meta.get('cwe'), list) else meta.get('cwe', '?')})",
            "snippet": _snippet(extra.get("lines", ""), line),
            "ref": "mcp-authscan taint engine (Semgrep)",
        })
    return findings
