"""Regenerate the site's reproducible sample from the installed mcp-authscan.

    python -m mcp_authscan.site_sample [--site PATH/SampleReport.tsx] [--landing PATH/Landing.tsx] [--port 19191]

Runs the published sample's steps (start the fixture below, scan it, verify the report, map
it to a release) with the installed package, so every value printed is output of the version
actually installed, never a stored capture. With --site/--landing it reads the site files and
prints each string to replace with its current and new value; it never edits them.

Fixture text: this module is its single source. The site's FIXTURE block must equal it.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from importlib.metadata import version as pkgversion

FIXTURE = 'import json, sys\nfrom http.server import BaseHTTPRequestHandler, ThreadingHTTPServer\nclass H(BaseHTTPRequestHandler):\n    def _s(self, o, c=200):\n        b = b"" if o is None else json.dumps(o).encode()\n        self.send_response(c); self.send_header("Content-Type", "application/json")\n        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)\n    def do_POST(self):\n        m = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")\n        meth, i = m.get("method"), m.get("id")\n        if meth == "initialize":\n            self._s({"jsonrpc": "2.0", "id": i, "result": {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},\n                     "serverInfo": {"name": "fx", "version": "0"}, "instructions": "x" * 900}})\n        elif meth == "tools/list":\n            self._s({"jsonrpc": "2.0", "id": i, "result": {"tools": [{"name": "list_docs", "description": "d", "inputSchema": {"type": "object"}}]}})\n        elif meth in ("prompts/list", "resources/list"):\n            self._s({"jsonrpc": "2.0", "id": i, "result": {meth.split("/")[0]: []}})\n        elif i is None: self._s(None, 202)\n        else: self._s({"jsonrpc": "2.0", "id": i, "error": {"code": -32601, "message": "nf"}})\n    def do_GET(self): self._s({"error": "nf"}, 404)\n    def log_message(self, *a): pass\nThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()\n'

SCAN_ARGS = ["--json", "--output", "report.json", "--authorized-by", "Your Name",
             "--auth-basis", "my own local test server", "--contact", "you@example.com", "--allow-private"]


def _wheel_sha(ver):
    """sha256 of the published wheel, from PyPI's index; None when not obtainable."""
    try:
        req = urllib.request.Request("https://pypi.org/simple/mcp-authscan/",
                                     headers={"Accept": "application/vnd.pypi.simple.v1+json"})
        with urllib.request.urlopen(req, timeout=20) as r:
            files = json.load(r)["files"]
        name = "mcp_authscan-%s-py3-none-any.whl" % ver
        return next((f["hashes"]["sha256"] for f in files if f["filename"] == name), None)
    except Exception:
        return None


def run(port=19191):
    from mcp_authscan.monolith import PROBE_SET_VERSION, SEVERITY_CALIBRATION_VERSION
    ver = pkgversion("mcp-authscan")
    cli = shutil.which("mcp-authscan", path=os.path.dirname(sys.executable)) or shutil.which("mcp-authscan")
    if not cli:
        raise SystemExit("mcp-authscan console script not found next to %s; install the package first" % sys.executable)
    work = tempfile.mkdtemp(prefix="site-sample-")
    open(os.path.join(work, "fixture.py"), "w").write(FIXTURE)
    srv = subprocess.Popen([sys.executable, "fixture.py", str(port)], cwd=work,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.0)
        url = "http://127.0.0.1:%d/mcp" % port
        scan = subprocess.run([cli, url, *SCAN_ARGS], cwd=work, capture_output=True, text=True, timeout=120)
    finally:
        srv.terminate()
    rep = json.load(open(os.path.join(work, "report.json")))
    sid = re.search(r"STATE ID \(anonymous\): ([0-9a-f]{64})", scan.stderr)
    ver_out = subprocess.run([sys.executable, "-m", "mcp_authscan.report_verify", "report.json"],
                             cwd=work, capture_output=True, text=True).stdout.strip()
    rel_out = subprocess.run([sys.executable, "-m", "mcp_authscan.releases", "report.json"],
                             cwd=work, capture_output=True, text=True).stdout.strip()
    f = rep.get("findings") or []
    return {
        "version": ver, "probe_set": PROBE_SET_VERSION, "calibration": SEVERITY_CALIBRATION_VERSION,
        "wheel_sha256": _wheel_sha(ver), "exit_code": scan.returncode, "coverage": rep.get("coverage"),
        "findings": ["%s %s %s" % (x.get("severity"), x.get("rule"), x.get("title")) for x in f],
        "report_hash": rep.get("report_hash"), "state_id": sid.group(1) if sid else None,
        "report_verify": ver_out, "releases": rel_out, "workdir": work,
    }


def new_strings(r):
    """The site sample's version-dependent strings, rendered from a run."""
    v = r["version"]
    f = r["findings"]
    find = ("one finding, %s" % ", ".join(f[0].split(" ", 2))) if len(f) == 1 else ("%d findings" % len(f))
    return {
        "scanner": "Scanner: mcp-authscan %s, probe set %s, severity calibration %s." % (v, r["probe_set"], r["calibration"]),
        "wheel": "Wheel sha256: %s" % (r["wheel_sha256"] or "NOT OBTAINED (PyPI unreachable or version unpublished)"),
        "install": 'v/bin/pip install "mcp-authscan[signing]==%s"' % v,
        "download": "v/bin/pip download --no-deps mcp-authscan==%s -d wheel" % v,
        "sha256sum": "sha256sum wheel/mcp_authscan-%s-py3-none-any.whl" % v,
        "expect": "Exit code %d: %s. Coverage %s." % (r["exit_code"], find, r["coverage"]),
        "state_id": "Security state ID (anonymous): %s" % r["state_id"],
        "rh_short": "const RH_SHORT = '%s';" % (r["report_hash"] or "")[:8],
        "release_line": "The second lists release %s for probe" % v,
        "probe_set_line": "set %s and installed_matches true." % r["probe_set"],
    }


PATTERNS = {  # current value on the site, located by the stable text around it
    "scanner": r"Scanner: mcp-authscan [^<]*?severity calibration [0-9.]+\.",
    "wheel": r"Wheel sha256: [0-9a-f]{64}",
    "install": r'v/bin/pip install "mcp-authscan\[signing\]==[0-9.]+"',
    "download": r"v/bin/pip download --no-deps mcp-authscan==[0-9.]+ -d wheel",
    "sha256sum": r"sha256sum wheel/mcp_authscan-[0-9.]+-py3-none-any\.whl",
    "expect": r"Exit code \d+: [^<]*?Coverage [0-9.]+\.",
    "state_id": r"Security state ID \(anonymous\): [0-9a-f]{64}",
    "rh_short": r"const RH_SHORT = '[0-9a-f]+';",  # the sample's hash; the page's "Report hash:" line
    # belongs to the frozen owner-approved redacted report and is never regenerated
    "release_line": r"The second lists release [0-9.]+ for probe",
    "probe_set_line": r"set [0-9.]+ and installed_matches true\.",
}


def replacements(site_text, new):
    out = []
    for key, rx in PATTERNS.items():
        m = re.search(rx, site_text)
        out.append((key, m.group(0) if m else None, new[key]))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--site", help="path to the site's SampleReport.tsx (read only)")
    ap.add_argument("--landing", help="path to the site's Landing.tsx (read only)")
    ap.add_argument("--port", type=int, default=19191)
    a = ap.parse_args(argv)
    r = run(a.port)
    print("Installed: mcp-authscan %s, probe set %s, calibration %s" % (r["version"], r["probe_set"], r["calibration"]))
    print("Scan exit %s; report_verify: %s" % (r["exit_code"], r["report_verify"].splitlines()[0] if r["report_verify"] else "no output"))
    new = new_strings(r)
    if a.site:
        text = open(a.site, encoding="utf-8").read()
        m = re.search(r"const FIXTURE = `(.*?)`;", text, re.S)
        print("\nFIXTURE block: %s" % ("identical to mcp_authscan.site_sample.FIXTURE" if m and m.group(1) == FIXTURE
                                       else "DIFFERS from mcp_authscan.site_sample.FIXTURE (replace it)"))
        print("\n== %s: replace current with new ==" % a.site)
        for key, cur, nv in replacements(text, new):
            status = "unchanged" if cur == nv else ("NOT FOUND on site" if cur is None else "replace")
            print("[%s] %s\n  current: %s\n  new:     %s" % (key, status, cur, nv))
    if a.landing:
        text = open(a.landing, encoding="utf-8").read()
        m = re.search(r"Current release: mcp-authscan [0-9.]+, probe set [0-9.]+\. Wheel sha256 <code>[0-9a-f]{64}</code>", text)
        nv = "Current release: mcp-authscan %s, probe set %s. Wheel sha256 <code>%s</code>" % (
            r["version"], r["probe_set"], r["wheel_sha256"] or "NOT OBTAINED")
        print("\n== %s: version line ==\n  current: %s\n  new:     %s" % (a.landing, m.group(0) if m else "NOT FOUND", nv))
    if not (a.site or a.landing):
        print(json.dumps(new, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
