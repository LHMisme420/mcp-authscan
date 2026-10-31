"""--json -o FILE must write the JSON report to FILE (help: "output file for HTML/JSON report").

Before the fix the --json branch printed to stdout and ignored --output, so no file was written.
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_json_output_option_writes_parseable_report(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "server.py").write_text("print('hello')\n")
    out = tmp_path / "report.json"
    proc = subprocess.run(
        [sys.executable, str(ROOT / "mcp_authscan.py"), str(src), "--json", "-o", str(out),
         "--authorized-by", "Fixture runner", "--auth-basis", "Local test fixture",
         "--contact", "fixture@example.test"],
        cwd=str(tmp_path), stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)
    assert proc.returncode in (0, 1), proc.stderr[-2000:]
    assert out.exists(), "--json -o %s wrote no file (rc=%d)" % (out, proc.returncode)
    report = json.loads(out.read_text())
    assert isinstance(report.get("report_hash"), str) and len(report["report_hash"]) == 64
    # stdout keeps the same report, so existing consumers of --json are unchanged
    assert json.loads(proc.stdout[proc.stdout.find("{"):])["report_hash"] == report["report_hash"]
