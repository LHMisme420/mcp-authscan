#!/usr/bin/env python3
"""Generate downloadable parity evidence from one owned loopback fixture scan.

No customer, production database, real target, email or publish operation.
The CLI's recorded scan is replayed into a disposable web export database; this
is not a claim that the different CLI/web scanning engines ran identical probes.
"""
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.test_exit_code_fixtures import fixture, AUTH
from mcp_authscan.report_verify import verify
from mcp_authscan.scan_report import save_snapshot


def main():
    output = ROOT / "generated-artifacts" / "report-parity"
    output.mkdir(parents=True, exist_ok=True)
    cli_file = output / "synthetic-cli-report.json"
    with fixture("test_fixture_with_findings.py", 9002):
        result = subprocess.run([
            sys.executable, str(ROOT / "mcp_authscan.py"),
            "http://127.0.0.1:9002/mcp", *AUTH, "--fail-on", "high",
            "--json", "--output", str(cli_file),
        ], cwd=ROOT, capture_output=True, text=True, timeout=60)
        if result.returncode != 1 or not cli_file.exists():
            raise RuntimeError("Synthetic findings fixture did not return expected exit 1:\n"
                               + result.stdout[-1000:] + result.stderr[-1000:])
    cli = json.loads(cli_file.read_text())
    with tempfile.TemporaryDirectory(prefix="report-parity-") as temporary:
        os.environ["DB_FILE"] = str(Path(temporary) / "fixture.sqlite")
        os.environ["JWT_SECRET"] = "synthetic-loopback-report-verification-key-only-32"
        spec = importlib.util.spec_from_file_location("parity_fixture_app", ROOT / "app.py")
        web = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(web)
        with sqlite3.connect(web.DB_FILE) as conn:
            conn.execute("INSERT INTO organizations(id,name) VALUES(?,?)",
                         (991, "Synthetic Demonstration — Not a Real Client Assessment"))
            scan_id = conn.execute(
                """INSERT INTO scan_runs(org_id,target,status,total_checks,findings_count)
                   VALUES(?,?,?,?,?)""",
                (991, cli["target"], cli["status"], cli["total_checks"], cli["findings_count"]),
            ).lastrowid
            for finding in cli["findings"]:
                conn.execute(
                    """INSERT INTO findings(org_id,scan_id,server_name,rule,vector_type,
                       severity,description,remediation) VALUES(?,?,?,?,?,?,?,?)""",
                    (991, scan_id, finding["server_name"], finding["rule"],
                     finding["vector_type"], finding["severity"],
                     finding["description"], finding["remediation"]),
                )
            save_snapshot(conn, 991, scan_id, cli)
        from flask_jwt_extended import create_access_token
        with web.app.app_context():
            token = create_access_token(identity="991")
        client = web.app.test_client()
        headers = {"Authorization": "Bearer " + token}
        json_response = client.get(
            f"/api/reports/pdf?scan_id={scan_id}&format=json", headers=headers)
        pdf_response = client.get(f"/api/reports/pdf?scan_id={scan_id}", headers=headers)
        assert json_response.status_code == pdf_response.status_code == 200
        exported = json_response.get_json()
        web_file = output / "synthetic-web-export.json"
        web_file.write_text(json.dumps(exported, indent=2, ensure_ascii=True) + "\n")
        (output / "synthetic-web-export.pdf").write_bytes(pdf_response.data)
    assert verify(cli_file)[0] == verify(web_file)[0] == "MATCH"
    assert cli["report_hash"] == exported["report_hash"]
    (output / "README.txt").write_text(
        "SYNTHETIC DEMONSTRATION — NOT A REAL CLIENT ASSESSMENT\n\n"
        "One CLI scan ran against the repository's owned loopback findings fixture.\n"
        "The exact recorded scan was replayed into a disposable SQLite database,\n"
        "then exported through the JWT-protected Flask web JSON/PDF route.\n"
        "The fixture deliberately contains failures. Expected CLI exit: 1.\n"
        "No production data or external target was used.\n"
        "This does not claim the different web and CLI engines execute identical probes.\n\n"
        "CLI SHA-256: " + cli["report_hash"] + "\n"
        "Web SHA-256: " + exported["report_hash"] + "\n"
    )
    print("SYNTHETIC owned loopback fixture; one recorded scan, no production data")
    print("CLI exit status:", result.returncode)
    print("Web JSON/PDF status:", json_response.status_code, pdf_response.status_code)
    print("CLI SHA-256:", cli["report_hash"])
    print("Web SHA-256:", exported["report_hash"])
    print("Both CLI verifications: MATCH")
    print("Artifacts:", output.relative_to(ROOT))


if __name__ == "__main__":
    main()
