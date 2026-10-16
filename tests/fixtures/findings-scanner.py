"""Isolated recovery-test server: deterministic checks, real Flask storage/auth."""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import app as dashboard
from mcp_authscan.scanner import ScanError


class FixtureScanner:
    def __init__(self, target_url, timeout=5):
        self.target_url = target_url

    def scan(self):
        if self.target_url.endswith("/failed"):
            raise ScanError("Fixture target unavailable")
        return [SimpleNamespace(
            passed=False, name="fixture-rule", risk_level=SimpleNamespace(value="HIGH"),
            description="Fixture evidence", endpoint="/mcp", details="Private fixture",
            remediation="Fixture remediation",
        )]


dashboard.MCPScanner = FixtureScanner
dashboard.app.run(host="127.0.0.1", port=dashboard.PORT, threaded=True)
