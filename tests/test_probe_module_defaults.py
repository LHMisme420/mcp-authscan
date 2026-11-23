"""oauth_probes_v2 must run without monolith.main() having set its module flags first.

Before probe set 2026.11.21.1 ALLOW_PRIVATE_TARGETS had no module-level value: a probe
called without main() raised NameError, and the probes' broad except recorded it as
NOT_OBSERVED ("Request failed: name 'ALLOW_PRIVATE_TARGETS' is not defined"), a
verdict that looked like a network problem. tests/conftest.py sets the flag for every
pytest test, which hid this, so the check runs in a fresh interpreter without conftest.
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SCRIPT = r"""
import json
from unittest.mock import MagicMock, patch
import mcp_authscan.oauth_probes_v2 as p

flags = {name: getattr(p, name, "<missing>") for name in
         ("ALLOW_PRIVATE_TARGETS", "ACQUIRE_TOKEN", "ATTENDED_WAIT_SECONDS")}

body = json.dumps({"access_token": "synthetic-fixture-token"}).encode()
with patch("mcp_authscan.monolith.ALLOWED_HOSTS", {"fixture.example.test"}), \
     patch("mcp_authscan.oauth_probes_v2.assert_url_is_fetchable", lambda *a, **k: None), \
     patch("mcp_authscan.oauth_probes_v2._resolve_pinned", return_value="93.184.216.34"), \
     patch("mcp_authscan.oauth_probes_v2._open_no_redirect") as req:
    resp = MagicMock(); resp.status = 200; resp.read.side_effect = [body, b""]
    req.return_value.__enter__.return_value = resp
    rec = p.probe_password_grant("https://fixture.example.test/token")
print(json.dumps({"flags": {k: repr(v) for k, v in flags.items()},
                  "status": rec.status, "detail": rec.detail}))
"""


def _run():
    out = subprocess.run([sys.executable, "-c", SCRIPT], cwd=ROOT, capture_output=True,
                         text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    import json
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_module_flags_have_defaults_without_main():
    flags = _run()["flags"]
    assert flags["ALLOW_PRIVATE_TARGETS"] == "False", flags
    assert "<missing>" not in flags.values(), flags


def test_probe_grades_without_main_instead_of_name_error():
    result = _run()
    assert "is not defined" not in (result["detail"] or ""), result
    assert result["status"] == "FAIL", result
