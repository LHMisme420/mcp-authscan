import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "two_tenant_server.py")

def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p

def start(port, misbehave):
    env = dict(os.environ, PORT=str(port))
    env.pop("MISBEHAVE", None)
    if misbehave:
        env["MISBEHAVE"] = "1"
    proc = subprocess.Popen([sys.executable, FIXTURE], env=env)
    for _ in range(60):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return proc
        except OSError:
            time.sleep(0.1)
    proc.terminate()
    raise RuntimeError("fixture did not start")

def call(port, token, record):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "params": {"name": "get_record", "arguments": {"id": record}}}).encode()
    url = "http://127.0.0.1:" + str(port) + "/mcp"
    req = urllib.request.Request(url, data=body, headers={"Authorization": "Bearer " + token})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())

def run(misbehave, token, record):
    port = free_port()
    proc = start(port, misbehave)
    try:
        return call(port, token, record)
    finally:
        proc.terminate()
        proc.wait(timeout=5)

def test_owned_record_is_returned():
    status, body = run(False, "tok-a", "r-a")
    assert status == 200 and body["result"]["owner"] == "a"

def test_cross_tenant_record_is_refused():
    status, body = run(False, "tok-a", "r-b")
    assert status == 403 and "result" not in body

def test_misbehaving_server_returns_foreign_record():
    status, body = run(True, "tok-a", "r-b")
    assert status == 200 and body["result"]["owner"] == "b"

def test_unknown_token_is_rejected():
    status, _ = run(False, "tok-x", "r-a")
    assert status == 401

def probe_run(monkeypatch, misbehave, token, foreign):
    import mcp_authscan.monolith as mo
    import mcp_authscan.oauth_probes_v2 as probes
    monkeypatch.setenv("MCPAUTHSCAN_TENANT_TOKEN", token)
    monkeypatch.setenv("MCPAUTHSCAN_FOREIGN_ID", foreign)
    monkeypatch.setattr(probes, "ALLOW_PRIVATE_TARGETS", True)
    mo.ALLOWED_HOSTS.add("127.0.0.1")
    port = free_port()
    proc = start(port, misbehave)
    try:
        return probes.probe_cross_tenant("http://127.0.0.1:" + str(port) + "/mcp")
    finally:
        proc.terminate()
        proc.wait(timeout=5)

def test_probe_passes_when_foreign_record_refused(monkeypatch):
    r = probe_run(monkeypatch, False, "tok-a", "r-b")
    assert r.status == "PASS"
    assert r.severity is None

def test_probe_fails_when_foreign_record_returned(monkeypatch):
    r = probe_run(monkeypatch, True, "tok-a", "r-b")
    assert r.status == "FAIL"
    assert r.severity == "CRITICAL"

def test_probe_does_not_pass_on_unauthorised_token(monkeypatch):
    r = probe_run(monkeypatch, False, "tok-x", "r-b")
    assert r.status == "NOT_OBSERVED"

def test_probe_excluded_without_tenant_inputs(monkeypatch):
    import mcp_authscan.oauth_probes_v2 as probes
    monkeypatch.delenv("MCPAUTHSCAN_TENANT_TOKEN", raising=False)
    monkeypatch.delenv("MCPAUTHSCAN_FOREIGN_ID", raising=False)
    r = probes.probe_cross_tenant("http://127.0.0.1/mcp")
    assert r.status == "EXCLUDED"
    assert "MCPAUTHSCAN_TENANT_TOKEN" in r.prerequisites
