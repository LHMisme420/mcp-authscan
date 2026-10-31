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
