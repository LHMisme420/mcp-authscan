import socket
import subprocess
import sys
import time

from mcp_authscan.resources_read_probe import probe_resources_read


def wait_port(port, timeout=10):
    start = time.time()
    while time.time() - start < timeout:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.5)
            s.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def run_fixture(mode, port):
    p = subprocess.Popen([sys.executable, "tests/resources_fixture.py", mode, str(port)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not wait_port(port):
        p.kill()
        raise RuntimeError("fixture did not start on %d" % port)
    return p


def test_no_token_excludes():
    r = probe_resources_read("http://127.0.0.1:1/mcp", None)
    assert r.status == "EXCLUDED", r.detail
    assert "no authenticated session" in r.detail


def test_enforcing_refusal_passes():
    p = run_fixture("enforcing", 9211)
    try:
        r = probe_resources_read("http://127.0.0.1:9211/mcp", "tok",
                                 allow_private=True, allowed_hosts=["127.0.0.1"])
        assert r.status == "PASS", r.detail
        assert r.http_status == 403, r.http_status
    finally:
        p.terminate()
        p.wait(timeout=5)


def test_vulnerable_session_fails():
    p = run_fixture("vulnerable", 9212)
    try:
        r = probe_resources_read("http://127.0.0.1:9212/mcp", "tok",
                                 allow_private=True, allowed_hosts=["127.0.0.1"])
        assert r.status == "FAIL", r.detail
        assert r.severity == "HIGH", r.severity
        assert "severity_basis" in r.detail, r.detail
    finally:
        p.terminate()
        p.wait(timeout=5)
