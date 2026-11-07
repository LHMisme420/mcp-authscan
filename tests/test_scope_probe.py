import json
import mcp_authscan.scope_probe as sp

URL = "http://127.0.0.1:9200/mcp"
TOK = "t"
TOOL = "notes-write"
RES = json.dumps({"result": {}}).encode()
CHAL = "Bearer error=insufficient_scope scope=mcp.write"


def _serve(monkeypatch, status, hdrs, body):
    def f(u, payload, headers=None, timeout=5):
        return (status, hdrs, body)
    monkeypatch.setattr(sp, "_egress_guard_fetch", f)


def test_pass_on_normative_challenge(monkeypatch):
    _serve(monkeypatch, 403, {"WWW-Authenticate": CHAL}, b"")
    r = sp.run(URL, TOK, TOOL, False)
    assert r.status == "PASS"
    assert "insufficient_scope" in r.detail
    assert r.prerequisite_met is True


def test_pass_on_401(monkeypatch):
    _serve(monkeypatch, 401, {}, b"")
    assert sp.run(URL, TOK, TOOL, False).status == "PASS"


def test_200_undeclared_never_fails(monkeypatch):
    _serve(monkeypatch, 200, {}, RES)
    r = sp.run(URL, TOK, TOOL, False)
    assert r.status == "NOT_OBSERVED"
    assert r.severity is None


def test_200_declared_under_is_fail_high(monkeypatch):
    _serve(monkeypatch, 200, {}, RES)
    r = sp.run(URL, TOK, TOOL, True)
    assert r.status == "FAIL"
    assert r.severity == "HIGH"


def test_200_declared_no_result_body(monkeypatch):
    _serve(monkeypatch, 200, {}, b"{}")
    assert sp.run(URL, TOK, TOOL, True).status == "NOT_OBSERVED"


def test_403_without_normative_challenge(monkeypatch):
    _serve(monkeypatch, 403, {}, b"")
    assert sp.run(URL, TOK, TOOL, False).status == "NOT_OBSERVED"


def test_5xx_not_observed(monkeypatch):
    _serve(monkeypatch, 503, {}, b"")
    assert sp.run(URL, TOK, TOOL, False).status == "NOT_OBSERVED"


def test_transport_error_not_observed(monkeypatch):
    def boom(u, payload, headers=None, timeout=5):
        raise RuntimeError("no route")
    monkeypatch.setattr(sp, "_egress_guard_fetch", boom)
    r = sp.run(URL, TOK, TOOL, True)
    assert r.status == "NOT_OBSERVED"
    assert r.prerequisite_met is False
