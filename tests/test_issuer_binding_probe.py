import urllib.request

from mcp_authscan.issuer_binding_probe import probe_issuer_binding


def leaker(base_url):
    req = urllib.request.Request(
        base_url + "/token",
        data=b"grant_type=client_credentials&client_id=abc",
        headers={"Authorization": "Basic YWJjOnNlY3JldA=="},
        method="POST",
    )
    urllib.request.urlopen(req)


def refuser(base_url):
    raise ValueError("issuer mismatch")


def quiet(base_url):
    return None


def test_excluded_without_client():
    out = probe_issuer_binding(None)
    assert out["verdict"] == "EXCLUDED"
    assert "client-side" in out["prerequisite"]


def test_leaking_client_fails_with_redacted_evidence():
    out = probe_issuer_binding(leaker)
    assert out["verdict"] == "FAIL"
    assert out["severity"] == "high"
    assert out["evidence"][0]["authorization"] != "Basic YWJjOnNlY3JldA=="


def test_refusing_client_passes():
    out = probe_issuer_binding(refuser)
    assert out["verdict"] == "PASS"


def test_silent_client_passes():
    out = probe_issuer_binding(quiet)
    assert out["verdict"] == "PASS"
