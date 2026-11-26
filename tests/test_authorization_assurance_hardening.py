import pytest

from mcp_authscan.policy_check import _authentication_contradiction
from mcp_authscan.report_verify import operations_binding
from mcp_authscan import strict_gate
from mcp_authscan import content_probe


def report(context=None):
    content = {
        "session_established": True,
        "operations": ["initialize"],
    }
    if context is not None:
        content["credential_context"] = context
    return {
        "sig_version": 4,
        "findings": [],
        "probes": [],
        "content_observed": content,
    }


@pytest.mark.parametrize(
    "context", [None, "credentialed", "unknown"]
)
def test_no_false_contradiction(context):
    assert _authentication_contradiction(report(context), True) is None


def test_anonymous_contradiction():
    assert _authentication_contradiction(report("anonymous"), True)


def test_unverified_operations_never_contradict():
    # The declared sig_version is not coverage; only the engine's verified result is.
    assert _authentication_contradiction(report("anonymous"), False) is None


def test_legacy_binding():
    r = report()
    assert operations_binding(r) == r["content_observed"]


def test_context_bound():
    r = report("credentialed")
    assert operations_binding(r)["credential_context"] == "credentialed"


@pytest.mark.parametrize("context", ["invalid", True, 123])
def test_invalid_context(context):
    with pytest.raises(ValueError):
        operations_binding(report(context))


@pytest.mark.parametrize(
    "token,expected",
    [(None, "unknown"), ("synthetic-token", "credentialed")]
)
def test_observation_context(monkeypatch, token, expected):
    monkeypatch.setattr(
        content_probe.mcp_session,
        "open_session",
        lambda *a, **k: {
            "established": False,
            "reason": "controlled fixture",
        }
    )
    result = content_probe.observe(
        "https://example.invalid/mcp", token=token
    )
    assert result["credential_context"] == expected


@pytest.mark.parametrize(
    "verdict,expected",
    [
        ("CLEAN", 0),
        ("CONDITIONAL", 2),
        ("REJECT", 1),
        ("CONTRADICTED", 1),
        ("UNKNOWN", 1),
    ]
)
def test_strict_gate(monkeypatch, verdict, expected):
    monkeypatch.setattr(
        strict_gate,
        "evaluate",
        lambda *args: {"verdict": verdict}
    )
    assert strict_gate.main(["report", "policy", "keys"]) == expected


def test_gate_exception_blocks(monkeypatch):
    def fail(*args):
        raise ValueError("invalid report")

    monkeypatch.setattr(strict_gate, "evaluate", fail)
    assert strict_gate.main(["report", "policy", "keys"]) == 1
