"""Findings must be measured, or labelled as fake - never passed off as scans.

`scanner_integration.py` invents its server list and decides severities with
`random.random()`. Submitting that output to a real API is indistinguishable
from submitting results, and the dashboard scores severity counts, so a
fabricated CRITICAL lowers a customer's compliance score exactly as much as a
measured one. These tests pin the guards that keep synthetic data labelled and
opt-in.
"""
import asyncio
import importlib
import sys

import pytest

import scanner_integration


class _NoNetwork:
    """Stand-in for httpx.AsyncClient that fails if anything tries to connect."""

    def __init__(self, *args, **kwargs):
        raise AssertionError("test must not open a network client")


def test_run_scan_refuses_without_explicit_demo():
    scanner = scanner_integration.ScannerIntegration()
    with pytest.raises(RuntimeError) as excinfo:
        asyncio.run(scanner.run_scan(sample_size=1))
    assert "demo=True" in str(excinfo.value)


def test_demo_findings_are_labelled_and_never_touch_the_network(monkeypatch):
    monkeypatch.setattr(scanner_integration.httpx, "AsyncClient", _NoNetwork)
    scanner = scanner_integration.ScannerIntegration()
    findings = asyncio.run(scanner.run_scan(sample_size=20, demo=True))
    assert findings, "demo mode should still produce data"
    for finding in findings:
        assert finding["demo"] is True
        assert finding["description"].startswith("[DEMO]")


def test_submit_refuses_unlabelled_findings_before_any_request(monkeypatch):
    monkeypatch.setattr(scanner_integration.httpx, "AsyncClient", _NoNetwork)
    scanner = scanner_integration.ScannerIntegration()
    scanner.jwt_token = "token"
    unlabelled = [{"server_url": "http://a", "vector_type": "cors_bypass",
                   "severity": "CRITICAL"}]
    with pytest.raises(ValueError) as excinfo:
        asyncio.run(scanner.submit_findings(unlabelled))
    assert "not labelled demo" in str(excinfo.value)


def test_full_pipeline_is_not_demo_by_default(monkeypatch):
    monkeypatch.setattr(scanner_integration.httpx, "AsyncClient", _NoNetwork)

    async def no_setup(self):
        return None

    monkeypatch.setattr(scanner_integration.ScannerIntegration, "setup", no_setup)
    scanner = scanner_integration.ScannerIntegration()
    with pytest.raises(RuntimeError):
        asyncio.run(scanner.full_pipeline(sample_size=1))


def test_importing_the_demo_script_does_not_call_the_api(monkeypatch):
    import requests

    def explode(*args, **kwargs):
        raise AssertionError("importing a script must not send a request")

    monkeypatch.setattr(requests, "post", explode)
    sys.modules.pop("automated_scanner", None)
    module = importlib.import_module("automated_scanner")
    assert hasattr(module, "main")


def test_demo_script_requires_the_demo_flag():
    import automated_scanner

    with pytest.raises(SystemExit):
        automated_scanner.main([])


def test_demo_script_refuses_a_remote_api_without_allow_remote(monkeypatch):
    import automated_scanner

    def explode(*args, **kwargs):
        raise AssertionError("must refuse before sending anything")

    monkeypatch.setattr(automated_scanner.requests, "post", explode)
    rc = automated_scanner.main(["--demo", "--api-url",
                                 "https://mcp-authscan.onrender.com"])
    assert rc == 2
