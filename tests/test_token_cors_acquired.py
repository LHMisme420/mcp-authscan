"""token-cors [4] acquired-token mode (--acquire-token), PROBE_CONTRACT.md [4], probe set 2026.10.30.

Attended exchange: the person at the browser is simulated (Browser/_browse act on the printed
URL against the local fixture and paste the address landed on). Local fixture only
(fixture_oauth.py): TOKEN_CORS=none|wildcard|wildcard-cred|echo,
CONSENT=deny|interactive|wrong-state|wrong-redirect, REGISTRATION=fail, REVOCATION=fail. Every test also checks the
token never leaves memory: it is revoked at the fixture, and no scanner output, record,
exception string or report contains it.
"""
import json
import os
import subprocess
import sys
from urllib.request import urlopen

import pytest

import mcp_authscan.monolith as monolith
from mcp_authscan import oauth_probes_v2 as probes
from tests.test_probes_pkce_redirect import ROOT, fixture, _hits

SECRETS = ("fixture-acquired", "fixture-code", "fixture-rat", "fixture-secret")


@pytest.fixture(autouse=True)
def scope(monkeypatch):
    monkeypatch.setattr(monolith, "ALLOW_PRIVATE_TARGETS", True, raising=False)
    monkeypatch.setattr(probes, "ALLOW_PRIVATE_TARGETS", True, raising=False)
    monkeypatch.setattr(monolith, "ALLOWED_HOSTS", {"127.0.0.1"})
    for k in ("MCPAUTHSCAN_CLIENT_ID", "MCPAUTHSCAN_CLIENT_SECRET", "MCPAUTHSCAN_REDIRECT_URI"):
        monkeypatch.delenv(k, raising=False)
    del probes.CLIENT_REPORTS[:]


@pytest.fixture
def acquire(monkeypatch):
    monkeypatch.setattr(probes, "ACQUIRE_TOKEN", True)


class Browser:
    """The person at the browser: opens the printed URL, approves (entering a passphrase on a
    consent page), and pastes the address the browser lands on. Never follows that address."""

    def __init__(self, paste=None):
        self.prompts, self.paste = [], paste

    def __call__(self, authorization_url, redirect_uri):
        self.prompts.append(authorization_url)
        if self.paste is not None:
            return self.paste
        return _browse(authorization_url)


def _browse(url):
    import re
    from urllib.error import HTTPError
    from urllib.parse import urlencode, urlsplit
    from urllib.request import Request
    def go(req):
        try:
            with probes._NO_REDIRECT_OPENER.open(req, timeout=5) as r:
                return r.status, r.headers, r.read()
        except HTTPError as e:
            return e.code, e.headers, e.read()
    st, h, b = go(Request(url))
    if st == 200 and b"/authorize/approve" in b:
        rid = re.search(rb"name=request value=([\w-]+)", b).group(1).decode()
        p = urlsplit(url)
        st, h, b = go(Request("%s://%s/authorize/approve" % (p.scheme, p.netloc),
                              data=urlencode({"request": rid, "passphrase": "typed"}).encode()))
    return (h.get("Location") or "") + "\n"


@pytest.fixture
def browser(monkeypatch):
    b = Browser()
    monkeypatch.setattr(probes, "_prompt_for_redirect", b)
    return b


def _state(base):
    with urlopen(base + "/_clients", timeout=5) as r:
        return json.loads(r.read())


def _token_cors(base):
    records, _ = probes.run_oauth_assessment(base, None, base + "/mcp")
    return next(r for r in records if r.name == "token-cors")


def _no_secret(*texts):
    for t in texts:
        for s in SECRETS:
            assert s not in t, s


def _clean(r):
    _no_secret(json.dumps(r.as_dict()), repr(r.as_dict()))


@pytest.mark.parametrize("cors,status,severity", [
    ("none", "PASS", None),
    ("wildcard", "FAIL", "HIGH"),
    ("wildcard-cred", "FAIL", "CRITICAL"),
    ("echo", "NOT_OBSERVED", None),
])
def test_cors_variants(acquire, browser, cors, status, severity):
    with fixture(TOKEN_CORS=cors) as base:
        r = _token_cors(base)
        st = _state(base)
        assert _hits(base) == {}
    assert r.status == status and r.severity == severity, r.detail
    assert r.http_status == 200
    assert "access token obtained" in r.detail
    assert "revocation: access_token HTTP 200; refresh_token HTTP 200" in r.detail
    assert st["tokens_issued"] == 2 and st["tokens_revoked"] == 2 and st["tokens_outstanding"] == 0
    assert '"access_token": "[redacted]"' in r.body_excerpt
    if status == "FAIL":
        assert r.endpoint == base + "/token"
    _clean(r)


def _probe(base, **meta):
    return probes.probe_token_cors(base + "/token", metadata={
        "authorization_endpoint": base + "/authorize", "token_endpoint": base + "/token",
        "revocation_endpoint": base + "/revoke", **meta}, client=_registered(base))


@pytest.mark.parametrize("consent,limitation,why", [
    ("deny", probes.REFUSED_LIMITATION, "error=access_denied"),
    ("wrong-state", probes.STATE_LIMITATION, "state differs"),
    ("wrong-redirect", probes.WRONG_REDIRECT_LIMITATION, "expected " + probes.REDIRECT_CANDIDATES[0]),
])
def test_pasted_address_rejected(acquire, browser, consent, limitation, why):
    with fixture(CONSENT=consent) as base:
        r = _probe(base)
        st = _state(base)
        assert _hits(base) == {}
    assert r.status == "NOT_OBSERVED" and r.limitation == limitation
    assert "%s: %s; no token obtained" % (limitation, why) in r.detail
    assert len(browser.prompts) == 1          # one prompt, no retry
    assert st["tokens_issued"] == 0
    _clean(r)


@pytest.mark.parametrize("paste", ["\n", "EOF", "   \n"])
def test_empty_paste_or_eof(acquire, monkeypatch, paste):
    b = Browser(paste=paste)
    monkeypatch.setattr(probes, "_prompt_for_redirect", lambda url, redirect: b(url, redirect) if paste != "EOF"
                        else b.prompts.append(url))   # _prompt_for_redirect returns None at end of input
    with fixture() as base:
        r = _probe(base)
        st = _state(base)
    assert r.status == "NOT_OBSERVED" and r.limitation == probes.NO_PASTE_LIMITATION
    assert len(b.prompts) == 1 and st["tokens_issued"] == 0


def test_no_code_in_pasted_address(acquire, monkeypatch):
    with fixture() as base:
        b = Browser(paste=None)
        monkeypatch.setattr(probes, "_prompt_for_redirect",
                            lambda url, redirect: "%s?state=%s\n" % (redirect, dict(
                                __import__("urllib.parse").parse.parse_qsl(url.split("?", 1)[1]))["state"]))
        r = _probe(base)
    assert r.status == "NOT_OBSERVED" and r.limitation == probes.NO_CODE_LIMITATION


def test_authorization_url_carries_challenge_not_verifier(acquire, browser):
    from urllib.parse import parse_qsl, urlsplit
    with fixture() as base:
        _probe(base)
        with urlopen(base + "/_issued", timeout=5) as resp:
            verifiers = json.loads(resp.read())["verifiers"]
    q = dict(parse_qsl(urlsplit(browser.prompts[0]).query))
    assert q["code_challenge_method"] == "S256" and q["redirect_uri"] == probes.REDIRECT_CANDIDATES[0]
    assert q["response_type"] == "code" and q["client_id"].startswith("dcr-client-") and len(q["state"]) >= 16
    assert len(verifiers) == 1 and verifiers[0] not in browser.prompts[0]


def test_interactive_consent_approved_in_browser(acquire, browser):
    """The consent page needs a person (passphrase); the attended flow completes it."""
    with fixture(CONSENT="interactive") as base:
        r = _token_cors(base)
        st = _state(base)
    assert r.status == "PASS", r.detail
    assert len(browser.prompts) == 1 and st["tokens_issued"] == 2 and st["tokens_outstanding"] == 0
    _clean(r)


def _registered(base):
    """Register a client at the fixture the way run_oauth_assessment does."""
    client, reason = probes._register_client({"authorization_endpoint": base + "/authorize",
                                              "registration_endpoint": base + "/register"})
    assert client is not None and client.usable, reason
    return client


def test_env_client_when_registration_fails(acquire, browser, monkeypatch):
    with fixture(REGISTRATION="fail", TOKEN_CORS="wildcard") as base:
        monkeypatch.setenv("MCPAUTHSCAN_CLIENT_ID", "fixture-client")
        monkeypatch.setenv("MCPAUTHSCAN_CLIENT_SECRET", "fixture-secret")
        monkeypatch.setenv("MCPAUTHSCAN_REDIRECT_URI", base + "/cb")
        r = _token_cors(base)
        st = _state(base)
        assert _hits(base) == {}
    assert r.status == "FAIL" and r.severity == "HIGH", r.detail
    assert "client fixture-client (environment (MCPAUTHSCAN_CLIENT_ID))" in r.detail
    assert st["tokens_outstanding"] == 0
    _clean(r)


def test_excluded_without_any_client(acquire, browser):
    with fixture(REGISTRATION="fail") as base:
        r = _token_cors(base)
        st = _state(base)
    assert r.status == "EXCLUDED"
    assert r.limitation.startswith("No client to obtain a token")
    assert r.detail == ("Dynamic client registration unavailable: "
                        "registration returned HTTP 400 error=invalid_client_metadata")
    assert st["tokens_issued"] == 0
    assert browser.prompts == []             # no client: no prompt


def test_revocation_failure_reported_verdict_stands(acquire, browser):
    with fixture(REVOCATION="fail") as base:
        r = _token_cors(base)
    assert r.status == "PASS", r.detail
    assert "revocation: access_token HTTP 503 error=temporarily_unavailable" in r.detail
    _clean(r)


def test_exception_strings_are_sanitized(acquire, browser, monkeypatch):
    real = probes._egress_guard

    def boom(req, *a, **kw):
        if req.full_url.endswith("/token"):
            raise RuntimeError("leaked " + req.data.decode())
        return real(req, *a, **kw)
    monkeypatch.setattr(probes, "_egress_guard", boom)
    with fixture() as base:
        r = _token_cors(base)
    assert r.status == "NOT_OBSERVED"
    assert r.detail.endswith("token request failed: RuntimeError")
    assert "code_verifier" not in json.dumps(r.as_dict())
    _clean(r)


def test_off_by_default(monkeypatch):
    assert probes.ACQUIRE_TOKEN is False
    prompts = []
    monkeypatch.setattr(probes, "_prompt_for_redirect", lambda *a: prompts.append(a) or "")
    with fixture(TOKEN_CORS="wildcard-cred") as base:
        r = probes.probe_token_cors(base + "/token", metadata={
            "authorization_endpoint": base + "/authorize", "token_endpoint": base + "/token"},
            client=_registered(base))
        st = _state(base)
    assert prompts == [] and st["tokens_issued"] == 0
    assert "Acquired-token mode" not in (r.detail or "")


def _cli(base, *extra, paste_mode="browser"):
    """Run the CLI; with --acquire-token act as the person: read the printed URL from stderr,
    browse it, and write the landed-on address to stdin (or an empty line / EOF).
    Returns (proc-like, pasted)."""
    import re
    import threading
    env = {k: v for k, v in os.environ.items() if not k.startswith("MCPAUTHSCAN_")}
    p = subprocess.Popen(
        [sys.executable, "-c", "import sys; from mcp_authscan.cli_wrapper import main; sys.exit(main())",
         base + "/mcp", "--allow-private", "--authorized-by", "X", "--auth-basis", "x",
         "--contact", "x@x.com", *extra],
        cwd=str(ROOT), env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    err, urls, ready = [], [], threading.Event()

    def pump():
        for line in p.stderr:
            err.append(line)
            m = re.search(r"(http://\S+/authorize\?\S+)", line)
            if m:
                urls.append(m.group(1))
            if "empty line skips" in line:
                ready.set()
        ready.set()
    t = threading.Thread(target=pump)
    t.start()
    pasted = ""
    if "--acquire-token" in extra:
        ready.wait(60)
        if paste_mode == "browser" and urls:
            pasted = _browse(urls[0])
        if paste_mode != "eof":
            p.stdin.write(pasted or "\n")
    p.stdin.close()
    out = p.stdout.read()
    p.wait(60)
    t.join(60)
    return subprocess.CompletedProcess(p.args, p.returncode, out, "".join(err)), pasted.strip(), len(urls)


def test_help_lists_acquire_token():
    proc = subprocess.run([sys.executable, "-c",
                           "import sys; from mcp_authscan.cli_wrapper import main; sys.exit(main())", "--help"],
                          cwd=str(ROOT), capture_output=True, text=True, timeout=30)
    assert "--acquire-token" in proc.stdout


@pytest.mark.parametrize("env", [{}, {"TOKEN_CORS": "wildcard"}, {"TOKEN_CORS": "wildcard-cred"},
                                 {"TOKEN_CORS": "echo"}, {"CONSENT": "deny"}, {"CONSENT": "interactive"},
                                 {"CONSENT": "wrong-state"}, {"CONSENT": "wrong-redirect"},
                                 {"REVOCATION": "fail"}])
def test_token_verifier_code_absent_from_all_cli_output(env):
    """grep every byte the CLI writes (text, --json, --sarif, --html) for the fixture's token,
    every PKCE verifier the fixture saw, the code and the pasted address."""
    with fixture(**env) as base:
        runs = [_cli(base, "--acquire-token", *fmt) for fmt in ((), ("--json",), ("--sarif",), ("--html",))]
        st = _state(base)
        with urlopen(base + "/_issued", timeout=5) as resp:
            verifiers = json.loads(resp.read())["verifiers"]
        assert _hits(base) == {}
    for p, pasted, prompts in runs:
        assert p.returncode in (0, 1), p.stderr[-500:]
        assert prompts == 1
        assert pasted
        _no_secret(p.stdout, p.stderr)
        for v in verifiers + [pasted]:
            assert v not in p.stdout and v not in p.stderr
    token_issued = not env or "TOKEN_CORS" in env or env == {"CONSENT": "interactive"} or "REVOCATION" in env
    assert len(verifiers) == (4 if token_issued else 0)
    assert st["tokens_issued"] == (8 if token_issued else 0)   # 4 runs x (access + refresh)
    # REVOCATION=fail: the fixture refuses revocation, so its tokens stay outstanding there
    assert st["tokens_outstanding"] == (8 if env == {"REVOCATION": "fail"} else 0)


@pytest.mark.parametrize("mode", ["empty", "eof"])
def test_cli_empty_paste_or_eof(mode):
    with fixture() as base:
        p, _, prompts = _cli(base, "--acquire-token", paste_mode=mode)
        st = _state(base)
    assert p.returncode == 0 and prompts == 1 and st["tokens_issued"] == 0
    assert "Consent not completed: no redirect address pasted" in p.stdout + p.stderr


def test_plain_scan_never_prompts_or_reads_stdin():
    """Without --acquire-token: stdin is an open pipe nobody writes to; the scan must finish."""
    with fixture() as base:
        env = {k: v for k, v in os.environ.items() if not k.startswith("MCPAUTHSCAN_")}
        p = subprocess.Popen(
            [sys.executable, "-c", "import sys; from mcp_authscan.cli_wrapper import main; sys.exit(main())",
             base + "/mcp", "--allow-private", "--authorized-by", "X", "--auth-basis", "x", "--contact", "x@x.com"],
            cwd=str(ROOT), env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, err = p.communicate(timeout=60)   # stdin left open until communicate closes it at the end
        st = _state(base)
    assert p.returncode == 0
    assert "[?]" not in err and "/authorize?" not in err and st["tokens_issued"] == 0
