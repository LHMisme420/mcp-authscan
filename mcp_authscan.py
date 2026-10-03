#!/usr/bin/env python3
"""
VATA mcp_authscan v0.8 -- static detector for self-rolled-auth failure classes in MCP servers
and issuer-binding gaps in MCP OAuth clients.
Seeded from filed VATA findings (lucky-aeon, mcpjungle, metamcp).
Stdlib only. Heuristic static analysis: flags patterns, does not prove exploitability.
Confidence per rule is stated. Ground-truth test = re-detect your own known findings.

v0.8 changes:
 - New client-side rule family C1-C3 (issuer binding on M2M MCP OAuth providers).
   Upgrading the SDK does not close this: Python ClientCredentialsOAuthProvider /
   PrivateKeyJWTOAuthProvider need issuer=, TS ClientCredentialsProvider /
   PrivateKeyJwtProvider / StaticPrivateKeyJwtProvider / CrossAppAccessProvider need
   expectedIssuer, or credentials follow whatever AS the MCP server advertises.
   Refs: GHSA-qx49-fqc8-xw99 (python-sdk), typescript-sdk PR #2887 (SEP-2352).
 - --exclude DIR (repeatable) so rule fixtures don't trip the self-scan gate.

v0.4 changes:
 - A4 rebuilt sink-first: finds HTTP calls, inspects the URL argument, flags a non-literal
   URL derived from config/metadata/request reached with no allowlist / internal-IP guard.
   Catches Go http.NewRequest*/client.Do, JS fetch/axios, py requests/urlopen. This is the
   mcpjungle upstream_oauth.go RegistrationEndpoint SSRF class the old A4 missed.
 - A2 value must be whitespace-free (kills the "access token: "+err FP) and test-support
   dirs (testhelpers/mocks/fixtures) are skipped.
 - A5 skips comments and help-text string literals (was flagging CLI help text).
"""
import argparse, hashlib, json, re, sys
from pathlib import Path

SRC_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".mjs", ".cjs"}
SKIP_DIR = {".git", "node_modules", "dist", "build", "vendor", ".venv", "__pycache__"}
# A scanner must not flag its own rule definitions. Skip our own source file.
SELF_PATH = __import__("pathlib").Path(__file__).resolve()
TEST_DIR = {"__tests__", "test", "tests", "e2e", "testdata", "spec",
            "testhelpers", "testhelper", "mocks", "fixtures", "testutil", "testutils"}
TEST_FILE = re.compile(
    r"(_test\.go$|\.test\.[jt]sx?$|\.spec\.[jt]sx?$|_test\.py$|(^|/)test_[^/]+\.py$|"
    r"(^|/)testhelpers?\.go$|(^|/)mock_[^/]+\.go$|_mock\.go$)", re.I)

def is_test_path(p):
    if any(part.lower() in TEST_DIR for part in p.parts):
        return True
    return bool(TEST_FILE.search(p.as_posix()))

def iter_files(root, include_tests, exclude=()):
    root = Path(root)
    excl = [ (root / e).resolve() for e in exclude ]
    for p in root.rglob("*"):
        if not (p.is_file() and p.suffix in SRC_EXT):
            continue
        if p.resolve() == SELF_PATH:
            continue
        if any(s in p.parts for s in SKIP_DIR):
            continue
        if not include_tests and is_test_path(p):
            continue
        rp = p.resolve()
        if any(rp == e or e in rp.parents for e in excl):
            continue
        yield p

def lineno(text, idx):
    return text.count("\n", 0, idx) + 1

def linetext(text, idx):
    lines = text.splitlines()
    return lines[lineno(text, idx) - 1] if lines else ""

def snippet(text, idx, span=1):
    lines = text.splitlines()
    ln = lineno(text, idx) - 1
    lo, hi = max(0, ln - span), min(len(lines), ln + span + 1)
    return "\n".join(f"  {i+1}: {lines[i]}" for i in range(lo, hi))

def defname(head):
    """Pull the identifier from a func/function/def match head (handles Go receiver), or ''."""
    m = re.search(r"(?:func|function|def)\s+(?:\([^)]*\)\s+)?(\w+)", head)
    return m.group(1) if m else ""

def brace_block(text, start):
    """Return substring of the { } block beginning at/after start. Fallback: 40-line window."""
    i = text.find("{", start)
    if i == -1:
        lines = text[start:].splitlines()[:40]
        return "\n".join(lines)
    depth, j = 0, i
    while j < len(text):
        if text[j] == "{": depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0: return text[i:j+1]
        j += 1
    return text[i:i+4000]

DEF_ANY = re.compile(r"(func\s+(?:\([^)]*\)\s+)?\w+|function\s+\w+|def\s+\w+)")

def enclosing_block(text, idx):
    """Best-effort body of the function enclosing idx (Go/JS via braces; else a line window)."""
    last = None
    for m in DEF_ANY.finditer(text):
        if m.start() > idx:
            break
        last = m
    if last is None:
        s = text.rfind("\n", 0, max(0, idx - 1500))
        return text[max(0, s):idx + 400]
    return brace_block(text, last.start())

def add(findings, rule, sev, title, path, text, idx, evidence, ref, conf):
    findings.append({
        "rule": rule, "severity": sev, "confidence": conf, "title": title,
        "file": str(path), "line": lineno(text, idx),
        "evidence": evidence, "snippet": snippet(text, idx), "ref": ref,
    })

# ---- Rule A1: OAuth authorize endpoint never validates client_id / redirect_uri ----
# Confidence: HIGH. lucky-aeon handleOAuthAuthorize() class.
AUTHZ_HANDLER = re.compile(
    r"(function\s+\w*[Aa]uthoriz\w*|"
    r"func\s+(\([^)]*\)\s+)?\w*[Aa]uthoriz\w*|"
    r"def\s+\w*authoriz\w*|"
    r"\w*[Aa]uthoriz\w*\s*[:=]\s*(async\s*)?\()", re.I)
VALIDATES_CLIENT = re.compile(
    r"client_id[\s\S]{0,160}?(includes|find|lookup|exists|validat|verif|allow|"
    r"registr|db\.|query|SELECT|WHERE|clients?\[)", re.I)
VALIDATES_REDIRECT = re.compile(
    r"redirect_uri[\s\S]{0,160}?(includes|startsWith|indexOf|allow|whitelist|allowlist|"
    r"validat|verif|\.match|registr|RedirectURIs|registered)", re.I)

# A1 server/client discriminators: only an authorization SERVER endpoint is vulnerable.
# A client doing token exchange legitimately handles redirect_uri (sends it outbound).
CLIENT_EXCHANGE = re.compile(
    r"(grant_type|token_endpoint|tokenEndpoint|URLSearchParams|postFormToToken|"
    r"new FormData|params\.(set|append)\s*\(\s*['\"]redirect_uri|"
    r"urlencode|authorization_url|authorizationUrl|credentials\[|generate_pkce)", re.I)
SERVER_AUTHZ_ROLE = re.compile(
    r"(response_type|FormValue|\.Query\(|searchParams|req\.query|request\.query|"
    r"\.Redirect\(|res\.redirect|\.redirect\(|StatusFound|Location|authorization_endpoint)", re.I)

def rule_oauth_authorize(path, text, F):
    for m in AUTHZ_HANDLER.finditer(text):
        if defname(m.group(0)).lower().startswith("test"):
            continue
        block = brace_block(text, m.start())
        reads_client = "client_id" in block
        reads_redirect = "redirect_uri" in block
        if not (reads_client or reads_redirect):
            continue
        missing = []
        if reads_client and not VALIDATES_CLIENT.search(block):
            missing.append("client_id")
        if reads_redirect and not VALIDATES_REDIRECT.search(block):
            missing.append("redirect_uri")
        if missing:
            # server-role gate: skip client token-exchange / outbound URL builders;
            # require authorize-server signals. Use a forward window (brace_block on
            # Python grabs an inner dict literal and misses trailing client signals).
            gate = text[m.start():m.start() + 900]
            if CLIENT_EXCHANGE.search(gate) or not SERVER_AUTHZ_ROLE.search(gate):
                continue
            add(F, "A1", "CRITICAL",
                f"OAuth authorize handler reads but never validates {', '.join(missing)}",
                path, text, m.start(),
                f"handler uses {'/'.join(missing)} with no validation/allowlist in block",
                "VATA:lucky-aeon auth-bypass/ATO chain", "HIGH")

# ---- Rule A2: hardcoded default admin credentials ----
# Confidence: HIGH literal creds; MEDIUM re-seed. Value must be whitespace-free (no err-string FPs).
DEFAULT_CRED = re.compile(
    r"(admin@[\w.-]+\.local|"
    r"(password|passwd|secret|apikey|api_key|token)\s*[:=]\s*['\"][^'\"\s]{6,}['\"])", re.I)
RESEED = re.compile(r"(UpsertAdmin|seedAdmin|ensureAdmin|createDefaultAdmin|"
    r"(func|def|const|async)\s+\w*[Bb]ootstrap\w*|\.[Bb]ootstrap\s*\()", re.I)
CRED_CONTEXT = re.compile(r"(admin|account|identity|password|credential|passwd|secret)", re.I)

# A2 noise filters: placeholder/example values and doctest/example lines are not real creds.
CRED_PLACEHOLDER = re.compile(
    r"(\.\.\.|<[^>]+>|\$\{|your[-_ ]?|example|redacted|changeme|xxx+|placeholder|"
    r"dummy|sample|test|doctest|foo|bar|jwt\.token\.here|token\.here|"
    r"^[A-Z][A-Z0-9_]+$|-\d+\.\d+$)", re.I)

def _cred_value(evidence):
    """Extract the quoted value from an A2 evidence string, or '' if none."""
    m = re.search(r"['\"]([^'\"]{6,})['\"]", evidence)
    return m.group(1) if m else ""

# A dangerous re-seed runs on every startup/restart. A bare setup function
# (idempotent, first-boot) is not a finding. Require a startup trigger nearby.
RESEED_TRIGGER = re.compile(r"on_?start|startup|on_?boot|every restart|on_event|lifespan|if __name__|OnInitialize", re.I)

def rule_default_creds(path, text, F):
    for m in DEFAULT_CRED.finditer(text):
        ev = m.group(0)
        val = _cred_value(ev)
        line = linetext(text, m.start())
        # skip obvious placeholders/examples and doctest/comment lines
        if val and CRED_PLACEHOLDER.search(val):
            continue
        if re.match(r"\s*(>>>|\.\.\.|#|//|\*)", line):
            continue
        if "pragma: allowlist secret" in line.lower():
            continue
        if any(seg in str(path).lower() for seg in ("/demo", "demo_", "/example", "example_", "/sample", "sample_")):
            continue
        add(F, "A2", "CRITICAL", "Hardcoded default credential literal",
            path, text, m.start(), ev[:80],
            "VATA:lucky-aeon default admin creds", "HIGH")
    for m in RESEED.finditer(text):
        window = text[max(0, m.start()-200):m.start()+200]
        if not CRED_CONTEXT.search(window):
            continue
        if "idempotent" in window.lower():
            continue
        if not RESEED_TRIGGER.search(window):
            continue
        add(F, "A2", "HIGH", "Admin re-seed routine (verify not run every restart)",
            path, text, m.start(), m.group(0),
            "VATA:lucky-aeon UpsertAdmin/Bootstrap on restart", "MEDIUM")

# ---- Rule A3: auth MIDDLEWARE validates a token but enforces no role/tenant/scope ----
# Confidence: MEDIUM. Name must contain "middleware" (metamcp v1AuthMiddleware class).
MIDDLEWARE = re.compile(
    r"(func\s+(\([^)]*\)\s+)?\w*[Mm]iddleware\w*|"
    r"\w*[Mm]iddleware\w*\s*[:=]\s*(async\s*)?\(|"
    r"def\s+\w*middleware\w*)", re.I)
AUTHZ_CHECK = re.compile(r"(role|tenant|workspace|scope|permission|rbac|org(_?id)?|is_?admin)", re.I)
# A3 must read an INBOUND credential to be an authentication gate (not a rate limiter,
# a handler factory, or a client-side OAuth flow that merely obtains a token).
INBOUND_AUTH = re.compile(
    r"(Bearer\b|[\"']?[Aa]uthorization[\"']?\s*[)\]:,]|\.[Gg]etHeader\s*\(|"
    r"[Rr]equest\(\)\.Header|req\.[Hh]eaders?|headers\[|bearerToken|parseBearer|"
    r"stripBearer|extractToken|jwt\.(Parse|Verify)|ParseWithClaims|[Vv]alidateToken|"
    r"[Vv]erifyToken|[Ii]ntrospect)", re.I)

def rule_middleware_authz(path, text, F):
    for m in MIDDLEWARE.finditer(text):
        if defname(m.group(0)).lower().startswith("test"):
            continue
        block = brace_block(text, m.start())
        reads_inbound_cred = INBOUND_AUTH.search(block)
        if reads_inbound_cred and not AUTHZ_CHECK.search(block):
            add(F, "A3", "HIGH",
                "Auth middleware validates token but enforces no role/tenant/scope",
                path, text, m.start(),
                "token checked; no role/tenant/workspace/scope in block",
                "VATA:metamcp cross-tenant CWE-863", "MEDIUM")

# ---- Rule A4: SSRF -- HTTP request to a non-literal, externally-influenced URL, no guard ----
# Confidence: MEDIUM-LOW. Sink-first: find the HTTP call, inspect its URL argument.
# Catches mcpjungle upstream_oauth.go RegistrationEndpoint fetch (Go http.NewRequest*/Do).
# Each sink: (regex, group# holding the URL argument expression).
HTTP_SINKS = [
    (re.compile(r"http\.NewRequestWithContext\s*\([^,]+,[^,]+,\s*([^,\)]+)", re.I), 1),
    (re.compile(r"http\.NewRequest\s*\([^,]+,\s*([^,\)]+)", re.I), 1),
    (re.compile(r"http\.(?:Get|Post|Head|PostForm)\s*\(\s*([^,\)]+)", re.I), 1),
    (re.compile(r"\bfetch\s*\(\s*([^,\)]+)", re.I), 1),
    (re.compile(r"\baxios(?:\.\w+)?\s*\(\s*([^,\)]+)", re.I), 1),
    (re.compile(r"requests\.(?:get|post|put|delete|request)\s*\(\s*([^,\)]+)", re.I), 1),
    (re.compile(r"(?:urlopen|urllib\.request\.urlopen)\s*\(\s*([^,\)]+)", re.I), 1),
    (re.compile(r"\bgot\s*\(\s*([^,\)]+)", re.I), 1),
]
# URL arg that suggests external influence (config/discovered/request-derived), not a fixed host.
URL_INFLUENCE = re.compile(
    r"(endpoint|\buri\b|url|issuer|metadata|redirect|registration|jwks|"
    r"server|host|target|resource|upstream|discover|callback|input\.|cfg\.|config\.|req\.|request\.|params|query)", re.I)
# Guards that make an outbound fetch defensible.
SSRF_GUARD = re.compile(
    r"(allowlist|allow_list|whitelist|isInternal|is_internal|isPrivate|is_private|"
    r"isLoopback|privateIP|private_ip|blockedHost|blocklist|denylist|deny_list|"
    r"ssrf|ParseIP|net\.IP|isPublic|validateURL|validate_url|assertURL)", re.I)

def _is_literal(expr):
    e = expr.strip()
    if e[:1] in ("\"", "'"):        # plain string literal
        return True
    if e[:1] == "`" and "${" not in e:  # Go raw / JS template with no interpolation
        return True
    return False

def rule_ssrf(path, text, F):
    seen = set()
    for rx, g in HTTP_SINKS:
        for m in rx.finditer(text):
            urlarg = m.group(g) or ""
            if _is_literal(urlarg):
                continue
            if not URL_INFLUENCE.search(urlarg):
                continue
            block = enclosing_block(text, m.start())
            if SSRF_GUARD.search(block):
                continue
            key = lineno(text, m.start())
            if key in seen:
                continue
            seen.add(key)
            add(F, "A4", "MEDIUM",
                "SSRF surface: outbound request to non-literal URL, no guard in function (review each)",
                path, text, m.start(), f"url arg: {urlarg.strip()[:60]}",
                "VATA:mcpjungle OAuth DCR SSRF", "LOW")

# ---- Rule A5: excluded_tools / blocklist defined but thinly enforced ----
# Confidence: LOW. Review pointer, not a detector. Skips comments and help-text strings.
EXCLUDED = re.compile(r"(excluded_tools|blocked_tools|tool_blocklist|disabled_tools)", re.I)

def _is_noise_line(line):
    s = line.strip()
    if s.startswith(("//", "#", "*", "/*")):
        return True
    # help-text / doc string fragment: line is dominated by a quoted string ending with \n
    if ('\\n"' in s or s.endswith('" +') or s.endswith('",')) and '"' in s and "excluded" in s.lower() and ":" not in s.split("excluded")[0][-3:]:
        # crude: mentions inside prose strings, not a struct field/tag
        if "`json" not in s and "[]string" not in s:
            return True
    return False

def rule_excluded_tools(path, text, F):
    hits = [m for m in EXCLUDED.finditer(text) if not _is_noise_line(linetext(text, m.start()))]
    if len(hits) == 1:
        m = hits[0]
        add(F, "A5", "MEDIUM", "excluded_tools referenced once - verify all surfaces enforce it",
            path, text, m.start(), m.group(0),
            "VATA:mcpjungle excluded_tools bypass / REST Enabled-flag gap", "LOW")

# ---- Rule A6: authz/deny check gated on a specific method/path (review-list) ----
# Confidence: LOW. Review pointer, NOT a detector. Static analysis cannot prove
# whether OTHER methods bypass the check (that is control-flow reasoning), so this
# only surfaces authz checks that sit inside a method/path conditional for a human
# to verify a catch-all deny exists. Seeded by VATA:ttokkime tools/list bypass.
METHOD_GATE = re.compile(
    r"(if\s+[^\n{]*\b(req\.)?[Mm]ethod\s*==|switch\s+[^\n{]*[Mm]ethod\b|"
    r"case\s+[\"'][a-z]+/[a-z]+[\"']|==\s*[\"'](tools|resources|prompts)/)", re.I)
AUTHZ_DECISION = re.compile(
    r"(DeniedRBAC|Unauthorized|[Ff]orbidden|StatusForbidden|403|"
    r"!\s*\w*\.?(ToolAllowed|IsWildcard|hasRole|canAccess|isAllowed)|"
    r"return\s+[^\n]*(deny|denied|unauthor))", re.I)

def rule_method_scoped_authz(path, text, F):
    # Skip test/mock fixtures: they dispatch by method but carry no real authz.
    if is_test_path(path) or "mock" in str(path).lower():
        return
    seen = set()
    for m in METHOD_GATE.finditer(text):
        # Look only in a tight window around the method conditional (the gated
        # branch), not the whole function, so an authz word drifting elsewhere
        # in the file does not trigger a match.
        near = text[m.start():m.start()+400]
        if not AUTHZ_DECISION.search(near):
            continue
        key = lineno(text, m.start())
        if key in seen:
            continue
        seen.add(key)
        line = linetext(text, m.start()).strip()
        if line.startswith(("//", "#", "*", "/*")):
            continue
        add(F, "A6", "MEDIUM",
            "Authz check gated on a specific method/path - verify other methods are not bypassed (review each)",
            path, text, m.start(), line[:70],
            "VATA:ttokkime method-scoped RBAC (tools/list bypass)", "LOW")

# ===================== Client-side rules (C-series) =====================
# Issuer binding on MCP OAuth CLIENT providers holding pre-provisioned credentials.
# These credentials were not obtained by the SDK, so only the configured issuer says
# which authorization server they belong to. Without it, a malicious or compromised
# MCP server can advertise its own AS (RFC 9728 PRM) and receive the client secret
# or signed JWT assertion. A fixed SDK version alone does NOT close this.

PY_M2M = re.compile(r"\b(ClientCredentialsOAuthProvider|PrivateKeyJWTOAuthProvider)\s*\(")
TS_M2M = re.compile(r"\bnew\s+(ClientCredentialsProvider|PrivateKeyJwtProvider|"
                    r"StaticPrivateKeyJwtProvider|CrossAppAccessProvider)\s*\(")
PY_LEGACY = re.compile(r"\bRFC7523OAuthClientProvider\s*\(")
ISSUER_ESCAPE = re.compile(
    r"(skip\w*Issuer\w*\s*[:=]\s*(true|True|1)\b|"
    r"skip_\w*issuer\w*\s*[:=]\s*(true|True|1)\b|"
    r"(validate|verify|check)_?[Ii]ssuer\w*\s*[:=]\s*(false|False|0)\b|"
    r"[\"']verify_iss[\"']\s*:\s*(false|False)\b)")

def call_args(text, open_idx):
    """Return the argument text of a call whose '(' is at open_idx (paren-balanced,
    string-aware), or the next 1500 chars if unbalanced."""
    depth, i, q = 0, open_idx, None
    while i < len(text):
        c = text[i]
        if q:
            if c == "\\":
                i += 2; continue
            if c == q:
                q = None
        elif c in "\"'`":
            q = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i]
        i += 1
    return text[open_idx + 1:open_idx + 1500]

def _comment_line(line):
    return line.strip().startswith(("#", "//", "*", "/*"))

def _resolve_ts_options(text, name, before_idx):
    """If args are a bare identifier, find `const|let|var name = {...}` earlier in the
    file and return that object literal, else None."""
    rx = re.compile(r"\b(?:const|let|var)\s+" + re.escape(name) + r"\b[^=\n]*=\s*\{")
    last = None
    for m in rx.finditer(text, 0, before_idx):
        last = m
    if not last:
        return None
    return brace_block(text, last.end() - 1)

def rule_client_issuer_binding(path, text, F):
    # C1 (Python): issuer= missing
    for m in PY_M2M.finditer(text):
        line = linetext(text, m.start())
        if _comment_line(line) or re.match(r"\s*(class|def|from|import)\b", line):
            continue
        args = call_args(text, m.end() - 1)
        if re.search(r"\bissuer\s*=", args):
            continue
        if "**" in args:
            add(F, "C1", "HIGH",
                f"{m.group(1)} built from **kwargs - verify issuer= is set (review)",
                path, text, m.start(), "options spread from elsewhere; issuer not visible at call site",
                "GHSA-qx49-fqc8-xw99 (python-sdk issuer binding)", "MEDIUM")
            continue
        add(F, "C1", "HIGH",
            f"{m.group(1)} constructed without issuer= - credentials follow any AS the MCP server advertises",
            path, text, m.start(), f"{m.group(1)}(...) has no issuer= argument",
            "GHSA-qx49-fqc8-xw99 (python-sdk issuer binding)", "HIGH")

    # C1 (TypeScript/JS): expectedIssuer missing
    for m in TS_M2M.finditer(text):
        line = linetext(text, m.start())
        if _comment_line(line):
            continue
        args = call_args(text, m.end() - 1)
        if "expectedIssuer" in args:
            continue
        ident = re.fullmatch(r"\s*([A-Za-z_$][\w$]*)\s*,?\s*", args)
        if ident:
            obj = _resolve_ts_options(text, ident.group(1), m.start())
            if obj is not None and "expectedIssuer" in obj:
                continue
            if obj is None:
                add(F, "C1", "HIGH",
                    f"{m.group(1)} options built elsewhere - verify expectedIssuer is set (review)",
                    path, text, m.start(), f"options identifier '{ident.group(1)}' not resolvable in file",
                    "typescript-sdk PR #2887 (SEP-2352 issuer binding)", "MEDIUM")
                continue
        elif "..." in args:
            add(F, "C1", "HIGH",
                f"{m.group(1)} options spread from elsewhere - verify expectedIssuer is set (review)",
                path, text, m.start(), "object spread; expectedIssuer not visible at call site",
                "typescript-sdk PR #2887 (SEP-2352 issuer binding)", "MEDIUM")
            continue
        add(F, "C1", "HIGH",
            f"{m.group(1)} constructed without expectedIssuer - credentials follow any AS the MCP server advertises",
            path, text, m.start(), f"new {m.group(1)}(...) has no expectedIssuer",
            "typescript-sdk PR #2887 (SEP-2352 issuer binding)", "HIGH")

    # C2: legacy provider with no issuer option at all
    for m in PY_LEGACY.finditer(text):
        line = linetext(text, m.start())
        if _comment_line(line) or re.match(r"\s*(class|def|from|import)\b", line):
            continue
        add(F, "C2", "HIGH",
            "Deprecated RFC7523OAuthClientProvider - has no issuer option; cannot be bound, migrate",
            path, text, m.start(), "RFC7523OAuthClientProvider(...)",
            "GHSA-qx49-fqc8-xw99 (legacy provider, no fix by config)", "HIGH")

    # C3: issuer validation switched off
    for m in ISSUER_ESCAPE.finditer(text):
        line = linetext(text, m.start())
        if _comment_line(line):
            continue
        add(F, "C3", "HIGH",
            "Issuer validation disabled - mix-up / credential redirection guard turned off",
            path, text, m.start(), m.group(0)[:70],
            "RFC 8414 s3.3 / RFC 9207 / SEP-2352 escape hatch", "MEDIUM")

RULES = [rule_oauth_authorize, rule_default_creds, rule_middleware_authz,
         rule_ssrf, rule_excluded_tools, rule_method_scoped_authz,
         rule_client_issuer_binding]

def scan(root, include_tests, exclude=()):
    F = []
    for path in iter_files(root, include_tests, exclude):
        try:
            text = path.read_text(errors="ignore")
        except Exception:
            continue
        for r in RULES:
            r(path, text, F)
    return F

def main():
    ap = argparse.ArgumentParser(description="VATA mcp_authscan v0.8")
    ap.add_argument("target", help="path to MCP server repo/dir")
    ap.add_argument("--json", action="store_true", help="emit JSON + report sha256")
    ap.add_argument("--include-tests", action="store_true", help="also scan test files")
    ap.add_argument("--exclude", action="append", default=[], metavar="DIR",
                    help="skip a directory relative to target (repeatable)")
    ap.add_argument("--fail-on", choices=["critical", "high", "medium"], default=None)
    args = ap.parse_args()

    F = scan(args.target, args.include_tests, args.exclude)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    F.sort(key=lambda x: (order.get(x["severity"], 9), x["file"], x["line"]))

    if args.json:
        payload = {"target": args.target, "count": len(F), "findings": F}
        blob = json.dumps(payload, sort_keys=True).encode()
        payload["report_sha256"] = hashlib.sha256(blob).hexdigest()  # anchor hook
        print(json.dumps(payload, indent=2))
    else:
        if not F:
            print("No findings. (Absence of finding is not proof of safety.)")
        for x in F:
            print(f"[{x['severity']}/{x['confidence']}] {x['rule']}  {x['title']}")
            print(f"  {x['file']}:{x['line']}  ({x['ref']})")
            print(f"  {x['evidence']}")
            print(x["snippet"]); print()
        print(f"{len(F)} finding(s).")

    if args.fail_on:
        thr = {"critical": 0, "high": 1, "medium": 2}[args.fail_on]
        if any(order.get(x["severity"], 9) <= thr for x in F):
            sys.exit(1)

if __name__ == "__main__":
    main()
