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

VERSION = "0.9.3"

SRC_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".mjs", ".cjs"}
SKIP_DIR = {".git", "node_modules", "dist", "build", "vendor", ".venv", "__pycache__"}
# A scanner must not flag its own rule definitions. Skip our own source file.
SELF_PATH = __import__("pathlib").Path(__file__).resolve()
TEST_DIR = {"__tests__", "test", "tests", "e2e", "testdata", "spec",
            "testhelpers", "testhelper", "mocks", "fixtures", "testutil", "testutils"}
TEST_FILE = re.compile(
    r"(_test\.go$|\.test\.[jt]sx?$|\.spec\.[jt]sx?$|_test\.py$|(^|/)test_[^/]+\.py$|"
    r"(^|/)testhelpers?\.go$|(^|/)mock_[^/]+\.go$|_mock\.go$)", re.I)

# Minified / hashed JS-CSS bundles are build output, not source. Skip scanner-wide.
MINIFIED_FILE = re.compile(
    r"(\.min\.(js|css)$|\.bundle\.(js|css)$|\.[0-9a-f]{8,}\.(js|css)$|"
    r"(^|/)static/js/[^/]+\.js$)", re.I)

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
        if MINIFIED_FILE.search(p.as_posix()):
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

# --- optional AST engine (A6-ast): graceful-degrade to stdlib regex if absent ---
HAVE_AST = False
try:
    import os as _os, sys as _sys
    _eng = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "engine")
    if _eng not in _sys.path:
        _sys.path.insert(0, _eng)
    import a6_ast as _a6ast  # loads tree_sitter + tree_sitter_go at import time
    HAVE_AST = True
except Exception:
    HAVE_AST = False


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
# Anchor is underscore-optional so it matches snake_case redirect_uri AND camelCase
# RedirectURI/redirectUri (Go/TS validate the camelCase form, often via a helper).
VALIDATES_REDIRECT = re.compile(
    r"redirect[_]?uri[s]?[\s\S]{0,200}?(includes|startsWith|indexOf|allow|whitelist|allowlist|"
    r"validat|verif|\.match|registr|registered|RedirectURIs\b|GetClient|checkRedirect|contains)", re.I)
# Handler that delegates the whole authorize to an authorization service/helper
# (e.g. h.authorize.StartAuthorization(req)) validates there, not inline. Action-verb
# prefix required so boolean checks (usesInternalAuthorizationServer) do NOT match.
DELEGATES_AUTHZ = re.compile(
    r"\.\s*(?:Start|Handle|Process|Do|Perform|Run|Begin)[Aa]uthoriz(?:e|ation)\w*\s*\(|"
    r"ValidateRedirect\w*\s*\(|registeredRedirect\s*\(", re.I)

# A1 server/client discriminators: only an authorization SERVER endpoint is vulnerable.
# A client doing token exchange legitimately handles redirect_uri (sends it outbound).
CLIENT_EXCHANGE = re.compile(
    r"(grant_type|token_endpoint|tokenEndpoint|URLSearchParams|postFormToToken|"
    r"new FormData|params\.(set|append)\s*\(\s*['\"]redirect_uri|"
    r"urlencode|authorization_url|authorizationUrl|credentials\[|generate_pkce)", re.I)
SERVER_AUTHZ_ROLE = re.compile(
    r"(response_type|FormValue|\.Query\(|searchParams|req\.query|request\.query|"
    r"\.Redirect\(|res\.redirect|\.redirect\(|StatusFound|Location|authorization_endpoint)", re.I)

INBOUND_REQ = re.compile(
    r"(\.Query\(\)|\.FormValue\(|URL\.Query|request\.args|request\.query_params|"
    r"req\.query|request\.GET\b|searchParams\.get|query_params|c\.Query\(|ctx\.Query\(|"
    r"http\.Request|http\.ResponseWriter|@(?:app|router|bp|blueprint)\.(?:get|post))", re.I)

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
            if not INBOUND_REQ.search(gate):   # outbound URL builder, not a server handler
                continue
            # Validation may be delegated to a helper/service or sit just past the
            # brace_block (Go/TS validate camelCase RedirectURI via a called function).
            # Re-check the wider gate before firing so we don't FP on handlers that
            # validate via registeredRedirect()/ValidateRedirectURI()/StartAuthorization().
            if "redirect_uri" in missing and (VALIDATES_REDIRECT.search(gate) or DELEGATES_AUTHZ.search(gate)):
                missing.remove("redirect_uri")
            if "client_id" in missing and (VALIDATES_CLIENT.search(gate) or DELEGATES_AUTHZ.search(gate)):
                missing.remove("client_id")
            if not missing:
                continue
            add(F, "A1", "MEDIUM",
                f"OAuth authorize handler reads {', '.join(missing)} \u2014 verify validation (here or in a downstream service)",
                path, text, m.start(),
                f"handler reads {'/'.join(missing)} with no validation/allowlist in THIS function; confirm it is enforced here or in a called service",
                "VATA:lucky-aeon auth-bypass/ATO chain (review-list)", "LOW")

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
        if val and "@" not in ev and (re.search(r"\{[^}]*\}|\$\{|%[sd]\b|%\(", val)
                    or re.fullmatch(r"(\S)\1{5,}", val)
                    or re.fullmatch(r"[\w$]+(?:\.[\w$]+)+", val)):
            continue
        if re.search(r"(#|//)\s*nosec\b", line, re.I):
            continue
        if "nolint:gosec" in line.lower() or "not a credential" in line.lower():
            continue
        if val and val.lower().startswith("urn:"):
            continue
        if any(seg in str(path).lower() for seg in ("/demo", "demo_", "/example", "example_", "/sample", "sample_")):
            continue
        pl = str(path).lower()
        if "@" not in ev and any(seg in pl for seg in (".config.", "/scripts/", "tsdown", "vite.config", "webpack", "rollup", "/config/", ".env.example")):
            continue
        if val and (re.search(r"\.(ts|js|tsx|jsx|py|go|json|ya?ml)$", val) or val.startswith("eyJ")):
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
    # Frontend and demo-script fetches to the app's own backend are not SSRF.
    pl = path.as_posix().lower()
    if any(s in pl for s in ("/frontend/", "/web/", "/ui/", "/scripts/save-demo", "/skills/")):
        return
    seen = set()
    for rx, g in HTTP_SINKS:
        for m in rx.finditer(text):
            urlarg = m.group(g) or ""
            if _is_literal(urlarg):
                continue
            if not URL_INFLUENCE.search(urlarg):
                continue
            # Configured base URL, not caller-controlled. Leave those to review by hand.
            if re.search(r"gateway_url|provisioner_url|sandbox_url|discovery_url|jwks_uri|token_endpoint|userinfo_endpoint|getenv|os\.environ|_host\(", urlarg):
                continue
            # Configured base URL, not caller-controlled. Leave those to review by hand.
            if re.search(r"gateway_url|provisioner_url|sandbox_url|discovery_url|jwks_uri|token_endpoint|userinfo_endpoint|getenv|os\.environ|_host\(", urlarg):
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

    # ---- Rule A6-ast: structural method-scoped authz bypass (HIGH, detector) ----
    # Upgrades regex-A6 (a LOW review-pointer) to a real detector via tree-sitter.
    # FIRES when: an `if <x>.Method == <protocol-method>` guard CONTAINS an authz
    #   call (ToolAllowed/Authorized/HasScope/...), AND a sink (proxy/ServeHTTP/
    #   forward/catalog) is a later sibling of that guard -- i.e. reachable when the
    #   guarded method condition is false. That asymmetry is the bypass.
    # VALIDATED: Ttokkime/mcp-gateway @ e2fa419 proxy.go:144 (tools/list RBAC
    #   bypass, Sepolia-anchored). Corpus sweep: 1/258 Go files, seed-only, 0 FP.
    # BLIND SPOT (documented, not a bug): guards keyed on HTTP transport verbs
    #   (GET/POST/OPTIONS) are treated as routing/CORS and ignored. A gateway that
    #   keys real authorization off HTTP verbs instead of protocol methods will
    #   NOT be detected by this rule. Scoped to MCP protocol-method dispatch.
    # CLAIM BOUNDARY: precision validated (0 FP on corpus); detection validated at
    #   n=1 (the seed). This rule has not yet DISCOVERED an unknown bug -- that
    #   requires a fire on a fresh target confirmed by hand. Receipts over promises.
    # --- A6-ast: structural confirmation on Go files when the AST engine is present ---
    # Regex-A6 above is a LOW review-pointer; A6-ast is a HIGH structural detector.
    # Reached only for non-test/.go files (test/mock returned early at top of fn).
    if HAVE_AST and str(path).endswith(".go"):
        try:
            for _f in _a6ast.analyze(str(path)):
                _gl = _f["gate_line"]
                _off = sum(len(p) + 1 for p in text.split("\n")[:_gl - 1])
                add(F, "A6-ast", "HIGH",
                    "Method-scoped authz gate with ungated sink on another method path (structural)",
                    path, text, _off,
                    "gate L%d -> ungated sink L%d (%s)" % (_gl, _f["sink_line"], _f["sink"]),
                    "VATA:ttokkime method-scoped RBAC (tools/list bypass) [AST-confirmed]", "HIGH")
        except Exception:
            pass  # engine failure must never break the stdlib scan

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

# ===================== SARIF 2.1.0 output (GitHub code scanning) =====================
# Rule metadata for the Security tab. Rules absent here still emit results via a
# graceful fallback, so adding a new detector rule never breaks SARIF output.
# security-severity is a string float GitHub buckets as: >=9 critical, 7-8.9 high,
# 4-6.9 medium, <4 low. It is a rule-level property, so a rule that spans severities
# (e.g. A2) buckets by its canonical value; the per-finding severity still rides on
# the result `level` (error/warning/note) below.
RULE_META = {
    "A1": {"name": "OAuthAuthorizeClientValidationUnverified",
           "desc": "Authorize handler reads client_id/redirect_uri; validation not seen in the handler itself. Review pointer \u2014 single-file analysis cannot follow validation into a downstream service, so confirm manually (auth bypass / open redirect / ATO if truly absent).",
           "sev": 3.5, "cwe": ["CWE-862", "CWE-863", "CWE-601"]},
    "A2": {"name": "HardcodedDefaultAdminCredential",
           "desc": "Hardcoded default admin credential, or an admin re-seed routine that may run on every restart.",
           "sev": 9.0, "cwe": ["CWE-798", "CWE-1392"]},
    "A3": {"name": "AuthMiddlewareNoAuthorization",
           "desc": "Auth middleware validates a token but enforces no role/tenant/scope (cross-tenant access).",
           "sev": 7.5, "cwe": ["CWE-862", "CWE-863"]},
    "A4": {"name": "SSRFOutboundNonLiteralURL",
           "desc": "Outbound HTTP request to a non-literal, externally-influenced URL with no allowlist / internal-IP guard (review-list).",
           "sev": 5.0, "cwe": ["CWE-918"]},
    "A5": {"name": "ToolBlocklistEnforcementUnverified",
           "desc": "excluded_tools/blocklist defined but enforcement unverified across surfaces (review pointer).",
           "sev": 3.0, "cwe": ["CWE-863"]},
    "A6": {"name": "MethodScopedAuthorization",
           "desc": "Authorization check gated on a specific method/path; other methods may bypass it (review-list).",
           "sev": 5.0, "cwe": ["CWE-863"]},
    "A7": {"name": "CrossTenantUnscopedList",
           "desc": "Unscoped list (findAll/listAll) on a repo that also exposes a tenant-scoped sibling, reached from a request handler - cross-tenant read.",
           "sev": 7.5, "cwe": ["CWE-863", "CWE-862"]},
    "A10": {"name": "FastMCPAuthNoneByDefault",
            "desc": "FastMCP server on a network transport (http/sse/0.0.0.0) with auth=None or an auth var that defaults to None unless an opt-in flag is set - unauthenticated by default.",
            "sev": 7.5, "cwe": ["CWE-306", "CWE-1188"]},
    "C1": {"name": "MCPClientMissingIssuerBinding",
           "desc": "M2M MCP OAuth client provider built without issuer/expectedIssuer; pre-provisioned credentials follow whatever AS the MCP server advertises.",
           "sev": 7.5, "cwe": ["CWE-346", "CWE-290"]},
    "C2": {"name": "MCPClientLegacyProviderNoIssuer",
           "desc": "Deprecated RFC7523OAuthClientProvider has no issuer option and cannot be bound; migrate.",
           "sev": 7.5, "cwe": ["CWE-346"]},
    "C3": {"name": "MCPClientIssuerValidationDisabled",
           "desc": "Issuer validation explicitly disabled; authorization-server mix-up / credential-redirection guard turned off.",
           "sev": 7.5, "cwe": ["CWE-346", "CWE-290"]},
    "B1": {"name": "PKCEAcceptedbutNeverEnforced",
           "desc": "Self-rolled authorization server accepts a PKCE code_verifier (or is explicitly told to skip local PKCE) but never performs the SHA-256/S256 challenge check.",
           "sev": 8.1, "cwe": ["CWE-287", "CWE-1390"]},
    "B2": {"name": "AuthorizationCodeNotSingleUse",
           "desc": "Authorization code is redeemed at the token endpoint but is never invalidated (delete/mark-used/revoke) in the same file; the code may be replayable. Review pointer: confirm invalidation is not delegated to an unscanned storage layer.",
           "sev": 8.6, "cwe": ["CWE-294", "CWE-384"]},
    "B3": {"name": "AuthorizationCodeExcessiveLifetime",
           "desc": "Large TTL found near authorization-code context. Review pointer \u2014 regex cannot prove the number governs the auth code (vs an access/refresh-token TTL), so confirm manually; an auth code far exceeding RFC 6749's ~600s is the real risk.",
           "sev": 3.5, "cwe": ["CWE-613"]},
}
SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}

def _ghsa_uri(ref):
    m = re.search(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", ref or "", re.I)
    return f"https://github.com/advisories/{m.group(0)}" if m else None

def to_sarif(findings, target):
    """Build a SARIF 2.1.0 log. Carries the same report_sha256 receipt as --json
    (over the identical findings payload) in run.properties so a SARIF run is as
    anchorable as a JSON one."""
    root = Path(target).resolve()
    # declare every known rule, plus any rule that fired but isn't in RULE_META
    rule_ids = list(RULE_META.keys())
    for f in findings:
        if f["rule"] not in rule_ids:
            rule_ids.append(f["rule"])
    rule_index = {rid: i for i, rid in enumerate(rule_ids)}
    rules = []
    for rid in rule_ids:
        meta = RULE_META.get(rid, {})
        rules.append({
            "id": rid,
            "name": meta.get("name", f"Rule{rid}"),
            "shortDescription": {"text": meta.get("desc", f"VATA mcp-authscan rule {rid}")},
            "helpUri": "https://github.com/LHMisme420/mcp-authscan#rules",
            "properties": {
                "security-severity": f"{meta.get('sev', 5.0):.1f}",
                "tags": ["security", "mcp", "oauth"] + meta.get("cwe", []),
            },
        })
    results = []
    for f in findings:
        rid = f["rule"]
        try:
            uri = Path(f["file"]).resolve().relative_to(root).as_posix()
        except Exception:
            uri = Path(f["file"]).as_posix()
        ref = f.get("ref", "")
        fp = hashlib.sha256(f"{rid}|{uri}|{f.get('evidence','')}".encode()).hexdigest()[:16]
        props = {"confidence": f.get("confidence", ""), "vataSeverity": f.get("severity", ""),
                 "ref": ref, "evidence": f.get("evidence", "")}
        adv = _ghsa_uri(ref)
        if adv:
            props["advisory"] = adv
        results.append({
            "ruleId": rid,
            "ruleIndex": rule_index[rid],
            "level": SARIF_LEVEL.get(f["severity"], "warning"),
            "message": {"text": f"{f['title']} [{f['severity']}/{f['confidence']}] ({ref})"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": max(1, int(f.get("line", 1)))},
            }}],
            "partialFingerprints": {"vataAuthscan/v1": fp},
            "properties": props,
        })
    blob = json.dumps({"target": target, "count": len(findings), "findings": findings},
                      sort_keys=True).encode()
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "mcp-authscan",
                "informationUri": "https://github.com/LHMisme420/mcp-authscan",
                "version": VERSION,
                "rules": rules,
            }},
            "properties": {"reportSha256": hashlib.sha256(blob).hexdigest()},
            "results": results,
        }],
    }
# ---- Rules B1/B2/B3: self-rolled OAuth authorization-code lifecycle ----
# Seeded from VATA findings akshay5995 / atrawog / webrix. Validated v4 against a
# 4-repo ground-truth corpus (3/3 seeded recovered, 0 FP on IdP-delegating control).
# Per-file by design (matches the scan() driver). KNOWN LIMITS, not faked:
#   * B1 does NOT detect PKCE-*optional* (validated-when-present, skippable-when-
#     absent) -- that is control-flow, not a regex shape (atrawog's B1 case).
#   * B2 is SAME-FILE only: a redeem path whose invalidation lives in a different
#     file (storage layer) will false-positive. Hence MEDIUM/warning + review note.
#   * B3 "no expiry field anywhere in schema" (cross-file absence) is out of scope;
#     only explicit excessive TTL is detected.

B_OAUTH_HINT = re.compile(r"authorization_code|grant_type|code_verifier|code_challenge|token_endpoint|oauth|pkce|/token|/authorize", re.I)
B_AS_ROUTE  = re.compile(r"""(?:@\w+\.(?:post|get|route|api_route)|(?:router|app|server|blueprint|bp)\.(?:post|get|route)|add_api_route|add_route)\s*\(\s*['"][^'"]*/(?:token|authorize|authorization|oauth)""", re.I)
B_AS_FORM   = re.compile(r"\bForm\s*\(", re.I)
B_AS_INBOUND = re.compile(r"""request\.(?:form|json|body|data|query|args|POST)|req\.(?:body|query|params)|\.get\(\s*['"](?:grant_type|code_verifier|code)['"]""", re.I)
B_AS_FUNC   = re.compile(r"""exchange[_]?authorization[_]?code|exchangeAuthorizationCode|create[_]?authorization[_]?code|createAuthorizationCode|store[_]?authorization[_]?code|storeAuthorizationCode|validate[_]?(?:authorization[_]?)?code|issue[_]?(?:access[_]?)?token|issueToken|def\s+token\b|def\s+authorize\b""", re.I)
B_CLIENT_REQ = re.compile(r"""(?:requests|httpx|aiohttp|urllib|session|axios)\.(?:post|request|get)\b|fetch\s*\([^\n]{0,120}token|data\s*=\s*\{[^}\n]*grant_type|token_(?:endpoint|url|uri)\s*[,=)]""", re.I)

def _b_is_authz_server(text):
    strong = bool(B_AS_ROUTE.search(text) or B_AS_FORM.search(text) or B_AS_INBOUND.search(text))
    func   = bool(B_AS_FUNC.search(text))
    client = bool(B_CLIENT_REQ.search(text))
    return strong or (func and not client)

B_SKIP_PKCE = re.compile(r"skip[_-]?local[_-]?pkce[_-]?validation\s*[:=]\s*true", re.I)
# PKCE downgradeable to 'plain': challenge method defaults to / falls back to 'plain'
# (plain -> challenge == verifier, no protection). CVE-2025-4144 class.
B_PKCE_PLAIN_DEFAULT = re.compile(
    r"code[_-]?challenge[_-]?method\b[^;\n]{0,60}(?:\|\||\?\?)\s*[\'\"]plain[\'\"]", re.I)
B_PKCE_HASH = re.compile(r"sha-?256|s256|createhash|crypto\.createHash|subtle\.digest|hashlib\.sha256|\.digest\(|hashes\.SHA256", re.I)
B_VERIFIER  = re.compile(r"code[_]?verifier", re.I)
B_GEN_VERIFIER = re.compile(r"code[_]?verifier\s*=\s*.*(?:secrets|token_|randombytes|random\.|base64|createhash|uuid|getrandom)", re.I)
B_RECV_HINT = re.compile(r"""Form\s*\(|Body\s*\(|Query\s*\(|:\s*Optional|:\s*str\b|\?\s*:\s*str|\.get\(\s*['"]code_verifier|request\.|req\.|body\.|params|\bdef\s|\bfunction\s|[(,]\s*code[_]?verifier\s*[:?,)]""", re.I)

B_GRANT_AC    = re.compile(r"grant_type[^\n]{0,40}authorization_code|authorization_code[^\n]{0,40}grant_type|['\"]authorization_code['\"]", re.I)
B_REDEEM_FUNC = re.compile(r"exchange[_]?authorization[_]?code|exchangeAuthorizationCode|redeem[_\s\w]{0,20}code|validate[_]?authorization[_]?code|validateAuthorizationCode|consume[_\s\w]{0,20}code", re.I)
B_LOOKUP_CODE = re.compile(r"(?:get|find|lookup|fetch|load|retrieve)[_\s\w.]*authorization[_]?code|getAuthorizationCode|findAuthorizationCode|getByCode|authorization[_]?codes?\s*\[[^\]]+\]|where\s+code\s*=|from\s+\w*codes?\b|codes?\.get\(|codes?\.find", re.I)
B_INVALIDATE  = re.compile(
    r"delete[_\s]+\w*code|del\s+\w*code|delete\s+from\s+\w*codes?\b"
    r"|revoke\w*code|revokeCode|revoke_authorization|invalidate\w*code|invalidateCode"
    r"|mark[_]?used|markUsed|mark[_]?code[_]?used|consume\w*code|consumeCode|consume_authorization"
    r"|redeemed\s*[:=]\s*[Tt]rue|used\s*[:=]\s*[Tt]rue|is[_]?used\s*[:=]\s*[Tt]rue"
    r"|codes?\.(?:delete|remove|pop)\(|authorization[_]?codes?\.(?:delete|remove|pop)\("
    r"|(?:delete|remove|pop|del)\([^)\n]*\bcode\b|\.(?:delete|remove|pop)\([^)\n]*\bcode", re.I)
B_EXPIRY_FIELD = re.compile(r"expires?(_at|_in)?\b|\bexp\b|\bttl\b|expiry|valid[_-]?until|not[_-]?after", re.I)
B_CODE_CTX = re.compile(r"\bcode\b|authorization", re.I)
# B3 gating: the excessive number must govern an AUTHORIZATION CODE.
B_AUTHCODE_TTL_CTX = re.compile(r"auth(?:oriz\w*)?[_ ]?code|authorization_code|code[_]?ttl|code[_]?expir|code[_]?lifetime|codes?\s*\[|store[_]?auth\w*code|create[_]?auth\w*code|issue\w*code", re.I)
# strong signal that THIS is explicitly an auth-code TTL (overrides the exclusion)
B_AUTHCODE_STRONG = re.compile(r"authorization_code|auth[_]?code[_]?(?:ttl|expir|lifetime|max_?age)|code[_]?ttl|oauth:code|code:\{|:code:|setex\([^)]*code", re.I)
# access/refresh/session/id-token lifetimes: 3600-class values here are NORMAL, not B3
B_OTHER_TOKEN_TTL = re.compile(r"access[_]?token|refresh[_]?token|id[_]?token|session|jwt|bearer|expires_in|cookie|max_?age", re.I)
B_TTL_PATTERNS = [
    (re.compile(r"timedelta\(\s*days\s*=\s*(\d+)", re.I), 86400),
    (re.compile(r"timedelta\(\s*hours\s*=\s*(\d+)", re.I), 3600),
    (re.compile(r"(\d+)\s*\*\s*86400"), 86400),
    (re.compile(r"(\d+)\s*\*\s*3600"), 3600),
]
B_BIG_INT_TTL = re.compile(r"(expires?_in|\bttl\b|code[_-]?ttl|code[_-]?lifetime|auth\w*code\w*(?:ttl|expir|lifetime)|expiry)\s*[:=]\s*(\d{3,})", re.I)
# Lines where a 3600/86400/etc. is definitely NOT an auth-code TTL.
B_B3_HARD_EXCLUDE = re.compile(r"cache-control|max-age|max_age|s-maxage|stale-while|expires:|\*\s*3600|3600\s*\*|\*\s*86400|86400\s*\*|\*\s*1000|CORS|Access-Control", re.I)
B_KNOWN_SECS = (31536000, 2592000, 604800)
B_RFC_MAX = 600

def _b_ttl_seconds(line):
    for rx, mult in B_TTL_PATTERNS:
        m = rx.search(line)
        if m:
            try: return int(m.group(1)) * mult
            except (IndexError, ValueError): pass
    m = B_BIG_INT_TTL.search(line)
    if m:
        try: return int(m.group(2))
        except ValueError: pass
    for c in B_KNOWN_SECS:
        if re.search(r"\b%d\b" % c, line): return c
    return None

def rule_pkce_not_enforced(path, text, F):
    if not B_OAUTH_HINT.search(text):
        return
    # B1a: PKCE explicitly skipped (definitive -> HIGH/error)
    for m in B_SKIP_PKCE.finditer(text):
        add(F, "B1", "HIGH", "PKCE validation explicitly disabled",
            path, text, m.start(),
            "skipLocalPkceValidation=true with no local verifier check taking over",
            "VATA:webrix skipLocalPkceValidation", "HIGH")
    # B1c: PKCE downgradeable to 'plain' (CVE-2025-4144 class). With method 'plain',
    # challenge == verifier, so anyone who observes the authorize request can replay it;
    # OAuth 2.1 requires S256. Defaulting/falling back to 'plain' is the downgrade.
    for m in B_PKCE_PLAIN_DEFAULT.finditer(text):
        add(F, "B1", "HIGH", "PKCE downgradeable to 'plain' method",
            path, text, m.start(),
            "code_challenge_method defaults/falls back to 'plain'; plain PKCE has "
            "challenge==verifier and is bypassable by anyone who sees the authorize request",
            "VATA:cloudflare CVE-2025-4144 PKCE plain downgrade", "HIGH")
    # B1b: verifier received as input but never hashed (AS-gated -> MEDIUM/warning)
    if _b_is_authz_server(text) and not B_PKCE_HASH.search(text):
        for m in B_VERIFIER.finditer(text):
            ls = text.rfind("\n", 0, m.start()) + 1
            le = text.find("\n", m.start());  le = len(text) if le < 0 else le
            line = text[ls:le]
            if B_GEN_VERIFIER.search(line) or not B_RECV_HINT.search(line):
                continue
            # Client generating a verifier is not an authorization server failing to check one.
            if re.search(r"generate_code_verifier|compute_code_challenge|code_challenge\s*=", text):
                if not re.search(r"request\.(?:form|json|body)|req\.(?:body|query)|code_verifier\s*=\s*request", text):
                    continue
            add(F, "B1", "MEDIUM", "PKCE code_verifier received but never validated",
                path, text, m.start(),
                "code_verifier received as input; no SHA-256/S256 transform in this file",
                "VATA:atrawog/webrix verifier-never-hashed", "MEDIUM")
            break
    # B3: explicit excessive authorization-code TTL (definitive number -> HIGH/error)
    for m in B_BIG_INT_TTL.finditer(text):
        pass  # covered by line loop below for context gating
    for mline in re.finditer(r"[^\n]*\n?", text):
        line = mline.group(0)
        if not line.strip():
            continue
        if B_B3_HARD_EXCLUDE.search(line):
            continue
        secs = _b_ttl_seconds(line)
        if secs is None or secs <= B_RFC_MAX:
            continue
        ctx = text[max(0, mline.start()-240):mline.start()+240]
        # Must be tied to an AUTHORIZATION CODE specifically, not generic OAuth
        # context. 3600 etc. is the usual access-token lifetime; only fire when the
        # vicinity names an auth code and does NOT read as access/refresh/session TTL.
        if not B_AUTHCODE_STRONG.search(ctx):
            continue
        if B_OTHER_TOKEN_TTL.search(ctx) and not B_AUTHCODE_STRONG.search(ctx):
            continue
        add(F, "B3", "MEDIUM", f"Large TTL ~{secs}s near auth-code context \u2014 verify it governs the authorization code (RFC 6749 ~600s)",
            path, text, mline.start(),
            f"TTL {secs}s within auth-code context; confirm it is the authorization-code lifetime and not an access/refresh-token TTL (RFC 6749 4.1.2 recommends <=600s)",
            "VATA:atrawog 1-year auth-code TTL (review-list)", "LOW")

def rule_authcode_replay(path, text, F):
    # B2 same-file: redeem path present, no invalidation in THIS file. MEDIUM/warning
    # + review note, because true single-use may be enforced in a separate storage file.
    if not B_OAUTH_HINT.search(text) or not _b_is_authz_server(text):
        return
    if not (B_GRANT_AC.search(text) or B_REDEEM_FUNC.search(text)):
        return
    rm = B_REDEEM_FUNC.search(text) or B_LOOKUP_CODE.search(text)
    if rm is None:
        return
    if B_INVALIDATE.search(text):
        return  # something in this file invalidates a code -> not a same-file replay
    add(F, "B2", "MEDIUM", "Authorization code redeemed but never invalidated (same-file)",
        path, text, rm.start(),
        "code redeemed/looked up here; no delete/mark-used/revoke in this file -- confirm storage layer before filing",
        "VATA:webrix auth-code replay", "MEDIUM")

# ---- Rule A7: cross-tenant unscoped list (seed: metamcp, CWE-863) ----
# Unscoped list on a repo that ALSO exposes a tenant-scoped sibling, reached from a
# request/auth handler -> cross-tenant read. Needs repo-wide context (SCOPED_REPOS).
SCOPED_REPOS = set()
A7_SCOPED_CALL = re.compile(
    r"(\w*(?:[Rr]epository|[Rr]epo|[Ss]tore|[Dd]ao))\."
    r"(?:findAllAccessibleTo\w*|findAccessibleTo\w*|listAccessibleTo\w*|"
    r"findVisibleTo\w*|visibleTo\w*|\w*ScopedTo\w*|findAllForUser\w*)\s*\(", re.I)
A7_UNSCOPED_LIST = re.compile(
    r"(\w*(?:[Rr]epository|[Rr]epo|[Ss]tore|[Dd]ao))\."
    r"(findAll|listAll|getAll|findMany|list)\s*\(\s*\)")
A7_BOOT_PATH = re.compile(
    r"(startup|bootstrap|seed|migrat|/cli|scripts?/|/bin/|(^|/)main\.|(^|/)index\.)", re.I)
A7_REQ_CTX = re.compile(
    r"(routers?/|controllers?/|handlers?/|req\.|request\.|res\.|ctx\.|"
    r"userId|user_id|session|getServerSession|currentUser|current_user|principal)", re.I)

def rule_cross_tenant_list(path, text, F):
    if not SCOPED_REPOS:
        return
    ppath = path.as_posix()
    if A7_BOOT_PATH.search(ppath):
        return
    for m in A7_UNSCOPED_LIST.finditer(text):
        repo = m.group(1)
        if repo not in SCOPED_REPOS:
            continue
        window = text[max(0, m.start() - 400):m.start() + 160]
        if not (A7_REQ_CTX.search(ppath) or A7_REQ_CTX.search(window)):
            continue
        add(F, "A7", "HIGH",
            f"Unscoped {repo}.{m.group(2)}() in a handler; a tenant-scoped sibling exists",
            path, text, m.start(),
            f"{repo} exposes a *AccessibleTo* method but this handler calls the "
            f"unscoped {m.group(2)}() - cross-tenant read (CWE-863)",
            "VATA:metamcp cross-tenant unscoped list", "MEDIUM")

# ---- Rule A10: MCP server on a network transport with auth None by default ----
# Seed: startreedata/mcp-pinot GHSA-73cv - FastMCP(auth=_auth) where _auth stays None
# unless oauth_enabled (default False); transport defaults http on 0.0.0.0. VATA class A
# (fail-open / disabled-by-default). External ground truth (reporter: GitHub advisory).
A10_FASTMCP   = re.compile(r"\bFastMCP\s*\(", re.I)
A10_NET       = re.compile(r"(0\.0\.0\.0|uvicorn\.run|transport\s*[:=]\s*['\"](?:http|sse|streamable[-_]?http)['\"]|\.run\([^)]*transport\s*=\s*['\"](?:http|sse|streamable))", re.I)
A10_AUTH_NONE = re.compile(r"FastMCP\s*\([^)]*\bauth\s*=\s*None\b", re.I)
A10_AUTH_VAR  = re.compile(r"FastMCP\s*\([^)]*\bauth\s*=\s*([A-Za-z_]\w*)")

def rule_fastmcp_auth_default(path, text, F):
    if not A10_FASTMCP.search(text) or not A10_NET.search(text):
        return  # not a FastMCP server, or not network-exposed (stdio-only is not this bug)
    hit = A10_AUTH_NONE.search(text)
    if not hit:
        mv = A10_AUTH_VAR.search(text)
        if not (mv and mv.group(1).lower() != "none"
                and re.search(r"\b" + re.escape(mv.group(1)) + r"\s*=\s*None\b", text)):
            return  # auth is a real provider, not a None-defaulting var
        hit = mv
    add(F, "A10", "HIGH",
        "FastMCP network server with auth None by default",
        path, text, hit.start(),
        "FastMCP on an http/sse transport with auth=None (or an auth var that defaults to "
        "None unless an opt-in flag is set) - unauthenticated by default (class A)",
        "VATA:mcp-pinot GHSA-73cv auth-disabled-by-default", "MEDIUM")


DEP_NAMES = {"requirements.txt", "requirements-dev.txt", "pyproject.toml", "setup.cfg", "Pipfile", "package.json"}

def _ver_tuple(s):
    nums = re.findall(r"\d+", s)
    if not nums:
        return None
    vt = tuple(int(n) for n in nums[:3])
    return vt + (0,) * (3 - len(vt))

def _in_advisory(vt):
    if not vt:
        return False
    if vt[0] == 1 and (1, 9, 1) <= vt < (1, 30, 0):
        return True
    if vt[0] == 2 and vt < (2, 2, 0):
        return True
    return False

def _overlaps(low, high):
    """True if [low, high) can install a GHSA-qx49-fqc8-xw99 version."""
    if low is None:
        low = (0, 0, 0)
    if high is None:
        high = (99, 0, 0)
    for a, b in (((1, 9, 1), (1, 30, 0)), ((2, 0, 0), (2, 2, 0))):
        if low < b and a < high:
            return True
    return False

def _mcp_vulnerable(spec):
    spec = spec.strip().strip("\"'")
    parts = [p.strip() for p in spec.split(",") if p.strip()]
    low = high = None
    for p in parts:
        m = re.match(r"(?:==|===)\s*(.+)", p)
        if m:
            return _in_advisory(_ver_tuple(m.group(1)))
        m = re.match(r"~=\s*(.+)", p)
        if m:
            vt = _ver_tuple(m.group(1))
            if not vt:
                return False
            upper = (vt[0], vt[1] + 1, 0) if len(vt) >= 2 else (vt[0] + 1, 0, 0)
            return _overlaps(vt, upper)
        m = re.match(r">=\s*(.+)", p)
        if m:
            low = _ver_tuple(m.group(1))
        m = re.match(r">\s*(.+)", p)
        if m and _ver_tuple(m.group(1)):
            vt = _ver_tuple(m.group(1))
            low = vt[:-1] + (vt[-1] + 1,)
        m = re.match(r"<\s*(.+)", p)
        if m:
            high = _ver_tuple(m.group(1))
        m = re.match(r"<=\s*(.+)", p)
        if m and _ver_tuple(m.group(1)):
            vt = _ver_tuple(m.group(1))
            high = vt[:-1] + (vt[-1] + 1,)
    if low is None and high is None:
        return False
    return _overlaps(low, high)

def _npm_vulnerable(name, spec):
    spec = spec.strip().strip("\"'")
    if spec.startswith("^"):
        low = _ver_tuple(spec[1:])
        if not low:
            return False
        high = (low[0] + 1, 0, 0)
        if name == "@modelcontextprotocol/sdk":
            return _overlaps(low, high) and low < (1, 31, 0)
        if name == "@modelcontextprotocol/client":
            return low < (2, 2, 0) and high > (2, 0, 0)
        return False
    vt = _ver_tuple(spec.lstrip("=v"))
    if not vt:
        return False
    if name == "@modelcontextprotocol/sdk":
        return (1, 12, 0) <= vt < (1, 31, 0)
    if name == "@modelcontextprotocol/client":
        return (2, 0, 0) <= vt < (2, 2, 0)
    return False

def rule_mcp_sdk_version(path, text, F):
    if path.name == "package.json":
        for m in re.finditer(r'"(@modelcontextprotocol/(?:sdk|client))"\s*:\s*"([^"]+)"', text):
            if not _npm_vulnerable(m.group(1), m.group(2)):
                continue
            add(F, "D1", "HIGH",
                "MCP TypeScript SDK pin is inside GHSA-6qxp-vccf-f47h; upgrade sdk to 1.31.0 or client to 2.2.0 and set expectedIssuer",
                path, text, m.start(), m.group(0)[:80],
                "GHSA-6qxp-vccf-f47h", "HIGH")
        return

    if path.name not in DEP_NAMES and not path.name.startswith("requirements"):
        return
    for m in re.finditer(r"(?m)^\s*(?:[\"']|)mcp(?:\[[^\]]*\])?\s*([=~<>!]+[^\s#\"']+)", text):
        spec = m.group(1)
        if not _mcp_vulnerable(spec):
            continue
        add(F, "D1", "HIGH",
            "mcp SDK pin is inside GHSA-qx49-fqc8-xw99; upgrade to 1.30.0 or 2.2.0 and set issuer=",
            path, text, m.start(), m.group(0)[:80],
            "GHSA-qx49-fqc8-xw99", "HIGH")

RULES = [rule_oauth_authorize, rule_default_creds, rule_middleware_authz,
         rule_ssrf, rule_excluded_tools, rule_method_scoped_authz,
         rule_client_issuer_binding,
         rule_pkce_not_enforced, rule_authcode_replay,
         rule_cross_tenant_list, rule_fastmcp_auth_default, rule_mcp_sdk_version]

def scan(root, include_tests, exclude=()):
    global SCOPED_REPOS
    docs = []
    for path in iter_files(root, include_tests, exclude):
        try:
            docs.append((path, path.read_text(errors="ignore")))
        except Exception:
            continue
    rootp = Path(root)
    excl = [(rootp / e).resolve() for e in exclude]
    for path in rootp.rglob("*"):
        if not path.is_file():
            continue
        if path.name not in DEP_NAMES and not path.name.startswith("requirements"):
            continue
        if any(s in path.parts for s in SKIP_DIR):
            continue
        rp = path.resolve()
        if any(rp == e or e in rp.parents for e in excl):
            continue
        try:
            docs.append((path, path.read_text(errors="ignore")))
        except Exception:
            continue
    SCOPED_REPOS = set()
    for _, text in docs:
        for m in A7_SCOPED_CALL.finditer(text):
            SCOPED_REPOS.add(m.group(1))
    F = []
    for path, text in docs:
        for r in RULES:
            r(path, text, F)
    return F

def main():
    ap = argparse.ArgumentParser(description=f"VATA mcp_authscan v{VERSION}")
    ap.add_argument("target", help="path to MCP server repo/dir")
    ap.add_argument("--json", action="store_true", help="emit JSON + report sha256")
    ap.add_argument("--sarif", action="store_true", help="emit SARIF 2.1.0 (GitHub code scanning)")
    ap.add_argument("--include-tests", action="store_true", help="also scan test files")
    ap.add_argument("--exclude", action="append", default=[], metavar="DIR",
                    help="skip a directory relative to target (repeatable)")
    ap.add_argument("--fail-on", choices=["critical", "high", "medium"], default=None)
    args = ap.parse_args()

    F = scan(args.target, args.include_tests, args.exclude)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    F.sort(key=lambda x: (order.get(x["severity"], 9), x["file"], x["line"]))

    if args.sarif:
        print(json.dumps(to_sarif(F, args.target), indent=2))
    elif args.json:
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

    # Review-list rules warn only. They must not fail CI.
    REVIEW = {"A4", "A5", "A6", "B2"}
    if args.fail_on:
        thr = {"critical": 0, "high": 1, "medium": 2}[args.fail_on]
        if any(order.get(x["severity"], 9) <= thr and x["rule"] not in REVIEW for x in F):
            sys.exit(1)

if __name__ == "__main__":
    main()
