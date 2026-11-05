"""field_issuer_echo.py -- server-side issuer-echo observation across MCP deployments.

For each MCP endpoint, does the authorization-server metadata it advertises name an
issuer identical to the URL that metadata was served from (RFC 8414 section 3.3)?

GET only. Never sends credentials, never calls token/register/authorize, never sends
an Authorization header. If metadata needs a credential, the endpoint is recorded as
not observed and skipped. This module does not import the scan path; no probe set moves.

METHOD_VERSION is this module's own observation method, separate from any probe set.
"""
import argparse
import hashlib
import http.server
import json
import os
import socket
import sys
import threading
import time
from urllib.parse import urlsplit, urlunsplit, urljoin

import requests

METHOD_VERSION = "issuer-echo/1.0.0"
USER_AGENT = "mcp-authscan field_issuer_echo (+https://github.com/LHMisme420/mcp-authscan)"
PER_HOST_CAP = 3
MIN_DELAY = 1.0
TIMEOUT = 10.0

ANSWERED_STATUSES = {200, 400, 401, 405, 406}


# ---------------------------------------------------------------------------
# comparison logic (RFC 8414 section 3.3, with the one trailing-slash tolerance)
# ---------------------------------------------------------------------------
def _norm_trailing(path):
    # tolerate exactly one trailing slash on the path
    if path.endswith("/") and len(path) > 1:
        return path[:-1]
    return path


def compare_issuer(advertised_issuer, as_identifier_url):
    """Return (verdict, reason). Verdicts: MATCH, MISMATCH, UNCLEAR.

    as_identifier_url is the authorization-server identifier (the base the well-known URL
    was built from), per RFC 8414 3.3 -- never the well-known URL itself.

    MISMATCH only when the issuer parses as an absolute URL whose origin differs from
    the fetch origin, or whose path differs beyond a lone trailing slash. Anything
    softer (not an absolute URL, scheme missing, bare hostname) is UNCLEAR, never a
    mismatch, with the reason recorded verbatim.
    """
    if advertised_issuer is None:
        return "UNCLEAR", "metadata carried no issuer field"
    if not isinstance(advertised_issuer, str) or not advertised_issuer.strip():
        return "UNCLEAR", "issuer is not a non-empty string: %r" % (advertised_issuer,)

    iss = advertised_issuer.strip()
    ip = urlsplit(iss)
    fp = urlsplit(as_identifier_url)

    # must be an absolute URL: scheme + netloc both present. A bare hostname
    # ("example.com") or a scheme-relative value is UNCLEAR, not a mismatch.
    if not ip.scheme or not ip.netloc:
        return "UNCLEAR", "issuer is not an absolute URL (scheme/host missing): %r" % (iss,)
    if ip.scheme.lower() not in ("http", "https"):
        return "UNCLEAR", "issuer scheme is not http(s): %r" % (iss,)

    iss_origin = (ip.scheme.lower(), ip.hostname or "", ip.port)
    fetch_origin = (fp.scheme.lower(), fp.hostname or "", fp.port)

    if iss_origin != fetch_origin:
        return "MISMATCH", "issuer origin %s differs from fetch origin %s" % (
            "%s://%s%s" % (ip.scheme, ip.netloc, ""), "%s://%s" % (fp.scheme, fp.netloc))

    if _norm_trailing(ip.path) != _norm_trailing(fp.path):
        return "MISMATCH", "issuer path %r differs from fetch path %r beyond a trailing slash" % (
            ip.path, fp.path)

    return "MATCH", "issuer equals fetch URL (trailing slash tolerated)"


# ---------------------------------------------------------------------------
# HTTP with base-URL override: rewrite ORIGIN ONLY, never path/query
# ---------------------------------------------------------------------------
class Fetcher:
    def __init__(self, base_override=None, timeout=TIMEOUT, delay=MIN_DELAY):
        # base_override: if set, every request's scheme+netloc is replaced with it,
        # so the fixture is driven through the identical request path as a live fetch.
        self.base_override = base_override
        self.timeout = timeout
        self.delay = delay
        self.host_counts = {}
        self.host_last = {}
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})

    def _effective(self, url):
        if not self.base_override:
            return url
        ov = urlsplit(self.base_override)
        p = urlsplit(url)
        return urlunsplit((ov.scheme, ov.netloc, p.path, p.query, p.fragment))

    def _host_of(self, url):
        return (urlsplit(url).hostname or "").lower()

    def get(self, url):
        """GET with per-host cap and spacing. Returns a dict, never raises for HTTP.
        keys: ok(bool), status, headers(dict), text, json(or None), error, capped, aborted
        """
        host = self._host_of(url)
        if self.host_counts.get(host, 0) >= PER_HOST_CAP:
            return {"ok": False, "capped": True, "error": "per-host request cap reached"}
        last = self.host_last.get(host)
        if last is not None:
            wait = self.delay - (time.monotonic() - last)
            if wait > 0:
                time.sleep(wait)
        eff = self._effective(url)
        self.host_counts[host] = self.host_counts.get(host, 0) + 1
        try:
            # GET only; no Authorization header is ever added
            r = self.session.get(eff, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException as e:
            self.host_last[host] = time.monotonic()
            return {"ok": False, "error": "%s: %s" % (type(e).__name__, e)}
        self.host_last[host] = time.monotonic()
        aborted = r.status_code == 429 or r.status_code >= 500
        body = None
        ctype = r.headers.get("Content-Type", "")
        if "json" in ctype.lower():
            try:
                body = r.json()
            except ValueError:
                body = None
        return {"ok": True, "status": r.status_code, "headers": dict(r.headers),
                "text": r.text[:4000], "json": body, "aborted": aborted}


# ---------------------------------------------------------------------------
# discovery chain
# ---------------------------------------------------------------------------
def _parse_resource_metadata_pointer(www_auth):
    # WWW-Authenticate: Bearer resource_metadata="https://.../.well-known/..."
    if not www_auth:
        return None
    marker = 'resource_metadata="'
    i = www_auth.find(marker)
    if i == -1:
        return None
    j = www_auth.find('"', i + len(marker))
    if j == -1:
        return None
    return www_auth[i + len(marker):j]


def _origin(url):
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, "", "", ""))


def observe_endpoint(url, fetcher, declares_auth):
    rec = {
        "endpoint": url,
        "declares_auth_hint": declares_auth,
        "mcp_status": None,
        "mcp_status_class": None,
        "resource_metadata_url": None,
        "authorization_servers": [],
        "auth_server_fetch_url": None,
        "advertised_issuer": None,
        "verdict": None,
        "reason": None,
    }

    # 1. GET the MCP URL, no auth
    r = fetcher.get(url)
    if not r.get("ok"):
        rec["verdict"] = "UNREACHABLE"
        rec["reason"] = r.get("error", "no response")
        if r.get("capped"):
            rec["reason"] = "per-host cap reached before MCP GET"
        return rec
    if r.get("aborted"):
        rec["mcp_status"] = r["status"]
        rec["verdict"] = "UNREACHABLE"
        rec["reason"] = "aborted host on %d" % r["status"]
        return rec
    status = r["status"]
    rec["mcp_status"] = status
    if status not in ANSWERED_STATUSES:
        rec["verdict"] = "UNREACHABLE"
        rec["reason"] = "unexpected status %d" % status
        return rec
    rec["mcp_status_class"] = {
        200: "200", 400: "400-jsonrpc", 401: "401-www-authenticate",
        405: "405", 406: "406"}[status]

    # 2. resolve protected-resource metadata
    pr_url = None
    if status == 401:
        pr_url = _parse_resource_metadata_pointer(r["headers"].get("WWW-Authenticate"))
    if not pr_url:
        pr_url = urljoin(_origin(url) + "/", ".well-known/oauth-protected-resource")
    rec["resource_metadata_url"] = pr_url

    pr = fetcher.get(pr_url)
    if not pr.get("ok") or pr.get("aborted"):
        rec["verdict"] = "NO_METADATA"
        rec["reason"] = "protected-resource metadata not fetchable: %s" % (
            pr.get("error") or ("aborted on %s" % pr.get("status")))
        return rec
    if pr.get("status") != 200 or not isinstance(pr.get("json"), dict):
        rec["verdict"] = "NO_METADATA"
        rec["reason"] = "protected-resource metadata status %s, not a JSON object" % pr.get("status")
        return rec
    auth_servers = pr["json"].get("authorization_servers") or []
    if not isinstance(auth_servers, list) or not auth_servers:
        rec["verdict"] = "NO_METADATA"
        rec["reason"] = "no authorization_servers in protected-resource metadata"
        return rec
    rec["authorization_servers"] = auth_servers

    # 3. for each AS, GET /.well-known/oauth-authorization-server; first decisive wins
    last_reason = None
    for as_url in auth_servers:
        as_well_known = urljoin(as_url.rstrip("/") + "/", ".well-known/oauth-authorization-server")
        asr = fetcher.get(as_well_known)
        if not asr.get("ok") or asr.get("aborted"):
            last_reason = "AS metadata not fetchable: %s" % (
                asr.get("error") or ("aborted on %s" % asr.get("status")))
            continue
        if asr.get("status") != 200 or not isinstance(asr.get("json"), dict):
            last_reason = "AS metadata status %s, not a JSON object" % asr.get("status")
            continue
        issuer = asr["json"].get("issuer")
        rec["auth_server_fetch_url"] = as_well_known
        rec["advertised_issuer"] = issuer
        # 4 + 5. RFC 8414 3.3: the issuer must equal the authorization-server identifier
        # (as_url) that the well-known URL was built from, NOT the well-known URL itself.
        verdict, reason = compare_issuer(issuer, as_url)
        rec["verdict"] = verdict
        rec["reason"] = reason
        return rec

    rec["verdict"] = "NO_METADATA"
    rec["reason"] = last_reason or "no authorization-server metadata reached"
    return rec


# ---------------------------------------------------------------------------
# input loading
# ---------------------------------------------------------------------------
def load_inputs(path):
    """Returns list of (source_name, url). A file -> source is its basename; a dir ->
    one source per file. Reads local files only. Each line may be a bare URL, or JSON
    carrying a url and an optional auth hint; bare URLs declare no auth hint."""
    items = []
    if os.path.isdir(path):
        files = [os.path.join(path, f) for f in sorted(os.listdir(path))
                 if os.path.isfile(os.path.join(path, f))]
    else:
        files = [path]
    for fp in files:
        source = os.path.basename(fp)
        with open(fp, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                declares_auth = False
                url = line
                namespace = ""
                server_name = ""
                if line.startswith("{"):
                    try:
                        obj = json.loads(line)
                        url = obj.get("url")
                        namespace = obj.get("namespace", "") or ""
                        server_name = obj.get("server_name", "") or ""
                        hdrs = obj.get("headers") or []
                        declares_auth = any(
                            (h.get("name", "").lower() == "authorization") for h in hdrs
                            if isinstance(h, dict))
                    except (ValueError, AttributeError):
                        continue
                if not url:
                    continue
                items.append((source, url, declares_auth, namespace, server_name))
    return items


def file_hash(path):
    h = hashlib.sha256()
    if os.path.isdir(path):
        for f in sorted(os.listdir(path)):
            fp = os.path.join(path, f)
            if os.path.isfile(fp):
                with open(fp, "rb") as fh:
                    h.update(fh.read())
    else:
        with open(path, "rb") as fh:
            h.update(fh.read())
    return h.hexdigest()


# ---------------------------------------------------------------------------
# fixture: three canned documents served by a stdlib server, driven through the
# SAME request path via base-URL override
# ---------------------------------------------------------------------------
FIXTURE_DOCS = {
    # case -> (issuer value the AS metadata advertises)
    "matching": None,       # filled with the server's own origin at runtime
    "foreign": "https://somewhere-else.invalid",
    "bare-host": "not-a-url-just-a-host",
    "nested-base": "MATCH-nested",  # issuer == AS base, well-known served one path deeper
}


class _FixtureHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, code, payload):
        b = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        s = self.server
        base = s.base_url
        case = s.case
        if self.path.startswith("/mcp"):
            self.send_response(401)
            self.send_header("WWW-Authenticate",
                             'Bearer resource_metadata="%s/.well-known/oauth-protected-resource"' % base)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path.startswith("/.well-known/oauth-protected-resource"):
            as_base = base + "/auth/v1" if case == "nested-base" else base
            return self._json(200, {"resource": base + "/mcp", "authorization_servers": [as_base]})
        if self.path.endswith("/.well-known/oauth-authorization-server"):
            if case == "matching":
                issuer = base
            elif case == "nested-base":
                issuer = base + "/auth/v1"   # equals the AS base, well-known is one level deeper
            else:
                issuer = FIXTURE_DOCS[case]
            return self._json(200, {
                "issuer": issuer,
                "authorization_endpoint": base + "/authorize",
                "token_endpoint": base + "/token",
            })
        self._json(404, {"error": "not_found"})

    def do_POST(self):
        # the check is GET-only; a POST here means the check misbehaved
        self._json(500, {"error": "fixture received a POST; check must be GET-only"})


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _start_fixture(case):
    port = _free_port()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), _FixtureHandler)
    srv.base_url = "http://127.0.0.1:%d" % port
    srv.case = case
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def run_fixture(delay):
    results = []
    for case in ("matching", "foreign", "bare-host", "nested-base"):
        srv = _start_fixture(case)
        try:
            # the endpoint URL uses a placeholder origin; the override points every
            # request at the fixture, so the check runs its real path against canned docs
            fetcher = Fetcher(base_override=srv.base_url, timeout=TIMEOUT, delay=delay)
            rec = observe_endpoint("http://placeholder.invalid/mcp", fetcher, declares_auth=False)
            rec["fixture_case"] = case
            results.append(rec)
        finally:
            srv.shutdown()
            srv.server_close()
    return results


# ---------------------------------------------------------------------------
# summary (counts only, no hostnames)
# ---------------------------------------------------------------------------
def build_summary(records, per_source_counts, input_path):
    verdicts = {}
    answered = advertising = reached = 0
    for r in records:
        v = r.get("verdict")
        verdicts[v] = verdicts.get(v, 0) + 1
        if r.get("mcp_status") in ANSWERED_STATUSES:
            answered += 1
        if r.get("resource_metadata_url"):
            advertising += 1
        if r.get("auth_server_fetch_url"):
            reached += 1
    return {
        "method_version": METHOD_VERSION,
        "run_timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "input_sha256": file_hash(input_path) if input_path and os.path.exists(input_path) else None,
        "python_version": sys.version.split()[0],
        "requests_version": requests.__version__,
        "endpoints_attempted": len(records),
        "endpoints_answered": answered,
        "endpoints_advertising_discovery": advertising,
        "endpoints_reached_metadata": reached,
        "verdicts": {
            "MATCH": verdicts.get("MATCH", 0),
            "MISMATCH": verdicts.get("MISMATCH", 0),
            "UNCLEAR": verdicts.get("UNCLEAR", 0),
            "NO_METADATA": verdicts.get("NO_METADATA", 0),
            "UNREACHABLE": verdicts.get("UNREACHABLE", 0),
        },
        "per_source_url_counts": per_source_counts,
    }


# ---------------------------------------------------------------------------
# registry fetch (optional) -- walks cursor, dedupes by host, isLatest only
# ---------------------------------------------------------------------------
def fetch_registry(out_path, limit=None):
    base = "https://registry.modelcontextprotocol.io/v0/servers"
    sess = requests.Session()
    sess.headers.update({"User-Agent": USER_AGENT})
    seen_hosts = set()
    urls = []
    cursor = None
    pages = 0
    while True:
        params = {"limit": 100}
        if cursor:
            params["cursor"] = cursor
        r = sess.get(base, params=params, timeout=TIMEOUT)
        r.raise_for_status()
        doc = r.json()
        for item in doc.get("servers", []):
            meta = item.get("_meta", {}) or {}
            official = meta.get("io.modelcontextprotocol.registry/official", {}) or {}
            if not official.get("isLatest"):   # dotted key indexed as a string, never attribute access
                continue
            server = item.get("server", {}) or {}
            for remote in (server.get("remotes") or []):
                u = remote.get("url")
                if not u:
                    continue
                host = (urlsplit(u).hostname or "").lower()
                if host and host not in seen_hosts:
                    seen_hosts.add(host)
                    name = server.get("name", "") or ""
                    ns = name.split("/")[0] if name else ""
                    hdrs = remote.get("headers") or []
                    declares = any(isinstance(h, dict) and h.get("name", "").lower() == "authorization"
                                   for h in hdrs)
                    urls.append(json.dumps({"url": u, "namespace": ns, "server_name": name,
                                            "headers": [{"name": "Authorization"}] if declares else []}))
                    if limit and len(urls) >= limit:
                        break
            if limit and len(urls) >= limit:
                break
        pages += 1
        cursor = (doc.get("metadata") or {}).get("nextCursor")
        if not cursor or (limit and len(urls) >= limit):
            break
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(urls) + ("\n" if urls else ""))
    return len(urls), pages


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Server-side issuer-echo observation (GET only).")
    ap.add_argument("--input", help="text file of URLs (one per line) or a directory of them")
    ap.add_argument("--out", default="issuer_echo_records.jsonl", help="per-endpoint JSONL output")
    ap.add_argument("--summary", default="issuer_echo_summary.json", help="counts-only summary output")
    ap.add_argument("--limit", type=int, default=None, help="cap number of endpoints")
    ap.add_argument("--timeout", type=float, default=TIMEOUT)
    ap.add_argument("--delay", type=float, default=MIN_DELAY, help="min seconds between requests to a host")
    ap.add_argument("--fixture", action="store_true", help="run three local fixtures end to end")
    ap.add_argument("--fetch-registry", metavar="OUTFILE",
                    help="walk the MCP registry (isLatest, dedupe by host) and write a URL list, then exit")
    args = ap.parse_args()

    if args.fetch_registry:
        try:
            n, pages = fetch_registry(args.fetch_registry, limit=args.limit)
        except requests.RequestException as e:
            print("fatal: registry fetch failed: %s" % e, file=sys.stderr)
            return 2
        print("wrote %d deduped hosts across %d page(s) to %s" % (n, pages, args.fetch_registry))
        return 0

    if args.fixture:
        records = run_fixture(args.delay)
        with open(args.out, "w", encoding="utf-8") as fh:
            for r in records:
                fh.write(json.dumps(r) + "\n")
        summary = build_summary(records, {"fixture": len(records)}, None)
        with open(args.summary, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2)
        for r in records:
            print("%-9s -> %-11s  %s" % (r["fixture_case"], r["verdict"], r["reason"]))
        return 0

    if not args.input:
        print("fatal: --input required (or use --fixture / --fetch-registry)", file=sys.stderr)
        return 2
    try:
        items = load_inputs(args.input)
    except OSError as e:
        print("fatal: cannot read input: %s" % e, file=sys.stderr)
        return 2
    if args.limit:
        items = items[:args.limit]

    fetcher = Fetcher(base_override=None, timeout=args.timeout, delay=args.delay)
    per_source = {}
    records = []
    with open(args.out, "w", encoding="utf-8") as fh:
        for source, url, declares_auth, namespace, server_name in items:
            per_source[source] = per_source.get(source, 0) + 1
            rec = observe_endpoint(url, fetcher, declares_auth)
            rec["source"] = source
            rec["namespace"] = namespace
            rec["server_name"] = server_name
            records.append(rec)
            fh.write(json.dumps(rec) + "\n")
    summary = build_summary(records, per_source, args.input)
    with open(args.summary, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    print("wrote %d records to %s, summary to %s" % (len(records), args.out, args.summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
