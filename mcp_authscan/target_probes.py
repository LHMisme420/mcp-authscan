"""Target-level probes: properties testable on an MCP endpoint with no authorization server."""

import json

from urllib.request import Request

from ._common import record
from .oauth_probes_v2 import _egress_guard
from .errors import EgressRefusalError

CORS_PROBE_ID = 13
PROBE_ORIGIN = "https://probe.invalid"


def _initialize_request(url):
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "mcp-authscan", "version": "1"},
        },
    }
    req = Request(url, data=json.dumps(payload).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json, text/event-stream")
    req.add_header("Origin", PROBE_ORIGIN)
    return req


def _is_block_page(status,raw): t=raw.decode('utf-8','ignore') if isinstance(raw,(bytes,bytearray)) else (raw or ''); return status in (401,403) and any(m in t for m in ('cloudflare_error','browser_signature_banned','error_code','Error 10'))
def cors_probe(mcp_url, allowed_hosts=None, allow_private=None):
    name = "cross-origin read on the MCP endpoint"
    try:
        status, headers, raw = _egress_guard(
            _initialize_request(mcp_url),
            allow_private=allow_private,
            allowed_hosts=allowed_hosts,
        )
    except Exception as e:
        return record(CORS_PROBE_ID, name, "NOT_OBSERVED",
                      limitation="request failed: %s" % e, endpoint=mcp_url)

    acao = (headers.get("access-control-allow-origin") or "").strip()
    acac = (headers.get("access-control-allow-credentials") or "").strip().lower()

    if status in (404, 405) or status >= 500:
        return record(CORS_PROBE_ID, name, "NOT_OBSERVED", http_status=status,
                      headers=headers, body=raw,
                      limitation="HTTP %s does not demonstrate the endpoint CORS posture" % status,
                      endpoint=mcp_url)

    if _is_block_page(status,raw): return record(CORS_PROBE_ID,name,'EXCLUDED',http_status=status,headers=headers,body=raw,limitation='intermediary block page, CORS not observed',endpoint=mcp_url)
    wildcard = acao == "*"
    echoes = acao.lower() == PROBE_ORIGIN.lower()

    if wildcard or echoes:
        severity = "CRITICAL" if acac == "true" else "HIGH"
        detail = "ACAO %r on HTTP %s%s" % (acao, status,
                                           ", credentials allowed" if acac == "true" else "")
        return record(CORS_PROBE_ID, name, "FAIL", http_status=status, headers=headers,
                      body=raw, evidence="headers", detail=detail, severity=severity, endpoint=mcp_url)

    detail = "ACAO %r on HTTP %s" % (acao, status) if acao else "no Access-Control-Allow-Origin on HTTP %s" % status
    return record(CORS_PROBE_ID, name, "PASS", http_status=status, headers=headers,
                  body=raw, evidence="headers", detail=detail, endpoint=mcp_url)


def run_target_probes(target_url, allowed_hosts=None, allow_private=False, rate_limit_count=None, rate_limit_window=None):
    try:
        rec = cors_probe(target_url, allowed_hosts=allowed_hosts, allow_private=allow_private)
    except Exception as e:
        rec = record(CORS_PROBE_ID, "cross-origin read on the MCP endpoint", "NOT_OBSERVED", limitation=str(e), endpoint=target_url)
    rate_rec = rate_limit_probe(target_url, count=rate_limit_count, window=rate_limit_window, allowed_hosts=allowed_hosts, allow_private=allow_private)
    records = [rec, rate_rec]
    if rec.status != "FAIL":
        return records, []
    return records, [{
        "rule": "CORS-1",
        "owasp": None,
        "severity": rec.severity or "HIGH",
        "confidence": "HIGH",
        "title": rec.name,
        "file": target_url,
        "line": 0,
        "ref": "CORS-1",
        "evidence": rec.detail or "",
        "snippet": "",
        "is_live_finding": True,
        "request_method": "OPTIONS",
        "request_body": "",
        "response_status": rec.http_status or 0,
        "response_body": rec.body_excerpt or "",
        "response_preview": rec.body_excerpt or "",
        "interpretation": rec.detail or "Endpoint CORS policy permits credentialed cross-origin reads",
        "remediation": "Restrict Access-Control-Allow-Origin to the origins that need it and never pair a wildcard with credentials",
    }]


def counts(records):
    c = {}
    for r in records:
        c[r.status] = c.get(r.status, 0) + 1
    return {
        "attempted": len(records) - c.get("EXCLUDED", 0) - c.get("NOT_IMPLEMENTED", 0),
        "passed": c.get("PASS", 0),
        "failed": c.get("FAIL", 0),
        "not_observed": c.get("NOT_OBSERVED", 0),
        "excluded": c.get("EXCLUDED", 0),
        "observation": 0,
        "not_implemented": c.get("NOT_IMPLEMENTED", 0),
    }
RATE_LIMIT_PROBE_ID = 14


def rate_limit_probe(url, count=None, window=None, allowed_hosts=None,
                     allow_private=None):
    name = "rate limiting on the endpoint"
    if not count or not window or count < 1 or window < 1:
        return record(RATE_LIMIT_PROBE_ID, name, "EXCLUDED",
                      limitation="no authorised request budget supplied, so no request was sent",
                      endpoint=url)

    sent = 0
    last_status = None
    for i in range(1, count + 1):
        if sent >= count:
            break
        try:
            status, headers, raw = _egress_guard(
                _initialize_request(url),
                allow_private=allow_private,
                allowed_hosts=allowed_hosts,
            )
        except EgressRefusalError as e:
            return record(RATE_LIMIT_PROBE_ID, name, "EXCLUDED",
                          limitation="egress refused before request %d of %d, nothing was sent: %s" % (sent + 1, count, e),
                          endpoint=url)
        except Exception as e:
            return record(RATE_LIMIT_PROBE_ID, name, "NOT_OBSERVED",
                          http_status=last_status,
                          limitation="request failed after %d of %d: %s" % (sent, count, e),
                          endpoint=url)
        sent += 1
        last_status = status
        if _is_block_page(status,raw): return record(RATE_LIMIT_PROBE_ID,name,'EXCLUDED',http_status=status,headers=headers,body=raw,limitation='block page, throttling untested',endpoint=url)
        if status == 429:
            retry = (headers.get("retry-after") or "").strip()
            if retry:
                return record(RATE_LIMIT_PROBE_ID, name, "PASS",
                              http_status=429, headers=headers, body=raw,
                              detail="request %d of %d returned 429 with Retry-After %s" % (sent, count, retry),
                              endpoint=url)
            return record(RATE_LIMIT_PROBE_ID, name, "NOT_OBSERVED",
                          http_status=429, headers=headers, body=raw,
                          limitation="429 on request %d of %d carried no Retry-After, so throttling is not established" % (sent, count),
                          endpoint=url)

    return record(RATE_LIMIT_PROBE_ID, name, "NOT_OBSERVED",
                  http_status=last_status,
                  limitation="no 429 observed inside the authorised budget of %d requests in %d seconds" % (count, window),
                  endpoint=url)

