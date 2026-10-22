#!/usr/bin/env python3
"""
VATA mcp_authscan v1.1.0 -- Live OAuth endpoint scanner for MCP servers.

Tests RFC 9728 → RFC 8414 OAuth discovery chain and probes OAuth server configuration
for authentication, token caching, CORS, PKCE, key rotation, and other security properties.

Scanner mode: HTTP request/response analysis against live MCP server endpoints.
Protocol: Tests JSON-RPC /initialize endpoint for 401 (OAuth required) or 200 (zero-auth).
Exit codes: 0=success, 1=auth failed, 2=unreachable, 3=preflight failed, 4=discovery incomplete.
Output: Human-readable security report with probe results and deterministic SHA256 hash.
"""
from mcp_authscan.report_copy import render_summary, check_counts
import argparse, hashlib, json, re, sys, ipaddress, os, time, subprocess
from datetime import datetime, timezone
from pathlib import Path


# ---- Live MCP Server Scanning ----
import socket
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import urlparse
from mcp_authscan.cors import probe_cors_urllib

LIVE_ENDPOINTS = {
    "/sse": "GET",
    "/message": "POST", 
    "/mcp": "POST",
    "/tools/list": "GET",
}

# Fields included in report hash integrity check
HASH_FIELDS = [
    "target",
    "scan_mode", 
    "probe_set_version",
    "probes_attempted",
    "probes_passed",
    "probes_failed",
    "probes_observed",
    "probes_not_observed",
    "probes_excluded",
    "findings_count",
    "scan_date",  # Timestamp IS included to bind hash to this run
    "tool_version",
    "findings",
    "authorization",  # If present
]

# ---- Security Hardening ----
PRIVATE_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

def is_private_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in PRIVATE_IP_RANGES)
    except ValueError:
        return False

def validate_target_host(hostname, port):
    try:
        addr_info = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        if not addr_info:
            raise ValueError(f"Cannot resolve {hostname}")
        resolved_ip = addr_info[0][4][0]
        if is_private_ip(resolved_ip):
            raise ValueError(f"Target {hostname} resolves to private IP {resolved_ip} (DNS rebinding protection)")
        return resolved_ip
    except socket.gaierror as e:
        raise ValueError(f"DNS resolution failed for {hostname}: {e}")

MAX_RESPONSE_SIZE = 10_000_000

def safe_read_response(req, timeout=5, max_size=MAX_RESPONSE_SIZE):
    try:
        with urlopen(req, timeout=timeout) as resp:
            data = b''
            chunk_size = 65536
            while len(data) < max_size:
                chunk = resp.read(chunk_size)
                if not chunk:
                    break
                data += chunk
            if len(data) >= max_size:
                raise ValueError(f"Response exceeded {max_size} bytes (DoS protection)")
            return data
    except HTTPError as e:
        if e.fp:
            e.fp.read()
        raise

class RateLimiter:
    def __init__(self, requests_per_second=10):
        self.min_interval = 1.0 / requests_per_second
        self.last_request = 0
    
    def wait(self):
        elapsed = time.time() - self.last_request
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self.last_request = time.time()

def validate_input_path(path_str):
    path = Path(path_str).resolve()
    if not path.exists():
        raise ValueError(f"Path does not exist: {path_str}")
    if not os.access(path, os.R_OK):
        raise ValueError(f"No read permission: {path_str}")
    forbidden = {'/proc', '/sys', '/dev', '/etc', '/root', '/boot', '/var', '/lib', '/usr/bin', '/bin'}
    for fd in forbidden:
        if str(path).startswith(fd):
            raise ValueError(f"Cannot scan sensitive directory {fd}: {path_str}")
    return path


def discover_oauth_endpoints(base_url):
    """
    RFC 9728 (MCP) → RFC 8414 (OAuth) discovery chain.

    Returns (endpoints_dict, discovery_info) where:
    - endpoints_dict: {endpoint_name: url} for discovered OAuth endpoints
    - discovery_info: metadata about discovery chain
    or (None, None) if not an OAuth server
    """
    base = base_url.rstrip("/")
    discovered_hosts = set()
    base_parsed = urlparse(base)
    base_host = base_parsed.hostname
    if base_host:
        discovered_hosts.add(base_host)

    print(f"[*] RFC 9728 → RFC 8414 discovery", file=sys.stderr)

    # Step 1: POST /initialize (RFC 9728)
    init_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "mcp-authscan", "version": VERSION}
        }
    }

    # Use the target URL as-is (already the MCP endpoint path)
    init_url = base

    try:
        req = Request(init_url, method="POST")
        req.add_header("User-Agent", f"mcp-authscan/{VERSION}")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json, text/event-stream")
        req.data = json.dumps(init_payload).encode()

        try:
            with urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    # Unauthenticated access - zero-auth vulnerability detected
                    print(f"[!] ZERO-AUTH: Target responds to /initialize without authentication", file=sys.stderr)
                    zero_auth_info = {"status": "ZERO_AUTH_DETECTED", "severity": "CRITICAL"}
                    return None, zero_auth_info
        except HTTPError as e:
            if e.code != 401:
                # Not an OAuth server
                print(f"[*] HTTP {e.code} - Not an OAuth server", file=sys.stderr)
                return None, None

            # Step 2: Parse 401 www-authenticate header (RFC 9728)
            www_auth = e.headers.get("www-authenticate", "")
            print(f"[+] OAuth detected (HTTP 401)", file=sys.stderr)

            # Look for resource_metadata URL in www-authenticate header
            match = re.search(r'resource_metadata="([^"]+)"', www_auth)
            if not match:
                print(f"[*] No OAuth discovery pointer in WWW-Authenticate", file=sys.stderr)
                return None, None

            resource_url = match.group(1)
            resource_parsed = urlparse(resource_url)
            if resource_parsed.hostname:
                discovered_hosts.add(resource_parsed.hostname)

            print(f"[*] Resource metadata: {resource_url}", file=sys.stderr)

            # Step 3: Fetch resource metadata
            try:
                req = Request(resource_url)
                req.add_header("User-Agent", f"mcp-authscan/{VERSION}")

                with urlopen(req, timeout=5) as resp:
                    resource_data = json.loads(resp.read().decode())
                    auth_servers = resource_data.get("authorization_servers", [])
                    print(f"[*] Found {len(auth_servers)} OAuth server(s)", file=sys.stderr)

                    if not auth_servers:
                        return None, None

                    # Step 4: Fetch OAuth server metadata (RFC 8414)
                    all_endpoints = {}
                    for oauth_server in auth_servers:
                        oauth_parsed = urlparse(oauth_server)
                        if oauth_parsed.hostname:
                            discovered_hosts.add(oauth_parsed.hostname)

                        try:
                            oauth_metadata_url = oauth_server.rstrip("/") + "/.well-known/oauth-authorization-server"
                            req = Request(oauth_metadata_url)
                            req.add_header("User-Agent", f"mcp-authscan/{VERSION}")

                            with urlopen(req, timeout=5) as resp:
                                oauth_data = json.loads(resp.read().decode())

                                # Extract OAuth endpoints
                                endpoints_found = {
                                    "token": oauth_data.get("token_endpoint"),
                                    "authorize": oauth_data.get("authorization_endpoint"),
                                    "register": oauth_data.get("registration_endpoint"),
                                    "revoke": oauth_data.get("revocation_endpoint"),
                                    "device": oauth_data.get("device_authorization_endpoint"),
                                    "jwks": oauth_data.get("jwks_uri"),
                                }
                                endpoints_found = {k: v for k, v in endpoints_found.items() if v}
                                all_endpoints.update(endpoints_found)
                                print(f"[+] Discovered {len(endpoints_found)} endpoints on {oauth_server}", file=sys.stderr)

                        except (HTTPError, URLError, socket.timeout, json.JSONDecodeError):
                            continue

                    if all_endpoints:
                        discovery_info = {
                            "method": "RFC 9728 → RFC 8414",
                            "resource_metadata": resource_url,
                            "auth_servers": auth_servers,
                            "discovered_hosts": list(discovered_hosts),
                            "endpoints": all_endpoints
                        }
                        print(f"[+] Discovery complete - {len(all_endpoints)} endpoints found", file=sys.stderr)
                        return all_endpoints, discovery_info

            except (HTTPError, URLError, socket.timeout, json.JSONDecodeError):
                print(f"[!] Failed to fetch OAuth metadata", file=sys.stderr)

    except (URLError, socket.timeout):
        pass

    return None, None

def scan_live_server(target_url):
    """Scan a running MCP server for zero-auth, CORS, token validation issues.
    Returns (findings, reachable, probe_status, discovery_info, (oauth_records, probe_results)) tuple.
    probe_status = {'passed': count, 'not_observed': count, 'findings': count}

    STATUS CLASSIFICATION (per probe, per endpoint):
    - PASSED: Server responded with 401/403 (correctly rejected unauthenticated request)
    - NOT_OBSERVED: Server returned 404/5xx (endpoint doesn't exist or error, can't test)
    - FINDINGS: Server returned 200/201/202 (vulnerability detected)
    """
    findings = []
    probe_status = {'passed': 0, 'not_observed': 0, 'findings': 0}
    oauth_records = []  # Initialize at function start - every return path will have this
    probe_results = []  # Track (endpoint, method, status, reason) for detailed reporting
    discovery_info = None

    try:
        p = urlparse(target_url)
        socket.create_connection((p.hostname, p.port or 80), timeout=5)
    except Exception as e:
        print(f"[!] Cannot reach {target_url}: {e}", file=sys.stderr)
        return findings, False, probe_status, discovery_info, ([], [])

    print(f"[*] Detected live server URL", file=sys.stderr)
    print(f"[*] Preflight: Checking if target is an MCP server...", file=sys.stderr)

    # PREFLIGHT: Verify target is an MCP server before running probes
    # POST /initialize should return 401 with WWW-Authenticate OR 200 with JSON
    mcp_verified = False
    init_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "mcp-authscan", "version": VERSION}
        }
    }

    try:
        req = Request(target_url, method="POST")
        req.add_header("User-Agent", f"mcp-authscan/{VERSION}")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json, text/event-stream")
        req.data = json.dumps(init_payload).encode()

        try:
            with urlopen(req, timeout=5) as resp:
                if resp.status in [200, 201, 202]:
                    # Should be JSON-RPC response
                    body = resp.read(500).decode(errors='ignore')
                    if 'jsonrpc' in body or '{' in body:
                        mcp_verified = True
                        print(f"[+] MCP server verified (HTTP {resp.status})", file=sys.stderr)
                elif resp.status == 400 or resp.status == 406 or resp.status == 405:
                    # 400: JSON-RPC error (malformed but MCP aware)
                    # 405/406: Wrong method/content-type (path exists, headers wrong)
                    body = resp.read(500).decode(errors='ignore')
                    if 'jsonrpc' in body or '{' in body:
                        mcp_verified = True
                        print(f"[+] MCP server verified (HTTP {resp.status} with JSON-RPC error)", file=sys.stderr)
        except HTTPError as e:
            if e.code == 401:
                # OAuth challenge - this is MCP
                mcp_verified = True
                print(f"[+] MCP server verified (HTTP 401 with OAuth)", file=sys.stderr)
            elif e.code in [400, 405, 406]:
                # Server returned error but in JSON format - still MCP
                body = e.fp.read(500).decode(errors='ignore') if e.fp else ""
                if 'jsonrpc' in body or '{' in body:
                    mcp_verified = True
                    print(f"[+] MCP server verified (HTTP {e.code} with JSON-RPC response)", file=sys.stderr)
    except Exception as e:
        pass

    if not mcp_verified:
        print(f"[!] No MCP surface detected at {target_url}", file=sys.stderr)
        print(f"[!] POST /initialize did not respond as MCP server (expected 401 with WWW-Authenticate, 200-202 with JSON-RPC, or 400 with JSON-RPC error)", file=sys.stderr)
        # Zero probes attempted—preflight failed
        probe_status['attempted'] = 0
        probe_status['passed'] = 0
        probe_status['failed'] = 0
        probe_status['not_observed'] = 0
        preflight_info = {"status": "PREFLIGHT_FAILED"}
        return findings, False, probe_status, preflight_info, ([], [])

    print(f"[*] Attempting OAuth discovery...", file=sys.stderr)

    # Perform RFC 9728 → RFC 8414 discovery
    oauth_endpoints, discovery_info = discover_oauth_endpoints(target_url)

    if oauth_endpoints:
        # Use discovered OAuth endpoints
        print(f"[+] Using {len(oauth_endpoints)} discovered OAuth endpoints", file=sys.stderr)

        # Phase 1: Run OAuth server probes (RFC 8414 metadata assessment)
        from mcp_authscan.oauth_probes_v2 import run_oauth_assessment, count_probes, render_probe

        oauth_server_urls = set()
        for endpoint_url in oauth_endpoints.values():
            parsed = urlparse(endpoint_url)
            oauth_server_urls.add(f"{parsed.scheme}://{parsed.netloc}")

        for oauth_server_url in oauth_server_urls:
            print(f"[*] Assessing OAuth server: {oauth_server_url}", file=sys.stderr)
            # Fetch resource_metadata document from URL in discovery_info
            resource_metadata_doc = None
            if discovery_info and discovery_info.get("resource_metadata"):
                try:
                    resource_url = discovery_info["resource_metadata"]
                    req = Request(resource_url)
                    req.add_header("User-Agent", f"mcp-authscan/{VERSION}")
                    with urlopen(req, timeout=5) as resp:
                        resource_metadata_doc = json.loads(resp.read().decode())
                except Exception as e:
                    pass  # Silently fail, resource_metadata_doc stays None
            
            records, oauth_findings = run_oauth_assessment(oauth_server_url, resource_metadata_doc, target_url)
            
            oauth_records.extend(records)

            for finding in oauth_findings:
                findings.append({
                    "rule": f"OAuth-{finding['rule']}",
                    "severity": finding['severity'],
                    "confidence": "HIGH",
                    "title": finding['title'],
                    "file": oauth_server_url,
                    "line": 0,
                    "ref": finding['rule'],
                    "evidence": finding.get('evidence', ''),
                    "snippet": "",
                    "is_live_finding": True,
                    "request_method": finding.get('request_method', 'POST'),
                    "request_body": finding.get('request_body', ''),
                    "response_status": finding.get('response_status', 0),
                    "response_body": finding.get('response_body', ''),
                    "response_preview": finding.get('response_body', ''),
                    "interpretation": finding.get('interpretation', 'OAuth configuration issue detected'),
                    "remediation": finding.get('remediation', 'Review and correct OAuth server metadata'),
                })

            # Sort probes by ID for consistent ordering
            sorted_records = sorted(records, key=lambda r: r.probe_id)
            for record in sorted_records:
                print(render_probe(record), file=sys.stderr)

        
        # Verify accounting
        oauth_counts, accounting_valid, accounting_error = count_probes(oauth_records)
        if not accounting_valid:
            print(f"[!] ACCOUNTING ERROR: {accounting_error}", file=sys.stderr)
            sys.exit(5)
        
        # Update probe_status from OAuth assessment counts
        authserver_counts = oauth_counts.get("authserver", {})
        probe_status['attempted'] = authserver_counts.get("attempted", 0)
        probe_status['passed'] = authserver_counts.get("passed", 0)
        probe_status['failed'] = authserver_counts.get("failed", 0)
        probe_status['not_observed'] = authserver_counts.get("not_observed", 0)
        probe_status['observation'] = authserver_counts.get("observation", 0)
        probe_status['excluded'] = authserver_counts.get("excluded", 0)
        
        # Phase 2: Skip endpoint-by-endpoint testing
        # OAuth server probes (Phase 1) are sufficient for this assessment.
        # Individual endpoint testing would repeat OAuth probe logic with wrong rules.
        # Future: accept --client-id to run PKCE/redirect-URI rules (OAuth-10, OAuth-11)
        return findings, True, probe_status, discovery_info, (oauth_records, probe_results)
    else:
        # Discovery failed - STOP, don't fallback to guessing
        # Report DISCOVERY_INCOMPLETE with forensic details
        print(f"[!] DISCOVERY_INCOMPLETE: OAuth endpoint discovery failed", file=sys.stderr)
        print(f"[!] The preflight detected OAuth (401) but RFC 9728 → RFC 8414 chain did not complete", file=sys.stderr)
        print(f"[!] Cannot test OAuth endpoints without discovery. Halting.", file=sys.stderr)

        # Return with DISCOVERY_INCOMPLETE status
        discovery_incomplete = {
            "status": "DISCOVERY_INCOMPLETE",
            "preflight_verified": True,
            "preflight_status": 401,
            "discovery_attempted": True,
            "discovery_failed_at": "resource_metadata_or_oauth_server_metadata",
            "message": "OAuth server detected but endpoint discovery chain incomplete"
        }
        # Zero probes were attempted because we had no endpoints to test
        probe_status['attempted'] = 0
        probe_status['passed'] = 0
        probe_status['failed'] = 0
        probe_status['not_observed'] = 0
        return findings, True, probe_status, discovery_incomplete, ([], [])

    print(f"[*] Scanning live server: {scan_target}", file=sys.stderr)
    print(f"[*] Probe-by-probe execution:", file=sys.stderr)

    for endpoint_path, method_and_url in endpoints_to_test.items():
        # Handle tuple format (method, full_url)
        if isinstance(method_and_url, tuple):
            method, url = method_and_url
        else:
            method = method_and_url
            url = scan_target.rstrip("/") + endpoint_path

        # Display path for output (use endpoint_path for discovered, or URL path for hardcoded)
        display_path = endpoint_path if not oauth_endpoints else urlparse(url).path or url.split("://")[1].split("/", 1)[1] if "/" in url.split("://")[1] else "/"

        # Test 1: Zero-auth endpoint (D1)
        # PASS: 401/403 (correctly rejected)
        # FINDING: 200/201/202 (vulnerable - accepts unauthenticated)
        # NOT_OBSERVED: 404/5xx (endpoint doesn't exist)
        request_body = ""
        try:
            req = Request(url, method=method)
            req.add_header("User-Agent", f"mcp-authscan/{VERSION}")
            if method == "POST":
                request_body = '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
                req.data = request_body.encode()
                req.add_header("Content-Type", "application/json")

            with urlopen(req, timeout=5) as resp:
                response_data = resp.read(500)
                response_preview = response_data.decode(errors='ignore')

                if resp.status in [200, 201, 202]:
                    # Check: is this actually the endpoint we're testing?
                    # HTML responses (<!DOCTYPE, <html) are SPA shells, not API endpoints
                    if response_preview.strip().startswith(('<!DOCTYPE', '<html', '<?xml')):
                        # Wrong content-type: expected JSON/OAuth endpoint, got HTML
                        print(f"  [D1] {method:4s} {display_path:30s} HTTP {resp.status} NOT_OBSERVED (wrong content-type: HTML)", file=sys.stderr)
                        probe_results.append((display_path, method, resp.status, "wrong content-type: HTML", "NOT_OBSERVED"))
                        probe_status['not_observed'] += 1
                    else:
                        # VULNERABILITY: endpoint accepts unauthenticated requests
                        print(f"  [D1] {method:4s} {display_path:30s} HTTP {resp.status} VULNERABLE (no auth required)", file=sys.stderr)
                        probe_results.append((display_path, method, resp.status, "no auth required", "VULNERABLE"))
                        add_live_finding(findings, "D1", "CRITICAL",
                            f"Zero-auth endpoint: {method} {display_path}",
                            url, method, request_body, resp.status, response_preview,
                            f"Endpoint responded to unauthenticated request (HTTP {resp.status})",
                            "Add Authorization: Bearer <token> requirement. Validate all requests before processing.",
                            "D1-zero-auth", "HIGH")
                        probe_status['findings'] += 1
                elif resp.status in [401, 403]:
                    # GOOD: server correctly rejected unauthenticated request
                    print(f"  [D1] {method:4s} {display_path:30s} HTTP {resp.status} PASS (auth enforced)", file=sys.stderr)
                    probe_results.append((display_path, method, resp.status, "auth enforced", "PASS"))
                    probe_status['passed'] += 1
                else:
                    # NOT_OBSERVED: unexpected status (endpoint missing, error, etc)
                    print(f"  [D1] {method:4s} {display_path:30s} HTTP {resp.status} NOT_OBSERVED", file=sys.stderr)
                    probe_results.append((display_path, method, resp.status, f"unexpected status", "NOT_OBSERVED"))
                    probe_status['not_observed'] += 1

        except HTTPError as e:
            if e.code in [200, 201, 202]:
                # Try to read error response
                try:
                    error_body = e.read(500).decode(errors='ignore')
                except:
                    error_body = ""

                # Check: is this actually the endpoint we're testing?
                if error_body.strip().startswith(('<!DOCTYPE', '<html', '<?xml')):
                    # Wrong content-type: expected JSON/OAuth endpoint, got HTML
                    print(f"  [D1] {method:4s} {display_path:30s} HTTP {e.code} NOT_OBSERVED (wrong content-type: HTML)", file=sys.stderr)
                    probe_status['not_observed'] += 1
                else:
                    print(f"  [D1] {method:4s} {display_path:30s} HTTP {e.code} VULNERABLE (no auth required)", file=sys.stderr)
                    add_live_finding(findings, "D1", "CRITICAL", f"Zero-auth: {method} {display_path}",
                        url, method, request_body if method == "POST" else "", e.code, error_body,
                        f"Endpoint accessible without Authorization header",
                        "Add Authorization: Bearer <token> requirement. Validate all requests before processing.",
                        "D1-zero-auth", "HIGH")
                    probe_status['findings'] += 1
            elif e.code in [401, 403]:
                print(f"  [D1] {method:4s} {display_path:15s} HTTP {e.code} PASS (auth enforced)", file=sys.stderr)
                probe_status['passed'] += 1
            else:
                # 404, 5xx, etc
                print(f"  [D1] {method:4s} {display_path:15s} HTTP {e.code} NOT_OBSERVED", file=sys.stderr)
                probe_status['not_observed'] += 1
        except (URLError, socket.timeout) as e:
            # Connection failed: can't observe this probe
            print(f"  [D1] {method:4s} {display_path:15s} TIMEOUT/CONNFAIL NOT_OBSERVED", file=sys.stderr)
            probe_status['not_observed'] += 1

        # Test 2: Evidence-based CORS policy (D2)
        # CORS can only be tested on endpoints that exist (2xx, 401/403)
        # If endpoint is 404/5xx, we can't test CORS = NOT_OBSERVED
        try:
            req = Request(url, method=method)
            req.add_header("User-Agent", f"mcp-authscan/{VERSION}")

            # First check: does the endpoint exist?
            endpoint_exists = False
            try:
                with urlopen(req, timeout=5) as resp:
                    if resp.status not in [404] and resp.status < 500:
                        endpoint_exists = True
            except HTTPError as e:
                if e.code not in [404] and e.code < 500:
                    endpoint_exists = True
            except (URLError, socket.timeout):
                pass

            if not endpoint_exists:
                # Endpoint doesn't exist or has server error - can't test
                print(f"  [D2] {method:4s} {display_path:15s} (endpoint missing) NOT_OBSERVED", file=sys.stderr)
                probe_status['not_observed'] += 1
            else:
                # Endpoint exists, now test CORS
                assessment = probe_cors_urllib(url, method, timeout=5, opener=urlopen)
                if assessment.is_finding:
                    print(f"  [D2] {method:4s} {display_path:15s} VULNERABLE (CORS misconfigured)", file=sys.stderr)
                    add(findings, "D2", assessment.severity, f"{assessment.summary} on {display_path}",
                        url, "", 0, assessment.details,
                        "D2-cors-origin-reflection" if assessment.reflected else "D2-cors-wildcard", "MEDIUM")
                    probe_status['findings'] += 1
                else:
                    # CORS test ran and found no issue = passed
                    print(f"  [D2] {method:4s} {display_path:15s} PASS (CORS OK)", file=sys.stderr)
                    probe_status['passed'] += 1
        except (HTTPError, URLError, socket.timeout):
            # Couldn't test CORS
            print(f"  [D2] {method:4s} {display_path:15s} TIMEOUT/CONNFAIL NOT_OBSERVED", file=sys.stderr)
            probe_status['not_observed'] += 1

        # Test 3: Invalid token accepted (D3)
        # PASS: 401/403 (correctly rejected invalid token)
        # FINDING: 200/201/202 (vulnerable - accepts invalid token)
        # NOT_OBSERVED: 404/5xx (endpoint doesn't exist)
        token_body = ""
        try:
            req = Request(url, method=method)
            req.add_header("Authorization", "Bearer invalid_token_xyz")
            if method == "POST":
                token_body = '{"jsonrpc":"2.0"}'
                req.data = token_body.encode()
                req.add_header("Content-Type", "application/json")

            with urlopen(req, timeout=5) as resp:
                response_data = resp.read(500)
                response_preview = response_data.decode(errors='ignore')

                if resp.status in [200, 201, 202]:
                    # Check: is this actually the endpoint we're testing?
                    if response_preview.strip().startswith(('<!DOCTYPE', '<html', '<?xml')):
                        # Wrong content-type: expected JSON/OAuth endpoint, got HTML
                        print(f"  [D3] {method:4s} {display_path:30s} HTTP {resp.status} NOT_OBSERVED (wrong content-type: HTML)", file=sys.stderr)
                        probe_status['not_observed'] += 1
                    else:
                        # VULNERABILITY: endpoint accepts invalid token
                        print(f"  [D3] {method:4s} {display_path:30s} HTTP {resp.status} VULNERABLE (invalid token accepted)", file=sys.stderr)
                        add_live_finding(findings, "D3", "HIGH", f"Token validation bypass on {display_path}",
                            url, method, token_body, resp.status, response_preview,
                            f"Invalid token accepted (HTTP {resp.status})",
                            "Validate token signature and expiry before processing requests. Reject invalid/expired tokens.",
                            "D3-token-validation", "HIGH")
                        probe_status['findings'] += 1
                elif resp.status == 401:
                    # PASS: 401 Unauthorized specifically proves token validation (rejected invalid token)
                    print(f"  [D3] {method:4s} {display_path:30s} HTTP {resp.status} PASS (token validation enforced)", file=sys.stderr)
                    probe_results.append((display_path, method, resp.status, "token validation enforced", "PASS"))
                    probe_status['passed'] += 1
                elif resp.status == 403:
                    # NOT_OBSERVED: 403 Forbidden means "access denied" but doesn't prove token validation
                    # Could be permission denied, rate limit, firewall, or actual token validation
                    print(f"  [D3] {method:4s} {display_path:30s} HTTP {resp.status} NOT_OBSERVED (reason unknown - could be token validation or permission denied)", file=sys.stderr)
                    probe_results.append((display_path, method, resp.status, "access denied but reason unknown", "NOT_OBSERVED"))
                    probe_status['not_observed'] += 1
                else:
                    # NOT_OBSERVED: unexpected status
                    print(f"  [D3] {method:4s} {display_path:30s} HTTP {resp.status} NOT_OBSERVED", file=sys.stderr)
                    probe_results.append((display_path, method, resp.status, f"unexpected status", "NOT_OBSERVED"))
                    probe_status['not_observed'] += 1

        except HTTPError as e:
            if e.code in [200, 201, 202]:
                # Try to read error response
                try:
                    error_body = e.read(500).decode(errors='ignore')
                except:
                    error_body = ""

                # Check: is this actually the endpoint we're testing?
                if error_body.strip().startswith(('<!DOCTYPE', '<html', '<?xml')):
                    # Wrong content-type: expected JSON/OAuth endpoint, got HTML
                    print(f"  [D3] {method:4s} {display_path:30s} HTTP {e.code} NOT_OBSERVED (wrong content-type: HTML)", file=sys.stderr)
                    probe_status['not_observed'] += 1
                else:
                    print(f"  [D3] {method:4s} {display_path:30s} HTTP {e.code} VULNERABLE (invalid token accepted)", file=sys.stderr)
                    add_live_finding(findings, "D3", "HIGH", f"Token validation bypass on {display_path}",
                        url, method, token_body if method == "POST" else "", e.code, error_body,
                        f"Invalid token accepted",
                        "Validate token signature and expiry before processing requests. Reject invalid/expired tokens.",
                        "D3-token-validation", "HIGH")
                    probe_status['findings'] += 1
            elif e.code == 401:
                print(f"  [D3] {method:4s} {display_path:30s} HTTP {e.code} PASS (token validation enforced)", file=sys.stderr)
                probe_results.append((display_path, method, e.code, "token validation enforced", "PASS"))
                probe_status['passed'] += 1
            elif e.code == 403:
                print(f"  [D3] {method:4s} {display_path:30s} HTTP {e.code} NOT_OBSERVED (reason unknown - could be token validation or permission denied)", file=sys.stderr)
                probe_results.append((display_path, method, e.code, "access denied but reason unknown", "NOT_OBSERVED"))
                probe_status['not_observed'] += 1
            else:
                print(f"  [D3] {method:4s} {display_path:30s} HTTP {e.code} NOT_OBSERVED", file=sys.stderr)
                probe_results.append((display_path, method, e.code, "unexpected status", "NOT_OBSERVED"))
                probe_status['not_observed'] += 1
        except (URLError, socket.timeout):
            print(f"  [D3] {method:4s} {display_path:15s} TIMEOUT/CONNFAIL NOT_OBSERVED", file=sys.stderr)
            probe_status['not_observed'] += 1

    return findings, True, probe_status, discovery_info, probe_results

VERSION = "1.1.0"
PROBE_SET_VERSION = "1.1.0"  # 1.1.0: 9-probe OAuth server assessment (issuer, resource-binding, cache-control, cors, jwks, password-grant, pkce, redirect-uri, client-auth)

def get_git_metadata(target_path):
    """Extract git information if target is in a git repo."""
    try:
        original_cwd = os.getcwd()
        os.chdir(target_path)

        repo_url = subprocess.check_output(
            ["git", "config", "--get", "remote.origin.url"],
            stderr=subprocess.DEVNULL,
            timeout=2
        ).decode().strip()

        branch = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            stderr=subprocess.DEVNULL,
            timeout=2
        ).decode().strip()

        commit_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
            timeout=2
        ).decode().strip()[:12]  # short SHA

        os.chdir(original_cwd)
        return repo_url, branch, commit_sha
    except Exception:
        return None, None, None

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
    paths = [root] if root.is_file() else root.rglob("*")
    skipped = 0
    for p in paths:
        if p.is_symlink():
            continue
        if not (p.is_file() and p.suffix in SRC_EXT):
            continue
        if p.resolve() == SELF_PATH:
            continue
        if any(s in p.parts for s in SKIP_DIR):
            continue
        if MINIFIED_FILE.search(p.as_posix()):
            continue
        if not include_tests and is_test_path(p):
            skipped += 1
            continue
        rp = p.resolve()
        if any(rp == e or e in rp.parents for e in excl):
            continue
        yield p
    if skipped:
        print(f"skipped {skipped} test/fixture path(s); pass --include-tests to scan them", file=sys.stderr)

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

def validate_response_format(response_preview, endpoint_type):
    """
    Validate response format matches endpoint type.
    - JWKS: should be JSON with keys
    - OAuth metadata: should be JSON  
    - JSON-RPC: should have jsonrpc field or be valid JSON
    
    Returns True if format matches, False (NOT_OBSERVED) if format is wrong.
    """
    if not response_preview:
        return False
    
    # HTML responses are never findings (SPA shells, error pages, etc)
    if response_preview.strip().startswith(('<!DOCTYPE', '<html', '<?xml')):
        return False
    
    # Should be JSON for OAuth/JWKS endpoints
    if endpoint_type in ['jwks', 'metadata', 'oauth']:
        try:
            import json as json_module
            json_module.loads(response_preview[:500])
            return True
        except:
            return False
    
    return False


def add_live_finding(findings, rule, sev, title, url, method, request_body,
                      response_status, response_preview, interpretation, remediation, ref, conf):
    """Add finding from live endpoint assessment with full request/response evidence."""
    findings.append({
        "rule": rule, "severity": sev, "confidence": conf, "title": title,
        "file": url, "line": 0,
        "evidence": interpretation,
        "snippet": "",
        "ref": ref,
        # Live endpoint specifics
        "is_live_finding": True,
        "request_method": method,
        "request_body": request_body,
        "response_status": response_status,
        "response_preview": response_preview,
        "interpretation": interpretation,
        "remediation": remediation,
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
    pl = path.as_posix().lower()
    if any(x in pl for x in ("/internal/httpx", "/oryx/httpx", "/fosite/integration", "/examples/", "cypress")):
        return
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

    # Wrapper that cannot pass issuer= through to the SDK.
    for m in re.finditer(r"class\s+\w+\((?:\w*ClientCredentialsOAuthProvider|\w*PrivateKeyJWTOAuthProvider)\)", text):
        block = text[m.start():m.start()+1200]
        sup = re.search(r"super\(\)\.__init__\((.*?)\)", block, re.S)
        if sup and not re.search(r"\bissuer\s*=", sup.group(1)):
            add(F, "C1", "HIGH",
                "M2M provider wrapper calls super().__init__ without issuer= - callers cannot bind the secret",
                path, text, m.start(), "super().__init__ has no issuer=",
                "GHSA-qx49-fqc8-xw99 (python-sdk issuer binding)", "HIGH")
    for m in re.finditer(r"expectedIssuer[^\n]{0,80}\?[^\n]{0,120}:\s*\{\s*\}", text):
        add(F, "C1", "HIGH",
            "expectedIssuer is omitted when the issuer value is missing - binding is conditional",
            path, text, m.start(), m.group(0)[:80],
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
    "E1": {"name": "MCPCrossSessionDataLeak",
           "desc": "Module-level store keyed by session id is returned whole to a caller, or a missing session id falls back to a constant key - one session reads another's data.",
           "sev": 7.5, "cwe": ["CWE-200", "CWE-639"]},
    "E2": {"name": "MCPSensitiveDataInLogs",
           "desc": "Secret-named value, tool argument kept as session data, or a whole session store written raw to logs/stderr, which MCP hosts routinely collect.",
           "sev": 5.5, "cwe": ["CWE-532"]},
    "E3": {"name": "MCPToolOutputPromptInjection",
           "desc": "Model-visible tool result or tool description contains a prompt-injection phrase (instruction override, system-prompt exfiltration, concealment from the user).",
           "sev": 8.0, "cwe": ["CWE-74", "CWE-1427"]},
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
    # JS idiom: code_challenge_method || 'plain' / ?? 'plain'
    r"code[_-]?challenge[_-]?method\b[^;\n]{0,60}(?:\|\||\?\?)\s*[\'\"]plain[\'\"]"
    # Python/generic default idiom: .get("code_challenge_method", "plain") or (= ... or "plain")
    r"|code[_-]?challenge[_-]?method[\'\"]?\s*,\s*[\'\"]plain[\'\"]"
    r"|code[_-]?challenge[_-]?method[^\n]{0,40}\bor\s+[\'\"]plain[\'\"]"
    # The smoking gun: non-S256 branch falls through to a RAW verifier compare
    # (calc = verifier / = code_verifier), i.e. plain is honored, not rejected.
    r"|==\s*[\'\"]S256[\'\"][^\n]*\n(?:[^\n]*\n){0,8}?\s*else\s*:\s*\n\s*\w+\s*=\s*(?:code_)?verifier\b", re.I | re.M)
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
    # timestamp-column single-use (cortex idiom): usedAt/consumedAt/redeemedAt set to a
    # date/now, plus the .usedAt read-guard that enforces it. KNOWN LIMIT: a file that
    # SETS usedAt but never CHECKS it is now silenced too (set-but-unchecked); acceptable
    # for a MEDIUM review-pointer.
    r"|(?:used|consumed|redeemed|revoked)_?at\s*[:=]\s*(?:new\s+Date|Date\.now|datetime|now\(|timezone\.now|Time\.now|\bnow\b|sql\w*\.now)"
    r"|(?:\.|\?\.)(?:used|consumed|redeemed|revoked)_?at\b"
    r"|data\s*:\s*\{[^}\n]*(?:used|consumed|redeemed)_?at"
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


DEP_NAMES = {"requirements.txt", "requirements-dev.txt", "pyproject.toml", "setup.cfg", "Pipfile", "package.json", "uv.lock", "package-lock.json", "poetry.lock"}

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
    if path.name in {"uv.lock", "package-lock.json", "poetry.lock"}:
        for m in re.finditer(r'name\s*=\s*"mcp"|"(?:mcp|@modelcontextprotocol/(?:sdk|client))"\s*:\s*\{[^}]{0,200}"version"\s*:\s*"([^"]+)"', text):
            spec = m.group(1) if m.lastindex else ""
            window = text[m.start():m.start()+240]
            vm = re.search(r'version\s*=\s*"([^"]+)"', window)
            pin = spec or (vm.group(1) if vm else "")
            if not pin:
                continue
            bad = _mcp_vulnerable("=="+pin) if path.name != "package-lock.json" else _npm_vulnerable("@modelcontextprotocol/sdk", pin) or _mcp_vulnerable("=="+pin)
            if bad:
                add(F, "D1", "HIGH",
                    "lockfile pin is inside the MCP issuer-binding advisory range",
                    path, text, m.start(), pin, "GHSA-qx49-fqc8-xw99", "HIGH")
        return
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

# ---- E-series: MCP server runtime data handling ----
# Seed: examples/vulnerable_gold_server.py (stdio JSON-RPC server). Fixed twin:
# examples/gold_server_fixed.py must stay silent. Gated on files that look like an MCP
# server so generic web code with module-level dicts or logging is not swept in.
E_MCP_SERVER = re.compile(
    r"""['"]tools/(?:call|list)['"]|@\w+\.tool\b|\bFastMCP\s*\(|\bMcpServer\b|"""
    r"""CallToolRequest|\.call_tool\b|server\.tool\s*\(""")
E_LOG_CALL = re.compile(
    r"\b(?:logger|logging|log|_log|LOGGER|LOG)\s*\.\s*"
    r"(?:debug|info|warning|warn|error|exception|critical|fatal|log)\s*\(|"
    r"\bconsole\.(?:log|error|warn|info|debug)\s*\(|"
    r"\bprint\s*\((?=[^\n]*file\s*=\s*sys\.stderr)|"
    r"\b(?:sys|process)\.stderr\.write\s*\(")
E_STORE_DEF = re.compile(
    r"^(?:(?:const|let|var)\s+)?([A-Za-z_]\w*)\s*(?::[^=\n]+)?=\s*"
    r"(?:\{\s*\}|dict\(\s*\)|(?:collections\.)?defaultdict\([^)\n]*\)|new\s+Map\s*\(\s*\))\s*;?\s*$",
    re.M)
E_SESSION_NAME = re.compile(r"session|^sid$|_sid$|conn|client|user|tenant|caller", re.I)

def _e_session_stores(text):
    """Module-level dicts/Maps written with a session-like key: {name: write_idx}."""
    stores = {}
    for m in E_STORE_DEF.finditer(text):
        name = m.group(1)
        n = re.escape(name)
        w = re.compile(r"\b" + n + r"\s*\[\s*([\w.]+)\s*\]\s*=(?!=)|\b" + n + r"\.set\(\s*([\w.]+)\s*,")
        for wm in w.finditer(text, m.end()):
            key = (wm.group(1) or wm.group(2)).split(".")[-1]
            if E_SESSION_NAME.search(key):
                stores[name] = wm.start()
                break
    return stores

def _e_is_log_line(line):
    return bool(E_LOG_CALL.search(line))

def rule_session_leak(path, text, F):
    if not E_MCP_SERVER.search(text):
        return
    stores = _e_session_stores(text)
    for name in stores:
        n = re.escape(name)
        whole = re.compile(
            r"\b(?:str|repr|dict|list|json\.dumps|JSON\.stringify)\(\s*" + n + r"\s*[,)]|"
            r"\{" + n + r"(?:![rsa])?\}|\$\{" + n + r"\}|"
            r"\breturn\s+" + n + r"\s*;?\s*$|"
            r"\b" + n + r"\.(?:items|values)\(\s*\)|"
            r"\bObject\.(?:values|entries|fromEntries)\(\s*" + n + r"\s*\)|\bArray\.from\(\s*" + n + r"\b|"
            r"\.\.\." + n + r"\.values\(", re.M)
        for m in whole.finditer(text):
            line = linetext(text, m.start())
            if _comment_line(line) or _e_is_log_line(line):
                continue  # logging the store is E2's finding, not a response leak
            add(F, "E1", "HIGH",
                f"Session-keyed shared store '{name}' returned whole to a caller",
                path, text, m.start(),
                f"'{name}' is a module-level dict keyed by session, and this line exposes "
                f"every session's entries at once - any caller reads other sessions' data",
                "VATA:gold-server cross-session store", "MEDIUM")
    # A missing session id that falls back to a constant puts every such caller in
    # one shared bucket of a session-keyed store.
    fallback = re.compile(
        r"""\b(\w+)\s*=\s*[^\n]*(?:\.get\(\s*['"](?:session_?id|sessionId|sid)['"]\s*,\s*['"][^'"\n]*['"]\s*\)|"""
        r"""session_?[Ii]d\s*(?:\?\?|\|\|)\s*['"][^'"\n]*['"])""")
    for m in fallback.finditer(text):
        var = re.escape(m.group(1))
        if not any(re.search(r"\b" + re.escape(s) + r"\s*\[\s*" + var + r"\s*\]|\b" + re.escape(s) + r"\.set\(\s*" + var + r"\b", text)
                   for s in stores):
            continue
        add(F, "E1", "HIGH",
            "Missing session id falls back to a constant key into a session-keyed store",
            path, text, m.start(),
            f"'{m.group(1)}' defaults to a fixed string when the caller sends no session id; "
            f"all such callers share one bucket and read each other's data",
            "VATA:gold-server cross-session store", "MEDIUM")

E_ARG_SOURCE = re.compile(
    r"""^\s*(?:(?:const|let|var)\s+)?([A-Za-z_]\w*)\s*(?::[^=\n]+)?=\s*[^\n]*"""
    r"""(?:\b(?:args|arguments|tool_args|tool_input)\b\s*(?:\.get\s*\(|\[|\.)|\[\s*['"]arguments['"]\s*\])""", re.M)
E_TOOL_DEF = re.compile(r"@\w+\.tool\b[^\n]*\n(?:\s*@[^\n]*\n)*\s*(?:async\s+)?def\s+\w+\s*\(([^)]*)\)")
# The name must END in the secret noun: client_secret / apiKey yes, token_kind / cookie_names no.
E_SECRET_NAME = re.compile(
    r"(?i:(?:^|_)(?:password|passwd|secret|token|api_?key|apikey|credentials?|private_?key|authorization|bearer|cookie)s?$)|"
    r"[a-z0-9](?:Password|Passwd|Secret|Token|ApiKey|Credentials?|PrivateKey|Cookie)s?$")

def _e_interpolates(args, var):
    """True if a log call's argument text embeds var's raw value (not len(var) etc.)."""
    v = re.escape(var)
    # f-string / template-literal placeholders
    if re.search(r"(?<![{])\{" + v + r"(?:\[[^}\]]*\])?(?:![rsa])?(?::[^}]*)?\}|\$\{" + v + r"\}", args):
        return True
    code = re.sub(r"""(['"`])(?:\\.|(?!\1)[^\\])*\1""", '""', args)  # drop string literals
    return bool(re.search(
        r"(?:^|[,+%]\s*)" + v + r"\b(?!\s*[(.\[])|"
        r"\b(?:str|repr|json\.dumps|JSON\.stringify)\(\s*" + v + r"\b", code.strip()))

def rule_secrets_in_logs(path, text, F):
    if not E_MCP_SERVER.search(text):
        return
    # Tool arguments count only once they are kept as session data (written into a
    # session-keyed store); logging an ordinary argument like host/port is not a leak.
    args_in = {m.group(1) for m in E_ARG_SOURCE.finditer(text)}
    for m in E_TOOL_DEF.finditer(text):
        for p in m.group(1).split(","):
            p = p.strip().split(":")[0].split("=")[0].strip().lstrip("*")
            if p and p not in ("self", "ctx", "context"):
                args_in.add(p)
    stores = _e_session_stores(text)
    tainted = {}
    for v in args_in:
        if any(re.search(r"\b" + re.escape(s) + r"\s*\[[^\]\n]+\]\s*=\s*" + re.escape(v) + r"\b|"
                         r"\b" + re.escape(s) + r"\.set\([^,\n]+,\s*" + re.escape(v) + r"\b", text)
               for s in stores):
            tainted[v] = "tool argument kept as session data"
    for name in stores:
        tainted.setdefault(name, "whole session store")
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*=", text):
        if E_SECRET_NAME.search(m.group(1)):
            tainted.setdefault(m.group(1), "secret-named value")
    if not tainted:
        return
    for m in E_LOG_CALL.finditer(text):
        if _comment_line(linetext(text, m.start())):
            continue
        args = call_args(text, m.end() - 1)
        hits = [v for v in tainted if _e_interpolates(args, v)]
        if not hits:
            continue
        what = ", ".join(f"{v} ({tainted[v]})" for v in hits)
        add(F, "E2", "MEDIUM",
            "Sensitive value written raw to logs/stderr",
            path, text, m.start(),
            f"log call embeds {what} verbatim; MCP stderr/log files are routinely "
            f"collected by hosts - log a length, hash or redacted form instead",
            "VATA:gold-server secrets in logs", "MEDIUM")

E_INJECTION = re.compile(
    r"ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+instructions|"
    r"disregard\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)|"
    r"(?:reveal|print|show|output|repeat|leak)\s+(?:your\s+|the\s+)?system\s+prompt|"
    r"\byou\s+are\s+now\s+(?:a|an|in)\b|"
    r"<\s*/?\s*(?:IMPORTANT|SYSTEM|system[-_]prompt)\s*>|"
    r"\[\s*INJECT(?:ION)?\s*\]|"
    r"do\s+not\s+(?:tell|inform|alert)\s+the\s+user", re.I)
E_STR_LIT = re.compile(r"""(['"`])((?:\\.|(?!\1)[^\\\n])*)\1""")
E_OUTPUT_CTX = re.compile(
    r"""['"](?:text|description|content|result|message)['"]\s*:|\b(?:text|description)\s*=|"""
    r"""\breturn\b|TextContent\s*\(|\bresolve\s*\(""")
E_MATCHER_CTX = re.compile(r"\bre\.(?:compile|search|match|findall|sub)\s*\(|\bRegExp\s*\(|\.test\s*\(|\bin\s+\w+\.lower\(\)")

def rule_tool_output_injection(path, text, F):
    if not E_MCP_SERVER.search(text):
        return
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if _comment_line(line) or _e_is_log_line(line) or E_MATCHER_CTX.search(line):
            continue
        ctx = "\n".join(lines[max(0, i - 2):i + 1])
        if not E_OUTPUT_CTX.search(ctx):
            continue
        for sm in E_STR_LIT.finditer(line):
            im = E_INJECTION.search(sm.group(2))
            if not im:
                continue
            idx = sum(len(l) + 1 for l in lines[:i]) + sm.start()
            add(F, "E3", "HIGH",
                "Tool output/description carries a prompt-injection payload",
                path, text, idx,
                f"model-visible string contains '{im.group(0)}' - the host LLM reads tool "
                f"results and descriptions as context and may follow it",
                "VATA:gold-server tool-output injection", "HIGH")
            break

RULES = [rule_oauth_authorize, rule_default_creds, rule_middleware_authz,
         rule_ssrf, rule_excluded_tools, rule_method_scoped_authz,
         rule_client_issuer_binding,
         rule_pkce_not_enforced, rule_authcode_replay,
         rule_cross_tenant_list, rule_fastmcp_auth_default, rule_mcp_sdk_version,
         rule_session_leak, rule_secrets_in_logs, rule_tool_output_injection]

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



# ---- HTML Report Generation (canonical payload only) ----
def generate_html_report(canonical_payload, output_file):
    """Generate OAuth assessment report from canonical_payload."""
    from datetime import datetime
    
    target = canonical_payload.get("target", "unknown")
    attempted = canonical_payload.get("probes_attempted", 0)
    passed = canonical_payload.get("probes_passed", 0)
    failed = canonical_payload.get("probes_failed", 0)
    observed = canonical_payload.get("probes_observed", 0)
    not_observed = canonical_payload.get("probes_not_observed", 0)
    excluded = canonical_payload.get("probes_excluded", 0)
    scan_date = canonical_payload.get("scan_date", "Unknown")
    tool_version = canonical_payload.get("tool_version", "1.1.0")
    
    auth = canonical_payload.get("authorization", {})
    findings = canonical_payload.get("findings", [])
    report_hash = canonical_payload.get("report_hash", "")
    
    auth_by = auth.get("authorized_by", "Unknown")
    auth_basis = auth.get("auth_basis", "Unknown")
    contact = auth.get("contact", "Unknown")
    assessed_by = auth.get("assessed_by", "Unknown")
    
    findings_html = ""
    if findings:
        findings_html = '<div class="section"><div class="section-title">Findings</div>'
        for f in findings:
            severity = f.get("severity", "INFO")
            title = f.get("title", "Unknown")
            evidence = f.get("evidence", "")
            findings_html += f'<div style="margin-bottom:15px; padding:15px; border-left:4px solid #dc2626;"><strong>{severity}: {title}</strong><br/><pre style="font-size:12px; white-space:pre-wrap;">{evidence}</pre></div>'
        findings_html += '</div>'
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuth Security Assessment — {target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6; max-width: 1000px; margin: 0 auto; padding: 40px 20px; background: #f9fafb; color: #1f2937; }}
        .header {{ border-bottom: 3px solid #059669; padding-bottom: 30px; margin-bottom: 40px; }}
        h1 {{ font-size: 28px; margin-bottom: 10px; color: #111827; }}
        .subtitle {{ color: #6b7280; font-size: 14px; }}
        .auth-block {{ background: #ecfdf5; border: 1px solid #a7f3d0; padding: 20px; margin-bottom: 30px; border-radius: 6px; }}
        .auth-line {{ margin-bottom: 10px; font-size: 14px; }}
        .auth-label {{ font-weight: 600; color: #059669; display: inline-block; width: 160px; }}
        .section {{ margin-bottom: 40px; }}
        .section-title {{ font-size: 18px; font-weight: 600; border-bottom: 2px solid #e5e7eb; padding-bottom: 12px; margin-bottom: 20px; color: #111827; }}
        .probe-stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 15px; margin-bottom: 30px; }}
        .stat-box {{ background: white; border: 1px solid #e5e7eb; padding: 15px; border-radius: 6px; text-align: center; }}
        .stat-number {{ font-size: 28px; font-weight: 700; color: #059669; margin-bottom: 8px; }}
        .stat-label {{ font-size: 11px; color: #6b7280; text-transform: uppercase; font-weight: 600; }}
        .hash-section {{ background: white; border: 1px solid #e5e7eb; padding: 20px; border-radius: 6px; margin-bottom: 30px; }}
        .hash-value {{ background: #f3f4f6; padding: 16px; border-radius: 4px; font-family: monospace; font-size: 12px; word-break: break-all; margin: 12px 0; color: #374151; }}
        .footer {{ border-top: 1px solid #e5e7eb; padding-top: 30px; margin-top: 40px; font-size: 12px; color: #6b7280; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>OAuth Security Assessment Report</h1>
        <div class="subtitle">{target} — Live Server Analysis</div>
        <div class="subtitle" style="margin-top: 10px;">Scan Date: {scan_date}</div>
    </div>

    <div class="auth-block">
        <div class="auth-line"><span class="auth-label">Authorized By:</span> {auth_by}</div>
        <div class="auth-line"><span class="auth-label">Authorization Basis:</span> {auth_basis}</div>
        <div class="auth-line"><span class="auth-label">Contact:</span> {contact}</div>
        <div class="auth-line"><span class="auth-label">Assessed by:</span> {assessed_by}</div>
    </div>

    <div class="section">
        <div class="section-title">Probe Execution Summary</div>
        <div class="probe-stats">
            <div class="stat-box"><div class="stat-number">{attempted}</div><div class="stat-label">Attempted</div></div>
            <div class="stat-box"><div class="stat-number">{passed}</div><div class="stat-label">Passed</div></div>
            <div class="stat-box"><div class="stat-number">{failed}</div><div class="stat-label">Failed</div></div>
            <div class="stat-box"><div class="stat-number">{observed}</div><div class="stat-label">Observation</div></div>
            <div class="stat-box"><div class="stat-number">{not_observed}</div><div class="stat-label">Not Observed</div></div>
            <div class="stat-box"><div class="stat-number">{excluded}</div><div class="stat-label">Excluded*</div></div>
        </div>
    </div>

    {findings_html}

    <div class="section">
        <div class="section-title">Report Integrity</div>
        <div class="hash-section">
            <div style="font-weight: 600; margin-bottom: 12px; color: #111827;">Hash (SHA256)</div>
            <div class="hash-value">{report_hash}</div>
            <div style="margin-top: 20px; font-size: 13px; color: #6b7280; line-height: 1.6;">
                <strong>Verification:</strong> Extract report_hash from JSON, remove it, recompute SHA256 of sorted JSON, compare.
                <br/><br/>
                <strong>Authenticity:</strong> Server logs showing {attempted} HTTP requests prove the scan occurred.
            </div>
        </div>
    </div>

    <div class="footer">
        <div class="footer-title">Scanner Information</div>
        <div>Tool: mcp-authscan {tool_version}</div>
        <div>All values extracted from canonical_payload. No arithmetic in renderer.</div>
    </div>
</body>
</html>
"""
    
    with open(output_file, 'w') as f:
        f.write(html_content)
    
    return output_file




def main():
    ap = argparse.ArgumentParser(description=f"VATA mcp_authscan v{VERSION}")

    # Override argparse's default exit code for usage errors (exit 2 → exit 6)
    def argparse_error(message):
        ap.print_usage(sys.stderr)
        print(f"mcp_authscan: error: {message}", file=sys.stderr)
        sys.exit(6)
    ap.error = argparse_error

    ap.add_argument("target", help="path to MCP server repo/dir OR http(s)://host:port for live scanning")
    ap.add_argument("--json", action="store_true", help="emit JSON + report sha256")
    ap.add_argument("--html", action="store_true", help="emit HTML report (shareable, print-friendly)")
    ap.add_argument("--sarif", action="store_true", help="emit SARIF 2.1.0 (GitHub code scanning)")
    ap.add_argument("--include-tests", action="store_true", help="also scan test files")
    ap.add_argument("--exclude", action="append", default=[], metavar="DIR",
                    help="skip a directory relative to target (repeatable)")
    ap.add_argument("--output", "-o", metavar="FILE",
                    help="output file for HTML/JSON report")
    ap.add_argument("--fail-on", choices=["critical", "high", "medium"], default="high",
                    help="exit 1 if findings at or above this severity are found (default: high)")
    ap.add_argument("--allow-private", action="store_true",
                    help="allow scanning private/loopback targets (127.0.0.0/8, 10.0.0.0/8, etc) - opt-in for lab and staging")

    # Authorization and compliance tracking
    ap.add_argument("--authorized-by", metavar="NAME",
                    help="person who authorized the scan")
    ap.add_argument("--client-name", metavar="NAME",
                    help="client organization name")
    ap.add_argument("--client-title", metavar="TITLE",
                    help="authorizer's title/role at client")
    ap.add_argument("--auth-basis", metavar="BASIS",
                    help="authorization basis (VRP, contract, scope document)")
    ap.add_argument("--ticket-ref", metavar="REF",
                    help="client's ticket/tracking reference")
    ap.add_argument("--contact", metavar="EMAIL",
                    help="contact email for scan authorization")
    ap.add_argument("--scope", metavar="SCOPE",
                    help="scan scope (what was tested)")

    args = ap.parse_args()

    # AUTHORIZATION CHECK: refuse to run without authorization metadata
    # Check if this is a fixture run (will be determined when we parse the target URL)
    # For now, check if target looks like localhost before we validate authorization
    temp_p = urlparse(args.target) if args.target.startswith("http") else None
    is_fixture = temp_p and temp_p.hostname in ('localhost', '127.0.0.1', '::1')

    # Authorization required for REAL scans, but NOT for fixture runs
    if not is_fixture:
        if not args.authorized_by:
            print("[!] ERROR: --authorized-by is required for real network scans", file=sys.stderr)
            print("[!] Usage: --authorized-by 'Name' --auth-basis 'basis' --contact 'email@example.com'", file=sys.stderr)
            sys.exit(2)

        if not args.auth_basis:
            print("[!] ERROR: --auth-basis is required", file=sys.stderr)
            sys.exit(2)

        if not args.contact:
            print("[!] ERROR: --contact is required", file=sys.stderr)
            sys.exit(2)

        # Validate authorization metadata for real scans
        if not args.authorized_by or not args.auth_basis or not args.contact:
            print(f"[!] ERROR: Authorization fields are required and must be non-empty.", file=sys.stderr)
            print(f"[!]   --authorized-by: {args.authorized_by or '(missing)'}", file=sys.stderr)
            print(f"[!]   --auth-basis: {args.auth_basis or '(missing)'}", file=sys.stderr)
            print(f"[!]   --contact: {args.contact or '(missing)'}", file=sys.stderr)
            sys.exit(2)

    # Auto-detect: live server (http(s)://) or source code directory?
    scan_mode = None
    scan_start_time = time.time()
    probes_attempted = 0
    probes_passed = 0
    probes_not_observed = 0
    probes_observed = 0
    probes_excluded = 0
    discovery_info = None
    repo_url = None
    branch = None
    commit_sha_long = None
    commit_sha_short = None
    oauth_records = []  # Initialize for all paths
    probe_results = []

    if args.target.startswith("http://") or args.target.startswith("https://"):
        # Detect fixture runs (localhost, 127.0.0.1)
        p = urlparse(args.target)
        is_fixture = p.hostname in ('localhost', '127.0.0.1', '::1')

        if is_fixture and args.authorized_by:
            print("[!] ERROR: Fixture runs (localhost) cannot accept third-party authorization.", file=sys.stderr)
            print("[!] --authorized-by is only valid for real network scans of live servers.", file=sys.stderr)
            print("[!] Fixture runs demonstrate probe functionality; they are not production assessments.", file=sys.stderr)
            sys.exit(2)

        # Validate target host if --allow-private not set (opt-in DNS rebinding protection)
        if not args.allow_private:
            try:
                if p.hostname:
                    validate_target_host(p.hostname, p.port or (443 if args.target.startswith("https") else 80))
            except ValueError as e:
                print(f"[!] Target validation failed: {e}", file=sys.stderr)
                sys.exit(3)

        try:
            result_tuple = scan_live_server(args.target)
            F, server_reachable, probe_status, discovery_info, oauth_result = result_tuple
            if isinstance(oauth_result, tuple) and len(oauth_result) == 2:
                oauth_records, probe_results = oauth_result
            else:
                raise ValueError(f"Expected (oauth_records, probe_results) tuple, got {type(oauth_result)}: {oauth_result}")
        except Exception as e:
            print(f"[!] scan_live_server failed: {type(e).__name__}: {e}", file=sys.stderr)
            raise
        scan_mode = "LIVE_ENDPOINT_ASSESSMENT"

        # Log discovery results (only if successful, not DISCOVERY_INCOMPLETE)
        if discovery_info and discovery_info.get('status') != 'DISCOVERY_INCOMPLETE':
            print(f"[+] OAuth discovery successful", file=sys.stderr)
            if 'method' in discovery_info:
                print(f"    Method: {discovery_info['method']}", file=sys.stderr)
            if 'endpoints' in discovery_info:
                print(f"    Endpoints: {len(discovery_info['endpoints'])} discovered", file=sys.stderr)
            if 'discovered_hosts' in discovery_info:
                print(f"    Hosts: {', '.join(discovery_info['discovered_hosts'])}", file=sys.stderr)

        # Check for zero-auth vulnerability
        if discovery_info and discovery_info.get("status") == "ZERO_AUTH_DETECTED":
            print(f"[!] ZERO-AUTH VULNERABILITY: MCP server is accessible without authentication", file=sys.stderr)
            findings = [{
                "rule": "ZERO-AUTH",
                "severity": "CRITICAL",
                "title": "Unauthenticated MCP endpoint",
                "evidence": "POST /initialize responded with HTTP 200 without authentication",
                "confidence": "HIGH",
                "file": target_url,
                "line": 0,
                "ref": "ZERO-AUTH",
                "is_live_finding": True,
                "request_method": "POST",
                "request_body": "",
                "response_status": 200,
                "response_body": "",
                "response_preview": "HTTP 200 - MCP endpoint accessible",
                "interpretation": "MCP server requires no authentication. Any client can call tools, resources and prompts.",
                "remediation": "Implement authentication and authorization controls for all MCP endpoints."
            }]
            probe_status = {'attempted': 0, 'passed': 0, 'failed': 0, 'not_observed': 0, 'observation': 0}
            return findings, True, probe_status, discovery_info, ([], [])

        # Check for discovery incomplete (OAuth detected but discovery chain failed)
        if discovery_info and discovery_info.get("status") == "DISCOVERY_INCOMPLETE":
            print(f"[!] OAuth detected (HTTP 401) but discovery chain failed. Cannot complete scan.", file=sys.stderr)
            sys.exit(5)

        if not server_reachable:
            # Distinguish failure modes by discovery_info status
            if discovery_info is None:
                # Can't connect at all
                print(f"[!] Target unreachable. Scan aborted.", file=sys.stderr)
                sys.exit(3)
            elif discovery_info.get("status") == "PREFLIGHT_FAILED":
                # Preflight failed (target not MCP)
                sys.exit(4)
            else:
                # Other error (e.g., connection timeout)
                sys.exit(3)
        else:
            # Server reachable: use actual probe status counts from scanner
            # This correctly distinguishes:
            # - PASSED: 401/403 (server correctly rejected)
            # - NOT_OBSERVED: 404/5xx (endpoint doesn't exist or error)
            # - FINDINGS: vulnerabilities detected
            probes_attempted = probe_status.get('attempted', 0)
            probes_passed = probe_status['passed']
            probes_not_observed = probe_status['not_observed']
            probes_observed = probe_status.get('observation', 0)
            probes_excluded = probe_status.get('excluded', 0)

        # Verify accounting before rendering
        # Attempted = probes actually sent (may exclude those with unmet prerequisites)
        # Excluded = probes never sent (verdict NOT_OBSERVED with prerequisite_met=False)
        # Total probe set = 9 (always attempted + excluded = 9)
        attempted = probe_status.get("attempted", 0)
        excluded = probe_status.get("excluded", 0)
        passed = probe_status.get("passed", 0)
        failed = probe_status.get("failed", 0)
        not_observed = probe_status.get("not_observed", 0)
        observation = probe_status.get("observation", 0)

        # Verify: verdicts must sum to attempted
        verdicts = passed + failed + not_observed + observation
        if verdicts != attempted:
            print(f"[!] ACCOUNTING ERROR: {verdicts} verdicts (expected {attempted} attempted)", file=sys.stderr)
            sys.exit(5)

        # Verify: attempted + excluded = 9
        if attempted + excluded != 9:
            print(f"[!] ACCOUNTING ERROR: {attempted} attempted + {excluded} excluded = {attempted + excluded} (expected 9)", file=sys.stderr)
            sys.exit(5)

        # Update probes_attempted in case it was 0 before
        probes_attempted = attempted

        # Exit 5: Coverage rule - need at least 7 conclusive verdicts
        # Conclusive = PASS, FAIL, OBSERVATION (NOT_OBSERVED is inconclusive)
        # If we have less than 7 conclusive verdicts, assessment is incomplete
        if scan_mode == "LIVE_ENDPOINT_ASSESSMENT":
            verdicts_reached = passed + failed + observation
            inconclusive = not_observed

            # Require at least 7 conclusive verdicts out of the attempted probes
            # If we have fewer, exit 5 (incomplete assessment)
            if verdicts_reached < 7:
                print(f"[!] Incomplete assessment: {verdicts_reached} probes reached conclusive verdicts. {inconclusive} NOT_OBSERVED (inconclusive), {excluded} excluded.", file=sys.stderr)
                sys.exit(5)

    else:
        print(f"[*] Scanning source code directory", file=sys.stderr)
        F = scan(args.target, args.include_tests, args.exclude)
        scan_mode = "SOURCE_CODE_ASSESSMENT"
        probes_attempted = len(F)  # For source code, probes = findings flagged
        probes_passed = probes_attempted  # All checks ran
        probe_results = []  # No detailed probe results for source code scan
        probe_status = {'attempted': 0, 'passed': 0, 'failed': 0, 'not_observed': 0, 'findings': 0}
        discovery_info = None

    elapsed_seconds = time.time() - scan_start_time
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    F.sort(key=lambda x: (order.get(x["severity"], 9), x["file"], x["line"]))

    # Generate report with authorization block if credentials provided
    report_lines = []
    auth_block = ""
    metadata_block = ""
    findings_by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in F:
        sev = finding.get("severity", "LOW")
        if sev in findings_by_severity:
            findings_by_severity[sev] += 1

    # For both authorized scans and fixture runs, create metadata objects
    # Fixture runs have empty authorization, but still need metadata for reporting
    if args.authorized_by or is_fixture:
        from mcp_authscan.authorization import ScanAuthorization, ScanMetadata, report_header_with_authorization

        # For real scans, populate authorization; for fixtures, leave empty
        auth = ScanAuthorization(
            authorized_by=args.authorized_by or "",
            client_name=args.client_name or "",
            client_title=args.client_title or "",
            auth_basis=args.auth_basis or "",
            ticket_ref=args.ticket_ref or "",
            contact=args.contact or ""
        )

        # For source code assessments, extract git metadata and count files
        files_examined = None
        files_total = None
        files_excluded = []

        if scan_mode == "SOURCE_CODE_ASSESSMENT" and not args.target.startswith("http"):
            repo_url, branch, commit_sha_long = get_git_metadata(args.target)
            if commit_sha_long:
                commit_sha_short = commit_sha_long[:12]

            # Count unique files examined
            files_examined = len(set(f.get("file") for f in F if f.get("file")))

            # Reconcile file counts: excluded vs. irrelevant vs. analyzed
            try:
                target_path = Path(args.target).resolve()
                excluded_by_category = 0
                recognized_irrelevant = 0
                total_src = 0

                for file in target_path.rglob("*"):
                    if not file.is_file():
                        continue

                    # Check file extension first
                    if file.suffix not in SRC_EXT:
                        continue

                    total_src += 1

                    # Check if in excluded directory
                    if any(part in SKIP_DIR for part in file.parts):
                        excluded_by_category += 1
                        continue

                    # Check if test file or irrelevant pattern
                    if (any(part in TEST_DIR for part in file.parts) or
                        TEST_FILE.search(file.name) or
                        MINIFIED_FILE.search(file.name)):
                        recognized_irrelevant += 1

                files_total = total_src
                # Report as: "113 analyzed; 189 excluded by category, 48 recognized as irrelevant"
                if excluded_by_category > 0 or recognized_irrelevant > 0:
                    files_examined_detail = f"{files_examined} analyzed"
                    exclusions = []
                    if excluded_by_category > 0:
                        exclusions.append(f"{excluded_by_category} excluded by category")
                    if recognized_irrelevant > 0:
                        exclusions.append(f"{recognized_irrelevant} recognized as irrelevant")
                    files_excluded = [files_examined_detail] + exclusions
            except:
                files_excluded = list(SKIP_DIR)

        # Define what wasn't tested based on assessment type
        not_tested = []
        if scan_mode == "SOURCE_CODE_ASSESSMENT":
            not_tested = [
                "Live OAuth flows and endpoint behavior",
                "Runtime configuration and deployment settings",
                "Infrastructure setup (TLS, CORS, reverse proxies, WAF)",
                "Dependency versions at runtime",
                "Environment secrets and credentials",
                "Network-level access controls",
                "What the deployed service actually does vs. code"
            ]
        elif scan_mode == "LIVE_ENDPOINT_ASSESSMENT":
            not_tested = [
                "Source code review and design patterns",
                "Dependency vulnerabilities (CVE check)",
                "Secrets in repository history",
                "Comments and documentation"
            ]
            # If we did OAuth discovery, note that MCP resource endpoint itself wasn't tested
            if discovery_info and discovery_info.get('status') != 'DISCOVERY_INCOMPLETE':
                not_tested.insert(0, "MCP resource endpoint behavior (only OAuth server configuration assessed via RFC 9728 → RFC 8414 discovery)")

        metadata = ScanMetadata(
            scope="OAuth server configuration only" if scan_mode == "LIVE_ENDPOINT_ASSESSMENT" else (args.scope or "Full assessment"),
            probe_set_version=PROBE_SET_VERSION,
            not_tested=not_tested,
            target=args.target,
            repo_url=repo_url,
            branch=branch,
            commit_sha=commit_sha_short,
            files_examined=files_examined,
            files_total=files_total,
            files_excluded=files_excluded,
            probes_attempted=probes_attempted,
            probes_passed=probes_passed,
            probes_failed=len(F),  # Number of findings = failed probes
            probes_observed=probes_observed,
            probes_not_observed=probes_not_observed,
            probes_excluded=probes_excluded,
            elapsed_seconds=elapsed_seconds,
            discovery_info=discovery_info
        )

        report_lines.append("=" * 80)
        report_lines.append("MCP-AUTHSCAN SECURITY REPORT")
        report_lines.append("=" * 80)
        report_lines.append("")
        report_lines.append("Scanner: mcp-authscan v" + VERSION)
        report_lines.append(f"Scan Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}")
        report_lines.append("Repository: https://github.com/LHMisme420/mcp-authscan")
        report_lines.append("")

        # Add scan verdict if incomplete
        if discovery_info and discovery_info.get('status') == 'DISCOVERY_INCOMPLETE':
            report_lines.append("⚠ SCAN INCOMPLETE")
            report_lines.append("-" * 80)
            report_lines.append("MCP server detected, but OAuth endpoint discovery failed.")
            report_lines.append("No probes executed. Assessment incomplete.")
            report_lines.append("-" * 80)
            report_lines.append("")

        report_lines.extend(auth.format_block().split("\n"))
        report_lines.append("")
        report_lines.append("ASSESSMENT MODE")
        report_lines.append("-" * 80)
        if scan_mode == "LIVE_ENDPOINT_ASSESSMENT":
            report_lines.append("Type: LIVE ENDPOINT TESTING")
            report_lines.append("Method: Runtime probing of live MCP server endpoints")
            report_lines.append("Scope: Network-based assessment of running server")
        else:
            report_lines.append("Type: SOURCE CODE ASSESSMENT")
            report_lines.append("Method: Static analysis of codebase for OAuth/security patterns")
            report_lines.append("Scope: Code repository examination")
        report_lines.append("-" * 80)
        report_lines.append("")
        report_lines.extend(metadata.format_block().split("\n"))
        report_lines.append("")

        # Add fixture disclaimer for localhost/test targets
        parsed_target = urlparse(args.target) if args.target.startswith("http") else None
        if parsed_target and parsed_target.hostname in ["127.0.0.1", "localhost", "[::1]"]:
            report_lines.append("⚠ TEST FIXTURE DISCLAIMER")
            report_lines.append("-" * 80)
            report_lines.append("This scan was run against a local test fixture (not a production server).")
            report_lines.append("Findings demonstrate probe functionality, not evidence of real-world deployment.")
            report_lines.append("-" * 80)
            report_lines.append("")

        report_lines.append("FINDINGS SUMMARY")
        report_lines.append("-" * 80)
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            report_lines.append(f"  {sev}: {findings_by_severity[sev]}")
        report_lines.append(f"  TOTAL: {len(F)}")
        report_lines.append("-" * 80)
        report_lines.append("")

    # Build canonical payload dict BEFORE rendering (for integrity: hash covers displayed values)
    canonical_payload = {
        "target": args.target,
        "scan_mode": scan_mode,
        "probe_set_version": PROBE_SET_VERSION,
        "probes_attempted": probes_attempted,
        "probes_passed": probes_passed,
        "probes_failed": len(F),
        "probes_observed": probes_observed,
        "probes_not_observed": probes_not_observed,
        "probes_excluded": probes_excluded,
        "findings_count": len(F),
        "scan_date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "tool_version": VERSION,
        "findings": F,
    }
    if args.authorized_by:
        canonical_payload["authorization"] = {
            "authorized_by": args.authorized_by,
            "auth_basis": args.auth_basis,
            "contact": args.contact,
            "assessed_by": "Leroy H. Mason",  # Fixed assessor for now
        }
    if commit_sha_long:
        canonical_payload["commit_sha"] = commit_sha_long

    # Hash the canonical payload (this is what the report signature covers)
    payload_json = json.dumps(canonical_payload, sort_keys=True)
    payload_hash = hashlib.sha256(payload_json.encode()).hexdigest()
    canonical_payload["report_hash"] = payload_hash

    if args.html:
        html_file = generate_html_report(canonical_payload, args.output or "mcp-authscan-report.html")
        print(f"[+] HTML report saved to {html_file}")
    if args.json:
        print(json.dumps(canonical_payload, indent=2))
    if args.sarif and not args.json:
        print(json.dumps(to_sarif(F, args.target), indent=2))
    else:
        # Text output with optional authorization header
        # Check for discovery incomplete status
        if discovery_info and discovery_info.get("status") == "DISCOVERY_INCOMPLETE":
            print("DISCOVERY STATUS")
            print("-" * 80)
            print("PREFLIGHT CHECK: PASSED")
            print("  POST /initialize returned HTTP 401 with OAuth challenge")
            print("  This confirms an MCP server with OAuth exists at the target path.")
            print("")
            print("DISCOVERY CHAIN: INCOMPLETE")
            print("  RFC 9728 → RFC 8414 discovery attempted but did not complete.")
            print("  Unable to discover OAuth endpoint URLs (token, authorize, etc.)")
            print("  Cannot proceed without discovered endpoint URLs.")
            print("")
            print("PROBES: NOT RUN")
            print("  All 12 probes marked NOT_OBSERVED (no endpoints to test)")
            print("-" * 80)
            print("")
            return  # Stop here - don't run probes

        # Build summary from actual probe records (data-driven only)
        report_lines.append("PROBE RESULTS SUMMARY")
        report_lines.append("-" * 80)
        if oauth_records:
            # Accounting check
            check_counts(oauth_records)
            # Human-readable evidence driven by the ProbeRecord list
            summary_lines = render_summary(oauth_records)
            report_lines.extend(summary_lines)
        else:
            # Probes never ran (discovery incomplete, unreachable, etc.)
            report_lines.append("No OAuth probes were attempted.")
        report_lines.append("-" * 80)
        report_lines.append("")

        # Print the main report with all sections (authorization, assessment, scan metadata, findings, probe results)
        print("\n".join(report_lines))

        if not F:
            print("No findings. (Absence of finding is not proof of safety.)")
        else:
            print("DETAILED FINDINGS")
            print("-" * 80)
            print("")
            for x in F:
                # For live OAuth findings, show severity only. For code findings, show severity/confidence.
                if x.get("is_live_finding"):
                    print(f"[{x['severity']}] {x['rule']}  {x['title']}")
                    print(f"  {x['file']}  ({x['ref']})")
                else:
                    print(f"[{x['severity']}/{x['confidence']}] {x['rule']}  {x['title']}")
                    print(f"  {x['file']}:{x['line']}  ({x['ref']})")

                # For live endpoint findings, show full request/response evidence
                if x.get("is_live_finding"):
                    print(f"\n  REQUEST:")
                    print(f"    Method: {x['request_method']}")
                    if x['request_body']:
                        print(f"    Body: {x['request_body'][:200]}")
                    print(f"\n  RESPONSE:")
                    print(f"    Status: HTTP {x['response_status']}")
                    if x['response_preview']:
                        print(f"    Body Preview: {x['response_preview'][:200]}")
                    print(f"\n  INTERPRETATION:")
                    print(f"    {x['interpretation']}")
                    print(f"\n  REMEDIATION:")
                    print(f"    {x['remediation']}")
                else:
                    print(f"  {x['evidence']}")
                    print(x["snippet"])
                print()

        # Footer with hash if authorization provided
        if report_lines:
            report_lines_for_hash = [line for line in report_lines if not line.strip().startswith("Elapsed Time:")]
            full_report = "\n".join(report_lines_for_hash) + f"\nDETAILED FINDINGS\n{'-' * 80}\n"
            for x in F:
                full_report += f"[{x['severity']}/{x['confidence']}] {x['rule']}  {x['title']}\n"
                if x.get("is_live_finding"):
                    full_report += f"  {x['file']}  ({x['ref']})\n"
                else:
                    full_report += f"  {x['file']}:{x['line']}  ({x['ref']})\n"

                # For live endpoint findings, include full evidence in report hash
                if x.get("is_live_finding"):
                    full_report += f"\n  REQUEST:\n"
                    full_report += f"    Method: {x['request_method']}\n"
                    if x['request_body']:
                        full_report += f"    Body: {x['request_body']}\n"
                    full_report += f"\n  RESPONSE:\n"
                    full_report += f"    Status: HTTP {x['response_status']}\n"
                    if x['response_preview']:
                        full_report += f"    Body Preview: {x['response_preview']}\n"
                    full_report += f"\n  INTERPRETATION:\n"
                    full_report += f"    {x['interpretation']}\n"
                    full_report += f"\n  REMEDIATION:\n"
                    full_report += f"    {x['remediation']}\n"
                else:
                    full_report += f"  {x['evidence']}\n{x['snippet']}\n"
                full_report += "\n"

            # Use canonical payload hash (covers probe counts, auth, and findings)
            report_hash = payload_hash
            print("=" * 80)
            print("[Hash computed over: authorization + scan mode + probe status + findings.")
            print(" Excludes: report_hash field itself (added after hash is computed).]")
            print(f"REPORT HASH (SHA256): {report_hash}")
            print("")
            print("[Verification: To verify integrity, use: --json flag to get canonical payload,")
            print(" remove report_hash field, recompute SHA256 of sorted JSON, and compare.]")
            print("")
            print("[Authenticity: Real proof of scan is Heath's server logs showing the probes.")
            print(" Hash provides integrity; logs provide proof the scan actually occurred.]")
            print("=" * 80)
            if metadata.elapsed_seconds is not None:
                print(f"Elapsed Time: {metadata.elapsed_seconds:.2f} seconds")
        else:
            print(f"{len(F)} finding(s).")

    # Exit code based on findings severity and --fail-on threshold
    thr_map = {"critical": 0, "high": 1, "medium": 2}
    thr = thr_map[args.fail_on]
    REVIEW = {"A4", "A5", "A6", "B2"}  # Review-list rules warn only

    # Check if any finding meets or exceeds the threshold
    findings_at_threshold = False
    for finding in F:
        severity = finding.get("severity", "LOW")
        sev_level = order.get(severity, 9)
        rule = finding.get("rule", finding.get("ref", ""))  # Live findings use "ref", source code uses "rule"

        if sev_level <= thr and rule not in REVIEW:
            findings_at_threshold = True
            break

    if findings_at_threshold:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()

# OAuth 2.1 Compliance Checks (v1.1)
OAUTH_2_1_CHECKS = {
    "implicit_flow_used": [r'response_type.*implicit', r'response_type.*token', r'flow.*implicit'],
    "pkce_plain_allowed": [r'code_challenge_method.*plain', r'method.*=.*plain', r'plain.*PKCE'],
    "pkce_not_required": [r'code_challenge.*optional', r'pkce.*not.*required'],
    "issuer_not_validated": [r'issuer.*validation.*skip', r'skipIssuerValidation.*true', r'validateIssuer.*false'],
    "weak_state_validation": [r'state.*length.*<.*16', r'state.*entropy.*weak'],
    "response_type_confusion": [r'response_type.*multiple', r'accepts.*code.*token'],
    "dop_not_enforced": [r'dpop.*optional', r'dpop.*not.*required'],
}

# OAuth 2.1 Compliance Checks (v1.1)
OAUTH_2_1_CHECKS = {
    "implicit_flow_used": [r'response_type.*implicit', r'response_type.*token', r'flow.*implicit'],
    "pkce_plain_allowed": [r'code_challenge_method.*plain', r'method.*=.*plain', r'plain.*PKCE'],
    "pkce_not_required": [r'code_challenge.*optional', r'pkce.*not.*required'],
    "issuer_not_validated": [r'issuer.*validation.*skip', r'skipIssuerValidation.*true', r'validateIssuer.*false'],
    "weak_state_validation": [r'state.*length.*<.*16', r'state.*entropy.*weak'],
    "response_type_confusion": [r'response_type.*multiple', r'accepts.*code.*token'],
    "dop_not_enforced": [r'dpop.*optional', r'dpop.*not.*required'],
}

# OAuth 2.1 Compliance Checks (v1.1)
OAUTH_2_1_CHECKS = {
    "implicit_flow_used": [r'response_type.*implicit', r'response_type.*token', r'flow.*implicit'],
    "pkce_plain_allowed": [r'code_challenge_method.*plain', r'method.*=.*plain', r'plain.*PKCE'],
    "pkce_not_required": [r'code_challenge.*optional', r'pkce.*not.*required'],
    "issuer_not_validated": [r'issuer.*validation.*skip', r'skipIssuerValidation.*true', r'validateIssuer.*false'],
    "weak_state_validation": [r'state.*length.*<.*16', r'state.*entropy.*weak'],
    "response_type_confusion": [r'response_type.*multiple', r'accepts.*code.*token'],
    "dop_not_enforced": [r'dpop.*optional', r'dpop.*not.*required'],
}

# ---- HTML Report Generation ----

