# Audit Findings: resource_probes.py and README

**Status:** CRITICAL ISSUES IDENTIFIED  
**Date:** October 28, 2026  
**Scope:** resource_probes.py (5 resource endpoint probes) and README.md documentation  
**Severity:** CRITICAL - Same architectural flaw as token-cors false negative

---

## Root Cause: Shared Response Architecture Missing

Each of the 5 resource probes makes its own HTTP request and independently decides its verdict. There is no guarantee that the status code, headers, and conclusion came from the same response. This is the same architectural flaw as the token-cors false negative.

**Solution:** Refactor to use one shared HTTP fetcher that captures (status_code, headers, body) and returns a unified ProbeRecord.

---

## Critical Issues in resource_probes.py

### 1. probe_endpoint_cors: False PASS on 401/405/500/HTML (CRITICAL)

**Location:** Lines 272-336  
**Issue:** No HTTP status code check anywhere in function

```python
response = requests.post(target_url, json=payload, headers=headers, timeout=5, verify=True)
# ... No check of response.status_code before evaluating headers ...
# Falls through to PASS "CORS properly restricted" regardless of status
```

**Problem:**
- A 401, 405, 500, or HTML error page with no ACAO header all report PASS
- By contract (README): "A 404, 405, 5xx... is NOT_OBSERVED"
- Same false negative as token-cors

**Fix Required:** Check `response.status_code` before evaluating ACAO header
- If 401/403/5xx/4xx: return NOT_OBSERVED
- If 200: evaluate ACAO header
- If HTML (content-type not application/json): return NOT_OBSERVED

---

### 2. Severity "MODERATE" Doesn't Exist (HIGH)

**Location:** Line 285  
**Issue:** Uses undefined severity level

```python
severity = "CRITICAL" if allow_credentials else "MODERATE"
```

**Problem:**
- Vocabulary is CRITICAL/HIGH/MEDIUM only
- "MODERATE" is not defined
- --fail-on high will never catch MODERATE findings
- Puts unfixable vulnerability below the gate

**Fix Required:** Change to HIGH (or CRITICAL if this is critical)
```python
severity = "CRITICAL" if allow_credentials else "HIGH"
```

---

### 3. probe_mcp_preflight: Docstring Violation (CRITICAL)

**Location:** Lines 26-111  
**Docstring:** "PASS if we get 401/403 with WWW-Authenticate"  
**Actual behavior:** PASS on any 200 with valid JSON-RPC

```python
if response.status_code in [401, 403]:
    # ... PASS cases ...
    return ProbeRecord(...)

# ... later ...
try:
    data = response.json()
    if "jsonrpc" in data:
        return ProbeRecord(  # PASS for 200 with JSON-RPC
            status="PASS",
            detail="MCP endpoint responds to JSON-RPC",
            endpoint=target_url
        )
```

**Problem:**
- An unauthenticated open MCP server returns 200 with valid JSON-RPC
- This passes preflight despite being completely open
- Violates own docstring

**Fix Required:**
- PASS must require 401/403 with WWW-Authenticate (per docstring)
- A 200 with JSON-RPC should return NOT_OBSERVED (endpoint doesn't require auth)
- Or change docstring if 200 with JSON-RPC is actually acceptable

---

### 4. probe_auth_challenge: Accepts Any WWW-Authenticate Scheme (HIGH)

**Location:** Lines 339-399  
**Issue:** No verification that the scheme is Bearer or contains resource_metadata

```python
if response.status_code == 401:
    www_auth = response.headers.get("WWW-Authenticate")
    if not www_auth:
        return FAIL
    return ProbeRecord(
        status="PASS",
        detail=f"Correctly challenges with: {www_auth}",
        endpoint=target_url
    )
```

**Problem:**
- Returns PASS for "Basic realm=admin"
- This probe's job is to verify the endpoint speaks MCP authentication
- Should verify Bearer scheme and resource_metadata field
- Green-lights Basic-auth and other non-OAuth schemes

**Fix Required:**
```python
# Verify Bearer scheme and resource_metadata field
if "Bearer" not in www_auth and "resource_metadata" not in www_auth:
    return FAIL
```

---

### 5. Same Response, Two Different Verdicts (HIGH)

**Location:** Lines 79-87 (preflight) vs lines 181-188, 262-269 (anon-initialize, anon-tools-list)  
**Issue:** A 200 serving HTML produces different verdicts

**Example: HTML response to preflight**
- In `probe_mcp_preflight`: Falls through to FAIL at HIGH "No JSON-RPC response"
- In `probe_anon_initialize`: response.json() raises, caught by bare except, returns NOT_OBSERVED
- In `probe_anon_tools_list`: response.json() raises, caught by bare except, returns NOT_OBSERVED

**Problem:**
- Same HTTP response (200 HTML)
- Three different verdicts from three different probes
- Impossible to debug what the actual response was

**Fix Required:** Unified response handling
- Detect non-JSON responses early
- Return consistent verdict across all probes
- Single source of truth for what the response was

---

### 6. body_sha256 is Hash of Re-serialization, Not Raw Response (MEDIUM)

**Locations:** Line 214 (anon-tools-list), similar in anon-initialize  
**Issue:** Hashes JSON re-serialization, not raw response bytes

```python
body_hash = hashlib.sha256(json.dumps(data).encode()).hexdigest()
```

**Problem:**
- `json.dumps()` re-serializes the data
- Two different responses that parse to the same JSON get same hash
- Hash doesn't match the bytes the server actually sent
- Makes it impossible to verify response integrity

**Fix Required:**
```python
body_hash = hashlib.sha256(response.content).hexdigest()
```

---

### 7. No Egress Guard / Private-IP Check (HIGH)

**Locations:** Lines 30, 118, 195, 277, 343  
**Issue:** Calls `requests.post(target_url)` directly with no private-IP check

```python
response = requests.post(target_url, json=payload, timeout=5, verify=True)
```

**Problem:**
- OAuth probes have private-IP guard (b74a16a)
- Resource probes do not
- Can reach internal IPs (127.0.0.1, 10.0.0.0/8, etc.)

**Fix Required:** Add private-IP check before making request
```python
from mcp_authscan._common import is_private_ip  # or similar

if is_private_ip(target_url):
    return ProbeRecord(status="NOT_OBSERVED", detail="Private IP not allowed")
```

---

## README Staleness (3 ways)

### Issue 1: Installation Instructions Wrong

**Line 36:** `pip install -e ./mcp_authscan`  
**Problem:** pyproject.toml was moved to repository root in commit 47f3cc4  
**Fix:** Change to `pip install -e .`

### Issue 2: Packaging Location Wrong

**Line 39:** "Packaging metadata lives in mcp_authscan/pyproject.toml"  
**Problem:** Moved to root directory  
**Fix:** Change to "Packaging metadata lives in ./pyproject.toml"

### Issue 3: Tool Version Out of Date

**Line 100:** "Tool version 1.1.1 and probe set 1.1.0"  
**Problem:** PyPI has 1.1.5  
**Fix:** Update to "Tool version 1.1.5 and probe set..."

### Issue 4: Dead CI Reference

**Line 77:** "A negative control runs in CI as cors-scanner-tests"  
**Problem:** Test file was deleted, job installs nothing  
**Fix:** Either restore the test or remove the reference

---

## Probe Set Version Discrepancy

**Location:** mcp_authscan/resource_probes.py line 9  
**Issue:** `RESOURCE_PROBE_SET_VERSION = "1.0.2"` but report stamps "1.1.0"

**TODO:** Find where report reads the version constant
- Check monolith.py for where it gets resource probe version
- Determine if 1.0.2 or 1.1.0 is correct
- Update the constant or the report accordingly

---

## Architecture Refactor Recommendation

All 5 issues stem from the same root: each probe independently fetches and decides.

**Refactor:** Create shared response handler
```python
def fetch_with_response(target_url, payload, headers=None, check_private_ip=True):
    """Fetch and return (status, headers, body) tuple with validation."""
    # - Check private IP
    # - Make request
    # - Return unified (status_code, headers, body)
    # Each probe uses this, no independent requests
    # Guarantees status, headers, verdict are from same response
```

This single change fixes:
- probe_endpoint_cors (no status check)
- HTML producing split verdicts
- Hash inconsistency
- Enables consistent content-type handling

---

## Summary of Required Fixes

| Issue | Severity | Type | Fix |
|-------|----------|------|-----|
| endpoint_cors: no status check | CRITICAL | Logic | Add status code validation |
| Severity "MODERATE" | HIGH | Config | Change to HIGH |
| preflight: docstring violation | CRITICAL | Logic | Verify 401/403 with WWW-Authenticate only |
| auth-challenge: any scheme accepted | HIGH | Logic | Verify Bearer + resource_metadata |
| HTML: two verdicts | HIGH | Logic | Unified response handling |
| body_sha256: re-serialization hash | MEDIUM | Logic | Hash raw response.content |
| No egress guard | HIGH | Security | Add private-IP check |
| README: install instructions | MEDIUM | Docs | Update pyproject.toml path |
| README: version out of date | LOW | Docs | Update to 1.1.5 |
| Probe version mismatch | MEDIUM | Logic | Find and fix version constant |

---

## Next Steps

1. **Read actual file lines** (don't trust line numbers from summary)
2. **Implement status code check** in probe_endpoint_cors first (critical path)
3. **Change MODERATE to HIGH** severity
4. **Create unified fetch function** to fix multiple issues at once
5. **Update README** with correct paths and versions
6. **Find probe version constant** and fix mismatch
7. **Test against actual servers** to verify fixes work

---

**Note:** oauth_probes_v2.py (token-cors false PASS on api.meant.run) not yet audited. Requires separate investigation.
