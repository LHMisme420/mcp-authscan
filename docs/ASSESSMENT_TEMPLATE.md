# MCP Server Security Assessment

- Client: {{CLIENT}}
- Target: {{TARGET_HOST}}
- Assessment ID: {{ASSESSMENT_ID}}
- Document version: 1.0
- Issued: {{ISSUED}}
- Assessor: Leroy H. Mason
- Tool: mcp-authscan {{TOOL_VERSION}}, probe set {{PROBE_SET_VERSION}}
- Scan window: {{START_UTC}} to {{END_UTC}} UTC

## 1. Authorization

Written authorization for this assessment was given by {{AUTHORIZING_PARTY}} on {{AUTH_DATE}} under {{AUTH_BASIS}}. The authorized scope is limited to the endpoints listed in section 2. No other host was contacted.

## 2. Scope

### In scope

| Method | Endpoint | Host |
| --- | --- | --- |
| {{METHOD}} | {{PATH}} | {{HOST}} |

### Out of scope

{{OUT_OF_SCOPE}}

### Not covered by this assessment

- Client-side OAuth behaviour, including issuer binding in MCP clients
- Source code review
- Multi-tenancy and cross-tenant isolation
- Destructive or state-changing tests
{{OTHER_NON_SCOPE}}

## 3. Executive summary

{{ONE_PARAGRAPH_SUMMARY}}

Findings by severity: critical {{N}}, high {{N}}, medium {{N}}, low {{N}}.

The single most important item is {{TOP_FINDING}}. Fix order: {{FIX_ORDER}}.

Demonstrated versus not: {{COVERAGE_LINE}}.

## 4. Method

Each probe tests one property of the running server and returns exactly one verdict.

- PASS means the property was positively demonstrated by the response.
- FAIL means the response demonstrated the property is absent or misconfigured.
- NOT_OBSERVED means the response demonstrated neither. It is not a pass.
- EXCLUDED means the probe could not run because a prerequisite was not met. Every exclusion names its prerequisite.

Findings are sorted by severity, rule id and endpoint. The same target and the same probe set produce the same content hash. Evidence is redacted for tokens, cookies, API keys and email addresses. No destructive or unauthenticated exploitation is attempted.

## 5. Coverage

| Probe | Verdict | Endpoint | Note |
| --- | --- | --- | --- |
| {{PROBE}} | {{VERDICT}} | {{ENDPOINT}} | {{NOTE}} |

Coverage counts as PASS plus FAIL over the in-scope set after exclusions. {{COVERAGE_STATEMENT}}

## 6. Findings

### {{FINDING_ID}} {{TITLE}}

- Severity: {{SEVERITY}} ({{RULE}})
- Endpoint: {{ENDPOINT}}
- Observed: {{OBSERVED}}
- Evidence: {{REDACTED_REQUEST_RESPONSE}}
- Why it matters here: {{ARCHITECTURE_IMPACT}}
- Remediation: {{REMEDIATION}}
- Retest criteria: {{RETEST_CRITERIA}}

## 7. Retest

Not yet performed. Completed after remediation.

- Retest date:
- Change made by client:
- New content hash:
- Diff against this report:
- Result:

## 8. Integrity

- Content hash: {{HASH}}
- The hash covers: target, authorization, scan mode, verdicts and findings.
- The hash does not cover: elapsed time, timestamps, server-varying headers, tool version, this scope statement, or finding detail text.
- Reproduce: {{REPRO_COMMAND}}

## 9. Signature

{{ASSESSOR_NAME}}, {{ASSESSOR_ROLE}}
{{ISSUED_DATE}}
