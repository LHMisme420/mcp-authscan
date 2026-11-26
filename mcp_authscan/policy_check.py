import json
import sys

from mcp_authscan.report_verify import authenticity


SEVERITY_ORDER = ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
FAIL_ON_FLOOR = 'HIGH'  # code floor; a policy may tighten it, never loosen below this
_RULE_SEPARATORS = '-_:./'


def _rule_matches(rule, bad):
    """Exact rule ID, or the ID followed by a separator (family member).
    CORS-1 matches CORS-1 and CORS-1-x, never CORS-10."""
    r, b = str(rule).strip().upper(), str(bad).strip().upper()
    return r == b or (r.startswith(b) and r[len(b)] in _RULE_SEPARATORS)


def _authentication_contradiction(report):
    """Positive observations only: neither a public OAuth document nor missing
    coverage proves that the resource accepted an unauthenticated client."""
    for finding in report.get('findings', []):
        if _rule_matches(finding.get('rule', ''), 'ZERO-AUTH'):
            return 'declared authentication required; zero-auth finding ' + str(finding['rule'])
    content = report.get('content_observed')
    # Existing form-4 signatures bind content_observed; older forms do not.
    if (report.get('sig_version') == 4 and isinstance(content, dict)
            and content.get('credential_context') == 'anonymous'
            and content.get('session_established') is True):
        return 'declared authentication required; content_observed.session_established is true'
    target = report.get('target')
    for probe in report.get('probes', []):
        if not target or probe.get('endpoint') != target or probe.get('http_status') != 200:
            continue
        name, status = probe.get('name'), probe.get('status')
        # Anonymous discovery success is not the PASS of issuer/metadata checks.
        # The existing resource probes instead mark successful anonymous access FAIL.
        if ((name == 'unauthenticated-discovery' and status == 'PASS')
                or (name in ('mcp-preflight', 'anon-initialize', 'anon-tools-list')
                    and status == 'FAIL')):
            return ('declared authentication required; ' + str(name) + ' ' + str(status)
                    + ' observed unauthenticated HTTP 200 at resource endpoint ' + str(target))
    return None


def _self_manifest_status(report):
    """A release cannot carry its own pin (pins ship one release later), so a report from
    the gate's own, unpinned version is checked against the gate's installed source."""
    import mcp_authscan
    from mcp_authscan import report_verify
    prov = report.get('provenance') if isinstance(report.get('provenance'), dict) else {}
    if prov.get('tool_version') != getattr(mcp_authscan, '__version__', None):
        return 'VERSION NOT PINNED'
    try:
        own = report_verify.build_provenance()
    except (ImportError, OSError):
        return 'VERSION NOT PINNED (installed manifest unavailable)'
    return 'MANIFEST MATCHES INSTALLED' if own.get('tool_manifest') == prov.get('tool_manifest') else 'MANIFEST NOT INSTALLED'


def evaluate(
    report_path, policy_path, keys_path, *,
    challenge_db=None, deployment_id=None,
):
    policy = json.load(open(policy_path))
    from mcp_authscan import assurance_freshness

    single_use = policy.get(
        "single-use-authorization-required", False
    )

    if type(single_use) is not bool:
        return {
            "verdict": "REJECT",
            "check": "SINGLE-USE-POLICY-INVALID",
            "detail": "Single-use requirement must be boolean",
        }

    registry_requested = (
        challenge_db is not None or deployment_id is not None
    )

    if single_use or registry_requested:
        if not (
            single_use
            and isinstance(challenge_db, str)
            and challenge_db.strip()
            and isinstance(deployment_id, str)
            and deployment_id.strip()
            and policy.get("verified-authentication-required") is True
            and assurance_freshness.valid_challenge(
                policy.get("expected-deployment-challenge")
            )
            and isinstance(
                policy.get("expected-assurance-target"), str
            )
            and policy.get("expected-assurance-target").strip()
            and "max-assurance-age-seconds" in policy
        ):
            return {
                "verdict": "REJECT",
                "check": "SINGLE-USE-CONFIGURATION",
                "detail": "Trusted registry, deployment and challenge policy required",
            }

    invalid_freshness = assurance_freshness.validate_policy(policy)

    if invalid_freshness:
        return invalid_freshness
    with open(report_path, 'rb') as _fh:
        raw = _fh.read()                      # D3: read the report bytes once...
    report = json.loads(raw)
    keys = json.load(open(keys_path)) if isinstance(keys_path, str) else keys_path
    trusted = {k if isinstance(k, str) else k.get('key-id') for k in policy.get('trusted-signers', [])}
    a = authenticity(report, keys)
    if not a.startswith('SIGNED BY '):
        return {'verdict': 'REJECT', 'check': ('SIGNATURE-INVALID' if 'INVALID' in a else 'UNTRUSTED-SIGNER'), 'detail': a}
    kid = a.split(' ', 2)[2]
    if kid not in trusted:
        return {'verdict': 'REJECT', 'check': 'UNTRUSTED-SIGNER', 'detail': a}
    from mcp_authscan import verification
    engine = verification.verify(raw, anchor=verification.anchor_from_keys(keys))  # D3: ...and feed those same bytes to every check
    _stage = engine['failed_stage']
    _legacy = engine['format']['verdict'] == 'LEGACY'
    if _stage in ('catalog', 'format'):
        return {'verdict': 'REJECT', 'check': 'NOT-REPRODUCIBLE', 'detail': engine[_stage]['reason']}
    if engine['integrity']['verdict'] != 'INTACT' or _legacy:
        return {'verdict': 'REJECT', 'check': 'NOT-REPRODUCIBLE',
                'detail': ('LEGACY_' if _legacy else '') + ('MATCH' if engine['integrity']['verdict'] == 'INTACT' else 'MISMATCH')}
    digest = engine['integrity']['recomputed']
    declared = policy.get('declared-authentication-required', False)
    if not isinstance(declared, bool):
        return {'verdict': 'REJECT', 'check': 'POLICY-INVALID',
                'detail': 'declared-authentication-required must be true or false'}
    if declared and engine['probe_statuses']['verdict'] == 'VERIFIED':
        contradiction = _authentication_contradiction(report)
        if contradiction:
            return {'verdict': 'CONTRADICTED', 'check': 'AUTHENTICATION-REQUIRED',
                    'detail': contradiction}
    need = set(policy.get('required-probes', [])) - set(str(q.get('name')) for q in report.get('probes', []))
    if need: return {'verdict': 'REJECT', 'check': 'PROBES-MISSING', 'detail': ', '.join(sorted(need))}
    names = [str(q.get("name")) for q in report.get("probes", [])]
    dupes = sorted({n for n in names if names.count(n) != 1})
    if dupes: return {"verdict": "REJECT", "check": "PROBES-DUPLICATED", "detail": ", ".join(dupes)}
    for p in report.get('probes', []):
        if p.get('status') == 'FAIL':
            return {'verdict': 'REJECT', 'check': 'PROPERTY-FAILED', 'detail': str(p.get('name')) + ' ' + str(p.get('status'))}
    rules = [str(f.get('rule')) for f in report.get('findings', [])]
    for bad in policy.get('forbidden-findings', []):
        if any(_rule_matches(r, bad) for r in rules):
            return {'verdict': 'REJECT', 'check': 'FINDING-PRESENT', 'detail': bad}
    for finding in report.get('findings', []):
        severity = str(finding.get('severity')).upper()
        if severity not in SEVERITY_ORDER:
            return {
                'verdict': 'REJECT',
                'check': 'FINDING-SEVERITY-INVALID',
                'detail': str(finding.get('rule')) + ' ' + severity
            }
    floor = policy.get('fail-on')
    if floor is not None:
        if str(floor).upper() not in SEVERITY_ORDER:
            return {'verdict': 'REJECT', 'check': 'POLICY-INVALID', 'detail': 'fail-on ' + str(floor)}
        lim = min(SEVERITY_ORDER.index(FAIL_ON_FLOOR), SEVERITY_ORDER.index(str(floor).upper()))  # a policy may tighten, never loosen below the floor
        for f in report.get('findings', []):
            sev = str(f.get('severity')).upper()
            if sev not in SEVERITY_ORDER or SEVERITY_ORDER.index(sev) >= lim:
                return {'verdict': 'REJECT', 'check': 'FINDING-SEVERITY', 'detail': str(f.get('rule')) + ' ' + sev}
    top = None
    if floor is None:  # no explicit fail-on: a HIGH/CRITICAL finding blocks CLEAN but does not REJECT
        hi = SEVERITY_ORDER.index(FAIL_ON_FLOOR)
        present = [SEVERITY_ORDER.index(s) for f in report.get('findings', [])
                   for s in (str(f.get('severity')).upper(),) if s in SEVERITY_ORDER and SEVERITY_ORDER.index(s) >= hi]
        if present:
            top = SEVERITY_ORDER[max(present)]
    req = [str(r) for r in policy.get('required-probes', [])]
    st = {str(q.get('name')): str(q.get('status')) for q in report.get('probes', [])}
    ok = {"PASS"}  # required probes must PASS (654e85b); acceptable-verdicts is not read
    missed = [n for n in req if st.get(n) not in ok]
    passed = len(req) - len(missed)
    want = policy.get("min-sig-version")
    d = int(want) - int(report.get("sig_version", 1)) if want else 0
    if d > 0: return {"verdict": "REJECT", "check": "SIG-VERSION", "detail": "sig_version " + str(report.get("sig_version", 1)) + " below " + str(want)}
    floor_scheme = policy.get("min-graded-scheme")
    if floor_scheme is not None:
        from mcp_authscan.report_verify import GRADED_SCHEME_RANK, graded_scheme_rank
        if floor_scheme not in GRADED_SCHEME_RANK:
            return {"verdict": "REJECT", "check": "POLICY-INVALID", "detail": "min-graded-scheme " + str(floor_scheme)}
        if graded_scheme_rank(report) < GRADED_SCHEME_RANK[floor_scheme]:
            return {"verdict": "REJECT", "check": "GRADED-SCHEME",
                    "detail": "hash_scheme " + str(report.get("hash_scheme")) + " below " + floor_scheme}
    if engine['probe_statuses']['verdict'] != 'VERIFIED':
        return {'verdict': 'REJECT', 'check': 'PROBE-STATUS-UNVERIFIED', 'detail': engine['probe_statuses']['reason']}
    if policy.get('require-manifest-pin'):
        # Provenance is inside the v3/v4 signature, so this pin status cannot be edited unnoticed.
        from mcp_authscan.report_verify import pin_status
        try:
            pin = pin_status(report)
        except ValueError:
            pin = 'INVALID PROVENANCE'
        if pin == 'VERSION NOT PINNED':
            pin = _self_manifest_status(report)
        if pin not in ('MANIFEST MATCHES PIN', 'MANIFEST MATCHES INSTALLED'):
            tv = (report.get('provenance') or {}).get('tool_version') if isinstance(report.get('provenance'), dict) else None
            return {'verdict': 'REJECT', 'check': 'MANIFEST-PIN', 'detail': pin + ' (tool_version ' + str(tv) + ')'}
    # Positive authentication assurance is opt-in.
    positive_auth = policy.get(
        'verified-authentication-required', False
    )

    if type(positive_auth) is not bool:
        return {
            'verdict': 'REJECT',
            'check': 'AUTHENTICATION-POLICY-INVALID',
            'detail': 'verified-authentication-required must be true or false',
        }

    if positive_auth:
        from mcp_authscan.authentication_assurance import derive_verdict

        content = report.get('content_observed')
        assurance = (
            content.get('authentication_assurance')
            if isinstance(content, dict) else None
        )

        if (
            report.get('sig_version') != 4
            or not isinstance(assurance, dict)
            or not isinstance(report.get('target'), str)
            or not report['target']
            or assurance.get('endpoint') != report['target']
        ):
            return {
                'verdict': 'CONDITIONAL',
                'check': 'AUTHENTICATION-ASSURANCE-MISSING',
                'detail': 'Signed authentication assurance for the assessed target is required',
            }

        auth_verdict = derive_verdict(assurance)

        if auth_verdict == 'CONTRADICTED':
            return {
                'verdict': 'REJECT',
                'check': 'AUTHENTICATION-ASSURANCE-CONTRADICTED',
                'detail': 'Unauthorized initialization acceptance observed',
            }

        if auth_verdict != 'VERIFIED':
            return {
                'verdict': 'CONDITIONAL',
                'check': 'AUTHENTICATION-ASSURANCE-INCONCLUSIVE',
                'detail': 'Authentication enforcement was not demonstrated',
            }

        freshness = assurance_freshness.evaluate(
            assurance, policy
        )

        if freshness:
            return freshness

    scope_ops = [str(o) for o in ((policy.get('scope') or {}).get('operations') or [])]
    if req and not missed and scope_ops:
        # Only a sig_version 4 signature covers content_observed.operations (checked above by
        # authenticity()); no other report can prove which operations ran.
        signed_ops = set((report.get('content_observed') or {}).get('operations') or []) if report.get('sig_version') == 4 else None
        unproven = [o for o in scope_ops if signed_ops is None or o not in signed_ops]
        if unproven:
            why = 'operations not signed (sig_version 4 required): ' if signed_ops is None else 'scope operations not observed: '
            return {'verdict': 'CONDITIONAL', 'check': 'SCOPE', 'detail': 'hash ' + digest[:8] + ' passed ' + str(passed) + ' of ' + str(len(req)) + '; ' + why + ', '.join(unproven)}
    if req and not missed:
        if top is not None:
            return {'verdict': 'CONDITIONAL', 'check': 'SEVERITY', 'detail': 'hash ' + digest[:8] + ' passed ' + str(passed) + ' of ' + str(len(req)) + '; ' + top + ' finding present and no fail-on set'}
        if single_use:
            import hashlib
            from mcp_authscan import challenge_registry

            try:
                accepted = challenge_registry.consume(
                    challenge_db,
                    challenge=assurance["deployment_challenge"],
                    target=assurance["endpoint"],
                    deployment_id=deployment_id,
                    report_digest=hashlib.sha256(raw).hexdigest(),
                    assessment_started_at=assurance["assessment_started_at"],
                    assessment_completed_at=assurance["assessment_completed_at"],
                    max_age=policy["max-assurance-age-seconds"],
                    max_skew=policy.get("max-clock-skew-seconds", 0),
                )
            except Exception as exc:
                return {
                    "verdict": "REJECT",
                    "check": "CHALLENGE-REGISTRY-ERROR",
                    "detail": type(exc).__name__,
                }

            if not accepted:
                return {
                    "verdict": "REJECT",
                    "check": "CHALLENGE-NOT-AUTHORIZED",
                    "detail": "Unknown, expired, consumed or mismatched challenge",
                }

            return {
                "verdict": "CLEAN",
                "check": "SINGLE-USE-AUTHORIZED",
                "detail": "Verified challenge atomically consumed",
                "deployment_id": deployment_id,
                "report_sha256": hashlib.sha256(raw).hexdigest(),
            }

        return {'verdict': 'CLEAN', 'check': 'ALL', 'detail': 'hash ' + digest[:8] + ' passed ' + str(passed) + ' of ' + str(len(req))}
    return {'verdict': 'CONDITIONAL', 'check': 'COVERAGE', 'detail': 'hash ' + digest[:8] + ' passed ' + str(passed) + ' of ' + str(len(req)) + '; not passing: ' + ', '.join(missed or ['none'])}


if __name__ == "__main__" and len(sys.argv) > 3: e = evaluate(sys.argv[1], sys.argv[2], sys.argv[3]); print(json.dumps(e)); sys.exit(1 if e['verdict'] in ('REJECT', 'CONTRADICTED') else 0)

from importlib.resources import files as pkgfiles
if __name__ == "__main__" and len(sys.argv) == 2: f = pkgfiles('mcp_authscan'); e = evaluate(sys.argv[1], str(f / 'policy-default.json'), str(f / 'keys-default.json')); print(json.dumps(e)); sys.exit(1 if e['verdict'] in ('REJECT', 'CONTRADICTED') else 0)
