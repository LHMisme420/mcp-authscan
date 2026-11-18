"""Scanner adapter: build security-state-v1 and observation-v1 from a graded scan.

This module is the only place that knows how mcp-authscan's graded result
(``canonical_payload`` in monolith.main) maps onto the evidence schemas.
The schema logic itself lives in the pure ``mcp_authscan.evidence`` package.

Rule: every state field is built from fields already present in the graded
result. A field the result does not establish is ``null``, and the reason is
recorded in the observation's ``unestablished`` list. Nothing is guessed.
"""
import json
import os
from datetime import UTC, datetime

from .evidence.state import compute_state_id, normalize_target, validate_state
from .target_probes import CORS_PROBE_ID, PROBE_ORIGIN

STATE_SCHEMA = "security-state-v1"
OBSERVATION_SCHEMA = "observation-v1"

# Probe ids are not unique across modules (13 is also denial-shape), so a
# record is identified by (probe_id, name).
CORS_PROBE = (CORS_PROBE_ID, "cross-origin read on the MCP endpoint")
AUDIENCE_PROBE = (11, "token-audience")

# Which state fields each probe would establish (observation-v1 §4 "affects").
AFFECTS = {
    CORS_PROBE: ["cors.allow_credentials", "cors.allow_origin_wildcard"],
    AUDIENCE_PROBE: ["audience.enforced"],
}

NOT_CAPTURED_NAMES = (
    "the scan records a count of tools/list results (content_observed.inspected.tools), "
    "not tool names"
)
NO_ORIGIN_PROBE = "no probe tests Origin request-header validation on the MCP endpoint"
SINGLE_ORIGIN = "only one probe origin is sent; the full allowlist is not enumerated"
AUDIENCES_NOT_ENUMERATED = "probe 11 presents one foreign audience; accepted audiences are not enumerated"


def _probe_key(probe):
    return (probe.get("probe_id"), probe.get("name"))


def _find(probes, key):
    """Return (record, reason). record is None if absent or ambiguous."""
    hits = [p for p in probes if _probe_key(p) == key]
    if len(hits) == 1:
        return hits[0], None
    label = "probe {} ({})".format(*key)
    if not hits:
        return None, label + " produced no record in this scan"
    return None, label + f" produced {len(hits)} records; ambiguous"


def _verdict_reason(record):
    label = "probe {} ({})".format(*_probe_key(record))
    why = record.get("limitation") or record.get("detail") or "no reason recorded"
    return "{} was {}: {}".format(label, record.get("status"), why)


def _tools(content_observed, credentialed):
    """Return (unauthenticated_tools, authenticated_tools, reasons)."""
    inspected = (content_observed or {}).get("inspected") or {}
    count = inspected.get("tools")
    own = "authenticated_tools" if credentialed else "unauthenticated_tools"
    other = "unauthenticated_tools" if credentialed else "authenticated_tools"
    reasons = {
        other: "the content probe ran %s a credential; this list was not requested"
        % ("with" if credentialed else "without"),
    }
    value = None
    if count == 0:
        value = []  # tools/list answered with an empty result.tools
    elif isinstance(count, int):
        reasons[own] = f"tools/list returned {count} tool(s), but {NOT_CAPTURED_NAMES}"
    else:
        why = "; ".join((content_observed or {}).get("reasons") or []) or "no tools/list result recorded"
        reasons[own] = "tools/list not established: " + why
    result = {own: value, other: None}
    return result["unauthenticated_tools"], result["authenticated_tools"], reasons


def _cors(probes):
    rec, missing = _find(probes, CORS_PROBE)
    out = {"allow_origin_wildcard": None, "allow_credentials": None, "allowed_origins": None}
    reasons = {"cors.allowed_origins": SINGLE_ORIGIN}
    if rec is None:
        for f in AFFECTS[CORS_PROBE]:
            reasons[f] = missing
        return out, reasons
    if rec.get("status") not in ("PASS", "FAIL"):
        for f in AFFECTS[CORS_PROBE]:
            reasons[f] = _verdict_reason(rec)
        return out, reasons
    headers = {k.lower(): v for k, v in (rec.get("headers_observed") or {}).items()}
    acao = (headers.get("access-control-allow-origin") or "").strip()
    acac = (headers.get("access-control-allow-credentials") or "").strip().lower()
    out["allow_origin_wildcard"] = acao == "*" or acao.lower() == PROBE_ORIGIN.lower()
    out["allow_credentials"] = acac == "true"
    return out, reasons


def _audience(probes, target):
    rec, missing = _find(probes, AUDIENCE_PROBE)
    out = {"enforced": None, "accepted_audiences": None}
    reasons = {"audience.accepted_audiences": AUDIENCES_NOT_ENUMERATED}
    if rec is None:
        reasons["audience.enforced"] = missing
        return out, reasons
    status = rec.get("status")
    if status == "FAIL":
        out["enforced"] = False
    elif status == "PASS" and rec.get("endpoint") == target:
        out["enforced"] = True
    elif status == "PASS":
        reasons["audience.enforced"] = (
            "probe 11 PASS came from the authorization server refusing to mint a "
            "foreign-audience token; the MCP endpoint's own enforcement was not exercised")
    else:
        reasons["audience.enforced"] = _verdict_reason(rec)
    return out, reasons


def build_state(payload, credentialed):
    """Return (state, unestablished) from the graded scan payload.

    ``unestablished`` maps each null state field (dotted path) to the reason.
    """
    target = payload["target"]
    probes = payload.get("probes") or []
    unauth, auth, tool_reasons = _tools(payload.get("content_observed"), credentialed)
    cors, cors_reasons = _cors(probes)
    audience, aud_reasons = _audience(probes, target)
    state = {
        "schema": STATE_SCHEMA,
        "target": normalize_target(target),
        "tool_visibility": {"unauthenticated_tools": unauth, "authenticated_tools": auth},
        "audience": audience,
        "origin": {"validated": None, "allowed_origins": None},
        "cors": cors,
    }
    validate_state(state)
    reasons = {"tool_visibility." + k: v for k, v in tool_reasons.items()}
    reasons.update(cors_reasons)
    reasons.update(aud_reasons)
    reasons["origin.validated"] = NO_ORIGIN_PROBE
    reasons["origin.allowed_origins"] = NO_ORIGIN_PROBE
    unestablished = []
    for section in ("tool_visibility", "audience", "origin", "cors"):
        for field, value in state[section].items():
            path = f"{section}.{field}"
            if value is None:
                unestablished.append({"field": path, "reason": reasons.get(path, "not established")})
    unestablished.sort(key=lambda e: e["field"])
    return state, unestablished


def _utc_z(dt):
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_observation(state, unestablished, payload, *, scanner_version, ended_at=None):
    """Return the observation-v1 envelope for ``state``. Never hashed into the STATE ID."""
    counts = payload["counts"]
    probes = payload.get("probes") or []
    not_observed = []
    excluded = []
    for p in probes:
        entry_id = "{}:{}".format(p.get("probe_id"), p.get("name"))
        affects = list(AFFECTS.get(_probe_key(p), []))
        if p.get("status") == "NOT_OBSERVED":
            not_observed.append({
                "probe_id": entry_id,
                "reason": p.get("limitation") or p.get("detail") or "no reason recorded",
                "affects": affects,
            })
        elif p.get("status") == "EXCLUDED":
            excluded.append({
                "probe_id": entry_id,
                "missing_prerequisite": (p.get("limitation") or "; ".join(p.get("prerequisites") or [])
                                         or "not recorded"),
                "affects": affects,
            })
    not_observed.sort(key=lambda e: e["probe_id"])
    excluded.sort(key=lambda e: e["probe_id"])
    coverage = {
        "in_scope": counts["PASS"] + counts["FAIL"] + counts["NOT_OBSERVED"],
        "pass": counts["PASS"],
        "fail": counts["FAIL"],
        "not_observed": counts["NOT_OBSERVED"],
        "excluded": counts["EXCLUDED"],
    }
    if coverage["not_observed"] != len(not_observed) or coverage["excluded"] != len(excluded):
        raise ValueError(f"observation counts disagree with probe records: counts={counts!r}, "
                         f"records={len(not_observed)}/{len(excluded)}")
    start = datetime.fromisoformat(payload["run_started_at"])
    end = ended_at or datetime.now(UTC)
    state_id = compute_state_id(state)
    return {
        "schema": OBSERVATION_SCHEMA,
        "state_id": state_id,
        "state": state,
        "observed_at": {"start": _utc_z(start), "end": _utc_z(max(end, start))},
        "scanner": {
            "name": "mcp-authscan",
            "version": scanner_version,
            "probe_set_version": payload["probe_set_version"],
        },
        "coverage": coverage,
        "not_observed": not_observed,
        "excluded": excluded,
        "unestablished": unestablished,
        "not_implemented": sorted(payload.get("not_implemented") or []),
        "report_hash": payload.get("report_hash"),
    }


def evidence_dir(evidence_dir_arg, output_arg):
    """--evidence-dir wins; otherwise next to --output; otherwise ./mcp-authscan-evidence."""
    if evidence_dir_arg:
        return evidence_dir_arg
    if output_arg:
        return os.path.dirname(os.path.abspath(output_arg))
    return os.path.join(os.getcwd(), "mcp-authscan-evidence")


def write_evidence(directory, state, observation):
    """Write both objects; return (state_path, observation_path).

    The state file is content-addressed (<state_id>.state.json), so rewriting
    the same boundary is idempotent. Each observation gets its own file.
    """
    os.makedirs(directory, exist_ok=True)
    sid = observation["state_id"]
    stamp = observation["observed_at"]["end"].replace("-", "").replace(":", "")
    state_path = os.path.join(directory, f"{sid}.state.json")
    obs_path = os.path.join(directory, f"observation-{stamp}-{sid[:12]}.json")
    for path, obj in ((state_path, state), (obs_path, observation)):
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(obj, indent=2, sort_keys=True) + "\n")
        os.replace(tmp, path)
    return state_path, obs_path
