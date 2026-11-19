"""Scanner adapter: capture surfaces, build security-state-v1 + observation-v1.

Restored from 90d3941 and rebased onto surface_capture.capture_surface().
The schema logic lives in the pure mcp_authscan.evidence package; this
module owns the network capture and the file writes.

Capture rules (schemas/EVIDENCE.md):
- anonymous: a complete capture gives a state. An initialize answered with
  HTTP 401/403 gives the EMPTY anonymous state, with the refusal recorded in
  the observation's ``capture`` field, never in the state. Anything else
  (server not reached, 5xx, a list that failed) gives no state.
- authenticated: only with a credential, and only a complete capture gives a
  state. A refused credential gives no state.
"""
import hashlib
import json
import os
import re
from datetime import UTC, datetime
from urllib.parse import urlsplit

from .evidence.state import build_state, compute_state_id, normalize_target
from .report_verify import EVIDENCE_SCHEME

OBSERVATION_SCHEMA = "observation-v1"
LISTS = ("tools", "prompts", "resources")
REFUSAL_STATUSES = (401, 403)


def _initialize_answered(cap):
    status = cap.get("initialize_status")
    return status is not None and 200 <= status < 300 and not any(
        r.startswith("initialize ") for r in cap.get("reasons") or [])


def classify_capture(cap, access_class):
    """Return (state, capture_record) or (None, skip_reason) for one capture."""
    reasons = list(cap.get("reasons") or [])
    complete = _initialize_answered(cap) and set(cap.get("captured") or []) == set(LISTS)
    if complete:
        return build_state(cap["surface"], access_class), {"status": "complete", "reasons": reasons}
    status = cap.get("initialize_status")
    if access_class == "anonymous" and status in REFUSAL_STATUSES:
        # The capture ran and the server answered with a refusal: anonymous
        # clients see nothing. That is a fact about the boundary, so it is a
        # state, and an empty one. The refusal itself is evidence, not state.
        return build_state({}, "anonymous"), {"status": "refused", "reasons": reasons}
    if status is None:
        why = "server not reached"
    elif status in REFUSAL_STATUSES:
        why = f"credential refused (HTTP {status})"
    else:
        why = f"capture incomplete (initialize HTTP {status})"
    return None, f"{access_class}: no state, {why}: " + ("; ".join(reasons) or "no reason recorded")


def capture_states(target, token, allowed_hosts, capture=None):
    """Capture each access class. Returns (states, skipped).

    ``states`` is a list of (access_class, state, capture_record) sorted by
    access class; ``skipped`` is a list of reason strings.
    """
    if capture is None:
        from .surface_capture import capture_surface as capture
    from .tools_digest_probe import EgressRefusalError
    classes = [("anonymous", None)] + ([("authenticated", token)] if token else [])
    states, skipped = [], []
    for access_class, credential in classes:
        try:
            cap = capture(target, credential, None, allowed_hosts)
        except EgressRefusalError as e:
            skipped.append(f"{access_class}: no state, egress refused: {e}")
            continue
        state, info = classify_capture(cap, access_class)
        if state is None:
            skipped.append(info)
        else:
            states.append((access_class, state, info))
    return states, skipped


def evidence_binding(states, ledgers=None):
    """The report's ``evidence`` field: signed, not hashed (report_verify.signed_content).

    ``ledgers`` maps access_class -> (chain key, head row before this run or
    None) for each class being recorded. The head row travels inline as
    ``prior_row`` with its own signature, so a reader can check the prior
    state without the ledger file or the earlier report. Classes not
    recorded get ledger, ledger_head and prior_row null.
    """
    ledgers = ledgers or {}
    out = []
    for c, s, _ in sorted(states, key=lambda x: x[0]):
        key, row = ledgers.get(c, (None, None))
        out.append({"access_class": c, "state_id": s["state_id"], "ledger": key,
                    "ledger_head": row["state_id"] if row else None, "prior_row": row})
    return {"scheme": EVIDENCE_SCHEME, "states": out}


def _utc_z(dt):
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _probe_entries(probes):
    not_observed, excluded = [], []
    for p in probes:
        entry_id = f"{p.get('probe_id')}:{p.get('name')}"
        if p.get("status") == "NOT_OBSERVED":
            not_observed.append({"probe_id": entry_id,
                                 "reason": p.get("limitation") or p.get("detail") or "no reason recorded"})
        elif p.get("status") == "EXCLUDED":
            excluded.append({"probe_id": entry_id,
                             "missing_prerequisite": (p.get("limitation") or "; ".join(p.get("prerequisites") or [])
                                                      or "not recorded")})
    return sorted(not_observed, key=lambda e: e["probe_id"]), sorted(excluded, key=lambda e: e["probe_id"])


def build_observation(state, capture_record, payload, *, scanner_version, ended_at=None):
    """observation-v1 for ``state``; never hashed into the STATE ID."""
    counts = payload["counts"]
    not_observed, excluded = _probe_entries(payload.get("probes") or [])
    coverage = {
        "in_scope": counts["PASS"] + counts["FAIL"] + counts["NOT_OBSERVED"],
        "pass": counts["PASS"], "fail": counts["FAIL"],
        "not_observed": counts["NOT_OBSERVED"], "excluded": counts["EXCLUDED"],
    }
    if coverage["not_observed"] != len(not_observed) or coverage["excluded"] != len(excluded):
        raise ValueError(f"observation counts disagree with probe records: counts={counts!r}, "
                         f"records={len(not_observed)}/{len(excluded)}")
    start = datetime.fromisoformat(payload["run_started_at"])
    end = max(ended_at or datetime.now(UTC), start)
    return {
        "schema": OBSERVATION_SCHEMA,
        "target": normalize_target(payload["target"]),
        "state_id": compute_state_id(state),
        "state": state,
        "observed_at": {"start": _utc_z(start), "end": _utc_z(end)},
        "scanner": {"name": "mcp-authscan", "version": scanner_version,
                    "probe_set_version": payload["probe_set_version"]},
        "coverage": coverage,
        "not_observed": not_observed,
        "excluded": excluded,
        "capture": capture_record,
        "report_hash": payload.get("report_hash"),
    }


def evidence_dir(evidence_dir_arg, output_arg):
    """--evidence-dir wins; otherwise next to --output; otherwise ./mcp-authscan-evidence."""
    if evidence_dir_arg:
        return evidence_dir_arg
    if output_arg:
        return os.path.dirname(os.path.abspath(output_arg))
    return os.path.join(os.getcwd(), "mcp-authscan-evidence")


def write_evidence(directory, observation):
    """Write <state_id>.state.json (content-addressed, idempotent) and one
    observation file per run and access class. Returns (state_path, obs_path)."""
    os.makedirs(directory, exist_ok=True)
    sid = observation["state_id"]
    klass = observation["state"]["access_class"]
    stamp = observation["observed_at"]["end"].replace("-", "").replace(":", "")
    state_path = os.path.join(directory, f"{sid}.state.json")
    obs_path = os.path.join(directory, f"observation-{stamp}-{klass}-{sid[:12]}.json")
    for path, obj in ((state_path, observation["state"]), (obs_path, observation)):
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(obj, indent=2, sort_keys=True) + "\n")
        os.replace(tmp, path)
    return state_path, obs_path


LEDGER_DIR_ENV = "MCP_AUTHSCAN_LEDGER_DIR"


def ledger_dir(ledger_dir_arg=None):
    """--ledger-dir, else $MCP_AUTHSCAN_LEDGER_DIR, else ~/.config/mcp-authscan/ledgers.

    A stable per-user default, next to the signing key, so every run of a
    target meets the same chain whatever its --output path.
    """
    if ledger_dir_arg:
        return ledger_dir_arg
    configured = os.environ.get(LEDGER_DIR_ENV)
    if configured:
        return configured
    from pathlib import Path
    return str(Path.home() / ".config" / "mcp-authscan" / "ledgers")


def ledger_key(target, access_class):
    """<host>_<port>-<sha256(target)[:16]>/<access_class>.jsonl, relative to the ledger root.

    This key, not an absolute path, is what a report names: it identifies the
    chain without putting the scanning machine's home directory in the report.
    The file name only locates the ledger; its header line binds target and class.
    """
    target = normalize_target(target)
    parts = urlsplit(target)
    label = re.sub(r"[^A-Za-z0-9.-]", "_", f"{parts.hostname}_{parts.port or ''}").rstrip("_")
    digest = hashlib.sha256(target.encode("utf-8")).hexdigest()[:16]
    return f"{label}-{digest}/{access_class}.jsonl"


def ledger_path(directory, target, access_class):
    return os.path.join(directory, *ledger_key(target, access_class).split("/"))
