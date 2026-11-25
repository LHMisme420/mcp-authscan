"""Controlled, non-mutating MCP initialization authentication assurance."""

import json
import hashlib
import secrets
from urllib.request import Request

from mcp_authscan import mcp_session

ASSURANCE_VERSION = "2026.11.25.1"

CONTEXTS = (
    "credentialed-before",
    "anonymous",
    "synthetic-invalid",
    "credentialed-after",
)


def _attempt(endpoint, token, context, allow_private=None,
             allowed_hosts=None):
    observation = {
        "context": context,
        "http_status": None,
        "protocol_valid": False,
        "baseline_digest": None,
    }

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": mcp_session.PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {
                "name": "mcp-authscan",
                "version": ASSURANCE_VERSION,
            },
        },
    }

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "User-Agent": "mcp-authscan/assurance",
    }

    if token:
        headers["Authorization"] = "Bearer " + token

    try:
        request = Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )

        status, hdrs, raw = mcp_session._egress_guard(
            request,
            allow_private=allow_private,
            allowed_hosts=allowed_hosts,
            follow_redirects=False,
        )

        observation["http_status"] = int(status)

        if not 200 <= int(status) < 300:
            return observation

        msg = mcp_session._parse_body(
            raw,
            mcp_session._header(hdrs, "Content-Type"),
        )

        result = mcp_session._rpc_result(msg, payload["id"])

        if result is None:
            return observation

        server = result.get("serverInfo")

        observation["protocol_valid"] = bool(
            isinstance(result.get("protocolVersion"), str)
            and result["protocolVersion"]
            and isinstance(result.get("capabilities"), dict)
            and isinstance(server, dict)
            and isinstance(server.get("name"), str)
            and server["name"]
            and isinstance(server.get("version"), str)
            and server["version"]
        )

        if observation["protocol_valid"]:
            identity = {
                "protocolVersion": result["protocolVersion"],
                "serverInfo": server,
                "capabilities": result["capabilities"],
            }

            canonical = json.dumps(
                identity,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("utf-8")

            observation["baseline_digest"] = (
                hashlib.sha256(canonical).hexdigest()
            )

    except mcp_session.EgressRefusalError:
        raise
    except Exception:
        # Never retain exception messages that might contain secrets.
        return observation

    return observation


def derive_verdict(evidence):
    """Derive a verdict from observations, not a claimed verdict."""

    if not isinstance(evidence, dict):
        return "NOT_OBSERVED"

    if evidence.get("version") != ASSURANCE_VERSION:
        return "NOT_OBSERVED"

    if evidence.get("operation") != "initialize":
        return "NOT_OBSERVED"

    if evidence.get("redirects") is not False:
        return "NOT_OBSERVED"

    rows = evidence.get("observations")

    if not isinstance(rows, list) or len(rows) != 4:
        return "NOT_OBSERVED"

    for row, expected in zip(rows, CONTEXTS):
        if not isinstance(row, dict):
            return "NOT_OBSERVED"

        if row.get("context") != expected:
            return "NOT_OBSERVED"

        if type(row.get("protocol_valid")) is not bool:
            return "NOT_OBSERVED"

        status = row.get("http_status")

        if status is not None and (
            type(status) is not int or not 100 <= status <= 599
        ):
            return "NOT_OBSERVED"

        if row["protocol_valid"] and (
            status is None or not 200 <= status < 300
        ):
            return "NOT_OBSERVED"

    before, anonymous, invalid, after = rows

    if anonymous["protocol_valid"] or invalid["protocol_valid"]:
        return "CONTRADICTED"

    if (
        before["protocol_valid"]
        and after["protocol_valid"]
        and isinstance(before.get("baseline_digest"), str)
        and len(before["baseline_digest"]) == 64
        and all(c in "0123456789abcdef"
                for c in before["baseline_digest"])
        and before["baseline_digest"] == after.get("baseline_digest")
        and anonymous["http_status"] in (401, 403)
        and invalid["http_status"] in (401, 403)
    ):
        return "VERIFIED"

    return "NOT_OBSERVED"


def observe(endpoint, token=None, allow_private=None,
            allowed_hosts=None):
    """Run only against an explicitly authorized assessment target."""

    evidence = {
        "version": ASSURANCE_VERSION,
        "endpoint": endpoint,
        "operation": "initialize",
        "redirects": False,
        "observations": [],
    }

    if not token:
        return evidence

    invalid = "authscan-invalid-" + secrets.token_urlsafe(32)

    while invalid == token:
        invalid = "authscan-invalid-" + secrets.token_urlsafe(32)

    for context, credential in zip(
        CONTEXTS, (token, None, invalid, token)
    ):
        evidence["observations"].append(
            _attempt(
                endpoint,
                credential,
                context,
                allow_private=allow_private,
                allowed_hosts=allowed_hosts,
            )
        )

    return evidence
