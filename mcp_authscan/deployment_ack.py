"""Deployment Acknowledgment Proof (DAP): bind a signed report to a reviewer-issued nonce.

A reviewer creates a challenge (``challenge create``) and hands it to the scanning
operator. The deployment controller publishes the challenge nonce at
``https://TARGET_ORIGIN/.well-known/mcp-authscan-challenge``. The scanner fetches it
through the shared DNS-pinned transport (oauth_probes_v2.open_pinned: one resolution,
non-public destinations refused unless explicitly authorized, no proxy, no redirects,
default certificate and hostname validation) and records the exact observation. With
``--sign`` the record is bound into a sig_version 5 report signature.

What this establishes, and what it does not, is fixed in STATEMENT. A signed record is
the scanner's own attestation: offline verification proves the record is unaltered and
signed by a trusted key, NOT that the recorded network request happened.

Results: ACKNOWLEDGED only for an HTTP 200 whose body is exactly the nonce (one
trailing LF or CRLF allowed), fetched over verified TLS inside the challenge validity
window. Every failure (DNS, TLS, timeout, refusal, redirect, non-200, oversize) is
NOT_OBSERVED; a different body is MISMATCH; outside the window is EXPIRED; a
malformed, altered or misbound challenge or record is INVALID.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import secrets
import ssl
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request

from mcp_authscan.report_verify import serialize

CHALLENGE_SCHEMA = "deployment-challenge-v1"
RECORD_SCHEMA = "deployment-acknowledgment-v1"
VERIFICATION_SCHEMA = "deployment-acknowledgment-verification-v1"
PUBLICATION_PATH = "/.well-known/mcp-authscan-challenge"

ACKNOWLEDGED = "ACKNOWLEDGED"
NOT_OBSERVED = "NOT_OBSERVED"
MISMATCH = "MISMATCH"
EXPIRED = "EXPIRED"
INVALID = "INVALID"
RESULTS = (ACKNOWLEDGED, NOT_OBSERVED, MISMATCH, EXPIRED, INVALID)

# Declared by the reviewer at challenge creation; never inferred from a hostname.
BINDING_SCOPES = ("dedicated-host", "shared-provider-host", "unknown")

MAX_RESPONSE_BYTES = 1024
MAX_CHALLENGE_FILE_BYTES = 64 * 1024
DEFAULT_TIMEOUT = 10
MAX_TIMEOUT = 30
DEFAULT_TTL = 3600
MAX_TTL = 7 * 86400

STATEMENT = (
    "This signed report records an acknowledgment challenge observed at the designated "
    "publication location for the named target. It does not establish tenant ownership, "
    "independently prove that the recorded network request occurred, demonstrate "
    "authorization security, or establish the deployment's current security posture."
)
LIMITATIONS = (
    "The observation is the scanner's signed attestation; offline verification proves the record "
    "is unaltered and signed, not that the network request occurred.",
    "Acknowledgment shows control of the publication location at observation time, not ownership "
    "of a particular MCP tenant; on a shared provider host it binds only the publication location.",
    "Binding scope is declared by the reviewer and is never inferred from the hostname.",
    "Acknowledgment does not demonstrate authorization security or current security posture.",
    "Independent reviewer participation requires the reviewer to verify against the challenge "
    "they issued; a scanner-generated challenge alone establishes nothing about the reviewer.",
)
NETWORK_NOTE = ("NOT INDEPENDENTLY PROVEN: the observation is a signed scanner record; "
                "only reviewer-side live confirmation makes a fresh network request.")

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_STAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_HOST = re.compile(r"^[a-z0-9.-]+$")
_CHALLENGE_KEYS = ("binding_scope", "challenge_id", "created_at", "expires_at", "nonce",
                   "publication_path", "schema", "target")
_RECORD_KEYS = ("binding_scope", "challenge", "challenge_id", "limitations", "nonce", "observation",
                "observer", "publication_origin", "publication_url", "reason", "requested_target",
                "result", "schema", "statement", "target")
_OBSERVATION_KEYS = ("allow_private", "content_type", "credentials_sent", "error", "http_status",
                     "max_response_bytes", "method", "observed_at", "proxy_used", "redirects_followed",
                     "request_attempted", "resolved_address", "response_body_b64", "response_bytes",
                     "response_sha256", "timeout_seconds", "tls_certificate_verified",
                     "tls_peer_certificate_sha256", "tls_version", "url")
OBSERVER = "scanner-signed-observation"


class ChallengeInvalid(ValueError):
    """The challenge is malformed, altered, or bound to a different target."""


# ---- time ------------------------------------------------------------------------

def _now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def _fmt(moment):
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(text):
    if not isinstance(text, str) or not _STAMP.fullmatch(text):
        raise ValueError("timestamp must be UTC YYYY-MM-DDTHH:MM:SSZ")
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


# ---- target identity ---------------------------------------------------------------

def canonical_target(url):
    """The canonical https target. Never changes scheme, host, port or path; refuses instead."""
    if not isinstance(url, str) or not url or len(url) > 2048 or any(c.isspace() or ord(c) < 32 for c in url):
        raise ChallengeInvalid("target must be a single-line URL of at most 2048 characters")
    parts = urlsplit(url)
    if parts.scheme.lower() != "https":
        raise ChallengeInvalid("target must be an https:// URL; the scheme is never changed")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise ChallengeInvalid("target must not carry credentials")
    if parts.query or parts.fragment or url.endswith(("?", "#")):
        raise ChallengeInvalid("target must not carry a query or fragment")
    host = parts.hostname
    if not host:
        raise ChallengeInvalid("target must name a host")
    try:
        port = parts.port
    except ValueError:
        raise ChallengeInvalid("target port is invalid") from None
    if ":" in host:
        host_part = "[" + host + "]"
    else:
        if not _HOST.fullmatch(host) or host.startswith(".") or host.endswith(".") or ".." in host:
            raise ChallengeInvalid("target host must be an ASCII (IDNA A-label) hostname or IP literal")
        host_part = host
    if port == 0:
        raise ChallengeInvalid("target port is invalid")
    origin = "https://" + host_part + ("" if port in (None, 443) else ":%d" % port)
    return origin + (parts.path or "/")


def publication_origin(target):
    parts = urlsplit(target)
    return "https://" + parts.netloc


def publication_url(target):
    return publication_origin(target) + PUBLICATION_PATH


# ---- challenge -------------------------------------------------------------------

def challenge_id(fields):
    """SHA-256 over the canonical JSON of every challenge field except challenge_id."""
    body = {k: fields[k] for k in _CHALLENGE_KEYS if k != "challenge_id"}
    return hashlib.sha256(serialize(body)).hexdigest()


def create_challenge(target, *, ttl=DEFAULT_TTL, binding_scope="unknown", now=None):
    """A reviewer challenge with a fresh 256-bit nonce from secrets.token_hex(32)."""
    if type(ttl) is not int or not 60 <= ttl <= MAX_TTL:
        raise ChallengeInvalid("ttl must be an integer between 60 and %d seconds" % MAX_TTL)
    if binding_scope not in BINDING_SCOPES:
        raise ChallengeInvalid("binding_scope must be one of " + ", ".join(BINDING_SCOPES))
    created = (now or _now()).replace(microsecond=0)
    fields = {
        "schema": CHALLENGE_SCHEMA,
        "nonce": secrets.token_hex(32),
        "target": canonical_target(target),
        "publication_path": PUBLICATION_PATH,
        "binding_scope": binding_scope,
        "created_at": _fmt(created),
        "expires_at": _fmt(created + timedelta(seconds=ttl)),
    }
    fields["challenge_id"] = challenge_id(fields)
    return {k: fields[k] for k in _CHALLENGE_KEYS}


def validate_challenge(obj):
    """Return the challenge unchanged if it is well formed and its id recomputes; else raise."""
    if not isinstance(obj, dict) or sorted(obj) != list(_CHALLENGE_KEYS):
        raise ChallengeInvalid("challenge must contain exactly: " + ", ".join(_CHALLENGE_KEYS))
    if obj["schema"] != CHALLENGE_SCHEMA:
        raise ChallengeInvalid("challenge schema must be " + CHALLENGE_SCHEMA)
    if not isinstance(obj["nonce"], str) or not _HEX64.fullmatch(obj["nonce"]):
        raise ChallengeInvalid("nonce must be 64 lowercase hex characters (256 bits)")
    if obj["publication_path"] != PUBLICATION_PATH:
        raise ChallengeInvalid("publication_path must be " + PUBLICATION_PATH)
    if obj["binding_scope"] not in BINDING_SCOPES:
        raise ChallengeInvalid("binding_scope must be one of " + ", ".join(BINDING_SCOPES))
    if canonical_target(obj["target"]) != obj["target"]:
        raise ChallengeInvalid("challenge target is not in canonical form")
    try:
        created, expires = _parse(obj["created_at"]), _parse(obj["expires_at"])
    except ValueError as error:
        raise ChallengeInvalid("challenge " + str(error)) from None
    if not 0 < (expires - created).total_seconds() <= MAX_TTL:
        raise ChallengeInvalid("challenge validity window must be positive and at most %d seconds" % MAX_TTL)
    if not isinstance(obj["challenge_id"], str) or obj["challenge_id"] != challenge_id(obj):
        raise ChallengeInvalid("challenge_id does not match the canonical SHA-256 of the challenge")
    return obj


def load_challenge(path):
    from mcp_authscan.verification import _strict_json
    try:
        raw = Path(path).read_bytes()
    except OSError:
        raise ChallengeInvalid("challenge file is unavailable") from None
    if len(raw) > MAX_CHALLENGE_FILE_BYTES:
        raise ChallengeInvalid("challenge file is too large")
    try:
        obj = _strict_json(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise ChallengeInvalid("challenge file is not strict UTF-8 JSON") from None
    return validate_challenge(obj)


# ---- observation -------------------------------------------------------------------

def _empty_observation(url, observed_at, allow_private, timeout):
    return {
        "observed_at": observed_at, "request_attempted": False, "method": "GET", "url": url,
        "resolved_address": None, "http_status": None, "content_type": None,
        "response_bytes": None, "response_sha256": None, "response_body_b64": None,
        "tls_certificate_verified": False, "tls_version": None, "tls_peer_certificate_sha256": None,
        "redirects_followed": False, "credentials_sent": False, "proxy_used": False,
        "allow_private": bool(allow_private), "timeout_seconds": timeout,
        "max_response_bytes": MAX_RESPONSE_BYTES, "error": None,
    }


def _tls_details(resp, obs):
    sock = getattr(getattr(getattr(resp, "fp", None), "raw", None), "_sock", None)
    if not isinstance(sock, ssl.SSLSocket):
        return
    try:
        obs["resolved_address"] = sock.getpeername()[0]
        der = sock.getpeercert(binary_form=True)
        obs["tls_version"] = sock.version()
        obs["tls_peer_certificate_sha256"] = hashlib.sha256(der).hexdigest() if der else None
        obs["tls_certificate_verified"] = bool(
            der and sock.context.verify_mode == ssl.CERT_REQUIRED and sock.context.check_hostname)
    except (OSError, ValueError):
        obs["tls_certificate_verified"] = False


def _error_text(exc):
    reason = getattr(exc, "reason", None)
    if isinstance(reason, ssl.SSLCertVerificationError) or isinstance(exc, ssl.SSLCertVerificationError):
        return "TLS certificate verification failed"
    if isinstance(reason, ssl.SSLError) or isinstance(exc, ssl.SSLError):
        return "TLS handshake failed"
    if isinstance(reason, (TimeoutError, OSError)) and "timed out" in str(reason):
        return "connection timed out"
    if isinstance(exc, TimeoutError):
        return "timed out"
    return "connection failed (%s)" % type(reason or exc).__name__


def fetch_publication(url, *, allow_private, timeout=DEFAULT_TIMEOUT, observed_at=None):
    """GET the publication URL through the shared pinned transport; return the observation.

    No credentials, cookies or proxies; redirects are refused, not followed; the body is
    capped at MAX_RESPONSE_BYTES and the whole exchange at ``timeout`` seconds.
    """
    from mcp_authscan import oauth_probes_v2 as transport
    from mcp_authscan.errors import EgressRefusalError

    if type(timeout) not in (int, float) or not 0 < timeout <= MAX_TIMEOUT:
        raise ChallengeInvalid("timeout must be between 0 and %d seconds" % MAX_TIMEOUT)
    obs = _empty_observation(url, observed_at or _fmt(_now()), allow_private, timeout)
    obs["request_attempted"] = True
    request = Request(url, method="GET", headers={
        "User-Agent": transport.USER_AGENT, "Accept": "text/plain", "Cache-Control": "no-cache"})
    deadline = transport._DEADLINE.set(time.monotonic() + timeout)
    try:
        with transport.open_pinned(request, timeout=timeout, allow_private=bool(allow_private)) as resp:
            obs["http_status"] = resp.status
            obs["content_type"] = (resp.headers.get("Content-Type") or None)
            _tls_details(resp, obs)
            declared = resp.headers.get("Content-Length")
            if declared is not None and (not declared.strip().isdigit() or int(declared) > MAX_RESPONSE_BYTES):
                obs["error"] = "declared response size exceeds %d bytes" % MAX_RESPONSE_BYTES
                return obs
            body = transport._read_capped(resp, limit=MAX_RESPONSE_BYTES)
        obs["response_bytes"] = len(body)
        obs["response_sha256"] = hashlib.sha256(body).hexdigest()
        obs["response_body_b64"] = base64.b64encode(body).decode("ascii")
    except HTTPError as exc:
        obs["http_status"] = exc.code
        obs["error"] = ("redirect refused (HTTP %d)" % exc.code if 300 <= exc.code < 400
                        else "HTTP status %d" % exc.code)
        exc.close()
    except EgressRefusalError as exc:
        text = str(exc)
        kind = ("response refused" if "body exceeded" in text else
                "timed out" if "deadline exceeded" in text else "destination refused")
        obs["error"] = "%s: %s" % (kind, text)
    except (URLError, OSError, ValueError) as exc:
        obs["error"] = _error_text(exc)
    finally:
        transport._DEADLINE.reset(deadline)
    return obs


def body_matches(body, nonce):
    expected = nonce.encode("ascii")
    return body in (expected, expected + b"\n", expected + b"\r\n")


def evaluate(challenge, obs):
    """(result, reason) for an observation. The single rule used when observing and verifying."""
    created, expires = _parse(challenge["created_at"]), _parse(challenge["expires_at"])
    observed = _parse(obs["observed_at"])
    if observed >= expires:
        return EXPIRED, "observation at or after the challenge expires_at"
    if observed < created:
        return INVALID, "observation precedes the challenge created_at"
    if not obs["request_attempted"]:
        return NOT_OBSERVED, obs["error"] or "no request was made"
    if obs["error"] is not None:
        return NOT_OBSERVED, obs["error"]
    if obs["http_status"] != 200:
        return NOT_OBSERVED, "HTTP status %r" % (obs["http_status"],)
    if not obs["tls_certificate_verified"]:
        return NOT_OBSERVED, "TLS certificate was not verified"
    try:
        body = base64.b64decode(obs["response_body_b64"], validate=True)
    except (ValueError, TypeError):
        return INVALID, "response body is not valid base64"
    if len(body) != obs["response_bytes"] or hashlib.sha256(body).hexdigest() != obs["response_sha256"]:
        return INVALID, "response digest does not match the recorded body"
    if body_matches(body, challenge["nonce"]):
        return ACKNOWLEDGED, "exact challenge nonce observed at the publication location"
    return MISMATCH, "publication location returned content that is not the challenge nonce"


def observe(challenge, *, requested_target, allow_private, timeout=DEFAULT_TIMEOUT, now=None):
    """Validate, check target identity and validity, fetch, and return the acknowledgment record.

    Raises ChallengeInvalid (no request made) for a malformed challenge or a target that
    differs from the one the challenge names.
    """
    validate_challenge(challenge)
    try:
        requested = canonical_target(requested_target)
    except ChallengeInvalid as error:
        raise ChallengeInvalid("requested target: " + str(error)) from None
    if requested != challenge["target"]:
        raise ChallengeInvalid("challenge was issued for a different target")
    moment = (now or _now()).replace(microsecond=0)
    if moment < _parse(challenge["created_at"]):
        raise ChallengeInvalid("challenge is not yet valid (created_at is after the scanner clock)")
    url = publication_url(challenge["target"])
    if moment >= _parse(challenge["expires_at"]):
        obs = _empty_observation(url, _fmt(moment), allow_private, timeout)
        obs["error"] = "challenge expired before observation; no request made"
    else:
        obs = fetch_publication(url, allow_private=allow_private, timeout=timeout, observed_at=_fmt(moment))
    result, reason = evaluate(challenge, obs)
    return {
        "schema": RECORD_SCHEMA,
        "challenge": dict(challenge),
        "challenge_id": challenge["challenge_id"],
        "nonce": challenge["nonce"],
        "requested_target": requested_target,
        "target": challenge["target"],
        "publication_origin": publication_origin(challenge["target"]),
        "publication_url": url,
        "binding_scope": challenge["binding_scope"],
        "result": result,
        "reason": reason,
        "observation": obs,
        "observer": OBSERVER,
        "limitations": list(LIMITATIONS),
        "statement": STATEMENT,
    }


# ---- record structure (report_verify) and offline verification ----------------------

def record_structure(record):
    """Shape check used by report_verify.signed_content. Messages start with the field name."""
    name = "deployment_acknowledgment"
    if not isinstance(record, dict) or sorted(record) != list(_RECORD_KEYS):
        raise ValueError(name + " must contain exactly: " + ", ".join(_RECORD_KEYS))
    obs = record["observation"]
    if not isinstance(obs, dict) or sorted(obs) != list(_OBSERVATION_KEYS):
        raise ValueError(name + ".observation must contain exactly: " + ", ".join(_OBSERVATION_KEYS))
    if record["schema"] != RECORD_SCHEMA or record["result"] not in RESULTS:
        raise ValueError(name + " schema or result is not recognised")
    if not isinstance(record["challenge"], dict):
        raise ValueError(name + ".challenge must be an object")
    return record


def _check(checks, name, ok, detail):
    checks[name] = {"verdict": "PASS" if ok else "FAIL", "detail": detail}
    return ok


def verify_report(report, reviewer_challenge, *, anchor="packaged"):
    """Offline verification of a report's deployment acknowledgment against the reviewer's challenge.

    ``report`` is the report bytes or str; ``reviewer_challenge`` is the challenge object
    the reviewer issued (required: without it reviewer participation is not established).
    The verdict is INVALID unless every check passes; then it is the recorded result.
    """
    from mcp_authscan import verification
    from mcp_authscan import report_verify as rv

    checks = {}
    out = {"schema": VERIFICATION_SCHEMA, "verdict": INVALID, "reason": "", "checks": checks,
           "recorded_result": None, "challenge_id": None, "target": None, "binding_scope": None,
           "report_hash": None, "network_request": NETWORK_NOTE, "limitations": list(LIMITATIONS),
           "statement": STATEMENT}

    def fail(reason):
        out["verdict"], out["reason"] = INVALID, reason
        return out

    if anchor != "packaged" and not (isinstance(anchor, dict) and anchor.get("keys")):
        return fail("a trust anchor is required; signatures are never skipped")
    try:
        reviewer = validate_challenge(reviewer_challenge)
    except ChallengeInvalid as error:
        _check(checks, "reviewer_challenge", False, str(error))
        return fail("reviewer challenge invalid: " + str(error))
    result = verification.verify(report, anchor=anchor)
    auth = result.get("authenticity", {})
    integrity_ok = result.get("integrity", {}).get("verdict") == "INTACT"
    signed = (auth.get("verdict") == "SIGNED BY" and auth.get("sig_version") == rv.SIG_VERSION_DEPLOYMENT
              and result.get("deployment_acknowledgment", {}).get("verdict") == "VERIFIED")
    _check(checks, "report_integrity", integrity_ok, result.get("integrity", {}).get("verdict"))
    _check(checks, "report_signature", signed, "%s (sig_version %r)" % (auth.get("verdict"), auth.get("sig_version")))
    if result.get("failed_stage") is not None or not integrity_ok:
        return fail("report failed verification at stage %s" % result.get("failed_stage"))
    if not signed:
        return fail("acknowledgment is not covered by a verified sig_version 5 signature; "
                    "an unsigned or unverifiable acknowledgment is never established")
    payload = json.loads(report)
    record = payload[rv.DEPLOYMENT_KEY]
    obs = record["observation"]
    out.update(recorded_result=record["result"], challenge_id=record["challenge_id"],
               target=record["target"], binding_scope=record["binding_scope"],
               report_hash=payload.get("report_hash"))
    try:
        embedded = validate_challenge(record["challenge"])
    except ChallengeInvalid as error:
        _check(checks, "challenge_binding", False, str(error))
        return fail("embedded challenge invalid: " + str(error))
    binding = (embedded["challenge_id"] == record["challenge_id"] and embedded["nonce"] == record["nonce"]
               and embedded["binding_scope"] == record["binding_scope"])
    if not _check(checks, "challenge_binding", binding, "challenge_id and nonce recompute from the challenge"):
        return fail("record challenge_id, nonce or binding scope differ from the embedded challenge")
    if not _check(checks, "reviewer_challenge", serialize(embedded) == serialize(reviewer),
                  "embedded challenge equals the reviewer-issued challenge"):
        return fail("report is bound to a different challenge than the one the reviewer issued")
    try:
        report_target = canonical_target(payload.get("target"))
        requested = canonical_target(record["requested_target"])
    except ChallengeInvalid as error:
        _check(checks, "target_identity", False, str(error))
        return fail("target identity: " + str(error))
    identity = (record["target"] == embedded["target"] == report_target == requested
                and record["publication_origin"] == publication_origin(embedded["target"])
                and record["publication_url"] == obs["url"] == publication_url(embedded["target"]))
    if not _check(checks, "target_identity", identity,
                  "report target, requested target, challenge target and publication URL agree"):
        return fail("target identity differs between report, record and challenge (replay or misbinding)")
    fixed = (record["observer"] == OBSERVER and record["statement"] == STATEMENT
             and record["limitations"] == list(LIMITATIONS) and obs["method"] == "GET"
             and obs["credentials_sent"] is False and obs["redirects_followed"] is False
             and obs["proxy_used"] is False and obs["max_response_bytes"] == MAX_RESPONSE_BYTES)
    if not _check(checks, "observation_record", fixed, "observation constraints and stated limitations"):
        return fail("observation record does not carry the required constraints and limitations")
    digest_ok = True
    if obs["response_body_b64"] is not None:
        try:
            body = base64.b64decode(obs["response_body_b64"], validate=True)
            digest_ok = (len(body) == obs["response_bytes"]
                         and hashlib.sha256(body).hexdigest() == obs["response_sha256"])
        except (ValueError, TypeError):
            digest_ok = False
    elif obs["response_sha256"] is not None or obs["response_bytes"] is not None:
        digest_ok = False
    if not _check(checks, "response_digest", digest_ok, "SHA-256 of the recorded body"):
        return fail("response digest does not match the recorded body")
    try:
        recomputed, reason = evaluate(embedded, obs)
    except (ValueError, TypeError, KeyError) as error:
        _check(checks, "result_recomputation", False, type(error).__name__)
        return fail("observation cannot be evaluated")
    if not _check(checks, "result_recomputation", recomputed == record["result"],
                  "recorded %s, recomputed %s" % (record["result"], recomputed)):
        return fail("recorded result %s differs from the result its own observation supports (%s)"
                    % (record["result"], recomputed))
    out["verdict"], out["reason"] = recomputed, reason
    return out


def live_confirmation(reviewer_challenge, *, allow_private, timeout=DEFAULT_TIMEOUT, now=None):
    """Reviewer-side fresh fetch: a separate, explicitly requested network check."""
    try:
        record = observe(reviewer_challenge, requested_target=(reviewer_challenge or {}).get("target"),
                         allow_private=allow_private, timeout=timeout, now=now)
    except (ChallengeInvalid, AttributeError) as error:
        return {"check": "reviewer-live-confirmation", "result": INVALID, "reason": str(error),
                "observation": None}
    return {"check": "reviewer-live-confirmation", "result": record["result"], "reason": record["reason"],
            "observation": record["observation"]}


# ---- CLI ---------------------------------------------------------------------------

def _write(path, data, exclusive=False):
    text = json.dumps(data, indent=2, sort_keys=True) + "\n"
    with open(path, "x" if exclusive else "w", encoding="utf-8") as handle:
        handle.write(text)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="mcp-authscan challenge",
                                     description="Deployment Acknowledgment Proof challenges.")
    sub = parser.add_subparsers(dest="action", required=True)
    create = sub.add_parser("create", help="reviewer: issue a challenge for one target")
    create.add_argument("--target", required=True, help="https:// MCP target URL")
    create.add_argument("--output", required=True, help="write challenge JSON here (never overwritten)")
    create.add_argument("--ttl", type=int, default=DEFAULT_TTL, help="validity in seconds (60-%d)" % MAX_TTL)
    create.add_argument("--binding-scope", choices=BINDING_SCOPES, default="unknown",
                        help="reviewer's declaration of who controls the host; never inferred")
    check = sub.add_parser("verify", help="fetch the published nonce for a challenge")
    check.add_argument("--challenge", required=True)
    check.add_argument("--allow-private", action="store_true",
                       help="explicitly authorize private/loopback destinations (lab use)")
    check.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    check.add_argument("--output")
    report = sub.add_parser("verify-report", help="offline: verify a signed report's acknowledgment")
    report.add_argument("--report", required=True)
    report.add_argument("--challenge", required=True, help="the challenge the reviewer issued")
    report.add_argument("--trust-anchor", metavar="FILE",
                        help="key-history-v1 or keys.json (default: the packaged pinned key history)")
    report.add_argument("--live", action="store_true",
                        help="ALSO make a fresh network request (separate check; requires network access)")
    report.add_argument("--allow-private", action="store_true")
    report.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    report.add_argument("--output")
    args = parser.parse_args(argv)

    if args.action == "create":
        try:
            challenge = create_challenge(args.target, ttl=args.ttl, binding_scope=args.binding_scope)
            _write(args.output, challenge, exclusive=True)
        except ChallengeInvalid as error:
            print("[!] challenge not created: %s" % error, file=sys.stderr)
            return 2
        except FileExistsError:
            print("[!] challenge not created: output file already exists", file=sys.stderr)
            return 2
        print("challenge_id %s" % challenge["challenge_id"])
        print("publish the nonce at %s until %s" % (publication_url(challenge["target"]), challenge["expires_at"]))
        return 0

    if args.action == "verify":
        try:
            challenge = load_challenge(args.challenge)
            record = observe(challenge, requested_target=challenge["target"],
                             allow_private=args.allow_private, timeout=args.timeout)
            result = {"result": record["result"], "reason": record["reason"], "record": record}
        except ChallengeInvalid as error:
            result = {"result": INVALID, "reason": str(error), "record": None}
        if args.output:
            _write(args.output, result)
        print(result["result"] + " " + result["reason"])
        return 0 if result["result"] == ACKNOWLEDGED else 1

    from mcp_authscan import verification
    try:
        anchor = ("packaged" if args.trust_anchor is None
                  else verification.external_anchor(args.trust_anchor))
        challenge = load_challenge(args.challenge)
        raw = Path(args.report).read_bytes()
        result = {"offline": verify_report(raw, challenge, anchor=anchor), "live_confirmation": None}
    except (verification.AnchorError, ChallengeInvalid, OSError) as error:
        result = {"offline": {"schema": VERIFICATION_SCHEMA, "verdict": INVALID,
                              "reason": "input unavailable or invalid: %s" % error},
                  "live_confirmation": None}
        challenge = None
    if args.live and challenge is not None:
        print("[*] live confirmation: making a network request to %s" % publication_url(challenge["target"]),
              file=sys.stderr)
        result["live_confirmation"] = live_confirmation(challenge, allow_private=args.allow_private,
                                                        timeout=args.timeout)
    if args.output:
        _write(args.output, result)
    offline = result["offline"]
    print("OFFLINE %s %s" % (offline["verdict"], offline["reason"]))
    print("NETWORK REQUEST: " + NETWORK_NOTE)
    if result["live_confirmation"] is not None:
        live = result["live_confirmation"]
        print("LIVE %s %s" % (live["result"], live["reason"]))
    ok = offline["verdict"] == ACKNOWLEDGED and (
        result["live_confirmation"] is None or result["live_confirmation"]["result"] == ACKNOWLEDGED)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
