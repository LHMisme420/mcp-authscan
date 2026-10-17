"""Opt-in, anonymous probes of explicitly authorized HTTP endpoints.

No registry discovery, authenticated requests, tool execution, database writes,
or automatic uploads. See docs/authorized-scans.md.
"""
import argparse
import json
import sys
import time
from dataclasses import asdict
from datetime import datetime, timezone
from http.client import HTTPException
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .cors import MAX_BODY, CorsResponse, assess_cors, sensitive_user_data

ORIGINS = ("https://vata-probe-one.invalid", "https://vata-probe-two.invalid")
MAX_TARGETS = 100


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_target(target):
    """Validate the exact endpoint, never expand it into other hosts or paths."""
    try:
        parsed = urlsplit(target)
        port = parsed.port
    except ValueError as error:
        raise ValueError("Invalid target URL or port.") from error
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or "?" in target
        or "#" in target
        or any(character.isspace() or ord(character) < 32 for character in target)
        or "\\" in target
        or port == 0
    ):
        raise ValueError(
            "Use an absolute HTTP(S) endpoint without credentials, query strings, "
            "fragments, or whitespace."
        )
    return target


def read_sample(response, deadline):
    encoding = response.headers.get("Content-Encoding", "identity").lower()
    if encoding != "identity":
        return b"", "Encoded body not inspected; sensitive-data assessment is incomplete."
    # Never wait for an SSE stream to finish. This probe cannot assess its body.
    if "text/event-stream" in response.headers.get("Content-Type", "").lower():
        return b"", "SSE body not inspected; sensitive-data assessment is incomplete."
    sample = bytearray()
    while len(sample) < MAX_BODY:
        if time.monotonic() >= deadline:
            raise TimeoutError("Response read deadline exceeded.")
        chunk = response.read1(min(4096, MAX_BODY - len(sample)))
        if not chunk:
            return bytes(sample), None
        sample.extend(chunk)
    return bytes(sample), "Body limit reached; sensitive-data assessment is incomplete."


def probe(opener, target, origin, method, timeout):
    headers = {
        "Origin": origin,
        "Accept": "application/json, text/event-stream",
        "Accept-Encoding": "identity",
        "User-Agent": "VATA-Authorized-Probe/1.0",
    }
    body = None
    if method == "POST":
        headers["Content-Type"] = "application/json"
        body = b'{"jsonrpc":"2.0","method":"tools/list","id":1}'
    request = Request(target, data=body, headers=headers, method=method)
    deadline = time.monotonic() + timeout
    try:
        response = opener.open(request, timeout=timeout)
    except HTTPError as error:
        # HTTP errors are observations, not transport failures or vulnerabilities.
        response = error
    with response:
        status = response.code
        sample, note = (b"", None)
        if 200 <= status < 300:
            sample, note = read_sample(response, deadline)
        return CorsResponse(dict(response.headers.items()), sample, status), note


def scan_endpoint(target, method="GET", timeout=5, opener=None):
    validate_target(target)
    # No proxy credentials, cookie jar, netrc authentication, or redirect scope
    # expansion. Each request remains anonymous, even after a Set-Cookie response.
    opener = opener or build_opener(ProxyHandler({}), NoRedirects())
    observations, probes, errors, findings = [], [], [], []
    for origin in ORIGINS:
        try:
            response, note = probe(opener, target, origin, method, timeout)
        except (OSError, URLError, HTTPException, ValueError) as error:
            # Do not serialize exception messages or response bodies: they may
            # contain credentials or personal data supplied by the target.
            errors.append({"origin": origin, "error": type(error).__name__})
            continue
        observations.append((origin, response))
        private = 200 <= response.status < 300 and sensitive_user_data(response.body)
        probes.append({
            "origin": origin,
            "status": response.status,
            "protected": response.status in {401, 403},
            "sensitive_data_evidence": private,
            "note": note,
        })
    if any(item["sensitive_data_evidence"] for item in probes):
        findings.append({
            "rule": "potential_unauthenticated_sensitive_data",
            "severity": "MEDIUM",
            "description": "Sensitive-data patterns returned without authentication.",
            "review_required": True,
            "details": "Confirm the data is real and intended to be private. "
                       "Public or synthetic records can match these heuristics.",
        })
    cors = assess_cors(observations) if observations else None
    if cors and cors.is_finding:
        findings.append({
            "rule": "cors",
            "severity": cors.severity,
            "description": cors.summary,
            "review_required": True,
            "details": cors.details,
            "remediation": cors.remediation,
        })
    incomplete = bool(errors) or any(
        item["note"] or item["status"] >= 300 and item["status"] not in {401, 403}
        for item in probes
    )
    return {
        "target": target,
        "method": method,
        "status": "incomplete" if incomplete else "completed",
        "probes": probes,
        "errors": errors,
        "cors": asdict(cors) if cors else None,
        "findings": findings,
        "limitations": "A successful public response is not a vulnerability. "
                       "No finding does not establish that this endpoint is secure.",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", action="append", required=True,
                        help="Exact authorized HTTP endpoint; repeat for more endpoints.")
    parser.add_argument("--authorized", action="store_true",
                        help="Confirm permission to test every supplied endpoint.")
    parser.add_argument("--method", choices=("GET", "POST"), default="GET",
                        help="POST sends only the read-only JSON-RPC tools/list request.")
    parser.add_argument("--timeout", type=int, default=5,
                        help="Socket timeout/read deadline in seconds (1–30).")
    parser.add_argument("--output", type=Path,
                        help="Write a new JSON report; existing files are not overwritten.")
    args = parser.parse_args(argv)
    if not args.authorized:
        parser.error("--authorized is required: test only endpoints you have permission to scan.")
    if not 1 <= args.timeout <= 30:
        parser.error("--timeout must be between 1 and 30 seconds.")
    targets = list(dict.fromkeys(args.target))
    if len(targets) > MAX_TARGETS:
        parser.error("At most 100 explicitly authorized endpoints are allowed.")
    try:
        for target in targets:
            validate_target(target)
    except ValueError as error:
        parser.error(str(error))
    # Reserve the destination before sending requests; never overwrite another
    # report or an application file accidentally.
    destination = None
    if args.output:
        try:
            destination = args.output.open("x", encoding="utf-8")
        except OSError:
            parser.error("Cannot create report file. Use a new path in an existing directory.")
    try:
        results = []
        for index, target in enumerate(targets, 1):
            print(f"Scanning authorized endpoint {index}/{len(targets)}", file=sys.stderr)
            results.append(scan_endpoint(target, args.method, args.timeout))
        report = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "authorized_targets_only": True,
            "results": results,
            "finding_count": sum(len(result["findings"]) for result in results),
        }
        output = destination or sys.stdout
        json.dump(report, output, indent=2)
        output.write("\n")
    finally:
        if destination:
            destination.close()
    if any(result["status"] == "incomplete" for result in results):
        return 2
    return 1 if report["finding_count"] else 0


if __name__ == "__main__":
    sys.exit(main())
