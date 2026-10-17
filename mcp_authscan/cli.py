import argparse, json, sys
from concurrent.futures import ThreadPoolExecutor
from . import __version__
from .scanner import MCPScanner, RiskLevel
from .report import SecurityReport, build_sarif

# Severity threshold ordering for --fail-on and exit-code decisions.
SEVERITY_ORDER = {"none": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
RISK_RANK = {
    RiskLevel.INFO: 1, RiskLevel.LOW: 2, RiskLevel.MEDIUM: 3,
    RiskLevel.HIGH: 4, RiskLevel.CRITICAL: 5,
}

EXIT_OK = 0
EXIT_FINDINGS = 1   # a finding met/exceeded the --fail-on threshold
EXIT_SCAN_ERROR = 2  # a target could not be scanned (and nothing worse happened)


def parse_headers(raw):
    """Parse repeated 'Name: Value' strings into a dict.

    Used to attach identifying headers some bug-bounty programs require on all
    testing traffic (e.g. a research tag tied to your researcher account).
    """
    headers = {}
    for item in raw or []:
        name, sep, value = item.partition(":")
        name, value = name.strip(), value.strip()
        if not sep or not name:
            raise ValueError(f"Invalid header {item!r}; expected 'Name: Value'.")
        headers[name] = value
    return headers


def load_targets(urls, targets_file):
    """Combine positional URLs and a --targets file (one URL/line, # comments),
    de-duplicated with input order preserved."""
    collected = list(urls or [])
    if targets_file:
        with open(targets_file) as handle:
            for line in handle:
                line = line.strip()
                if line and not line.startswith("#"):
                    collected.append(line)
    seen, ordered = set(), []
    for url in collected:
        if url not in seen:
            seen.add(url)
            ordered.append(url)
    return ordered


def max_failed_rank(checks):
    """Highest severity rank among failed checks (0 if none failed)."""
    return max((RISK_RANK[c.risk_level] for c in checks if not c.passed), default=0)


def compute_exit_code(results, fail_on):
    """Decide the process exit code from per-target results and a threshold.

    results: list of dicts with status 'ok' (and 'checks') or 'error'.
    """
    threshold = SEVERITY_ORDER[fail_on]
    has_findings = threshold > 0 and any(
        r["status"] == "ok" and max_failed_rank(r["checks"]) >= threshold
        for r in results
    )
    if has_findings:
        return EXIT_FINDINGS
    if any(r["status"] == "error" for r in results):
        return EXIT_SCAN_ERROR
    return EXIT_OK


def scan_one(url, timeout, headers, checks_profile="default"):
    """Scan a single target; never raises -- returns a result dict."""
    try:
        checks = MCPScanner(url, timeout=timeout, headers=headers,
                            checks=checks_profile).scan()
        return {"target": url, "status": "ok", "checks": checks,
                "report": SecurityReport(checks, url)}
    except Exception as exc:  # noqa: BLE001 - one bad target must not abort the fleet
        return {"target": url, "status": "error", "error": str(exc)}


def build_batch_dict(results):
    """Aggregate per-target results into a single JSON-able dict."""
    ok = [r for r in results if r["status"] == "ok"]
    errors = [r for r in results if r["status"] == "error"]
    entries = []
    for r in results:
        if r["status"] == "ok":
            entry = {"target": r["target"], "status": "ok"}
            entry.update(r["report"].to_dict())
            entries.append(entry)
        else:
            entries.append({"target": r["target"], "status": "error", "error": r["error"]})
    return {
        "summary": {
            "targets": len(results),
            "scanned": len(ok),
            "errors": len(errors),
            "critical": sum(r["report"].summary()["critical"] for r in ok),
            "high": sum(r["report"].summary()["high"] for r in ok),
            "findings": sum(r["report"].summary()["failed"] for r in ok),
        },
        "results": entries,
    }


def build_batch_text(results):
    lines = ["=" * 80, "MCP SECURITY SCAN REPORT (fleet)", "=" * 80, ""]
    for r in results:
        if r["status"] == "ok":
            s = r["report"].summary()
            lines.append(f"  {r['target']}: {s['passed']}/{s['total_checks']} passed, "
                         f"CRITICAL {s['critical']}, HIGH {s['high']}")
        else:
            lines.append(f"  {r['target']}: ERROR - {r['error']}")
    batch = build_batch_dict(results)["summary"]
    lines.extend([
        "", "-" * 80,
        f"Targets: {batch['targets']}  Scanned: {batch['scanned']}  Errors: {batch['errors']}",
        f"Total CRITICAL: {batch['critical']}  Total HIGH: {batch['high']}",
        "=" * 80,
    ])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="mcp-authscan: MCP security scanner")
    subparsers = parser.add_subparsers(dest="command")
    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("url", nargs="*", help="one or more target base URLs")
    scan_parser.add_argument("--targets", metavar="FILE",
                             help="file of target URLs, one per line (# comments allowed)")
    scan_parser.add_argument("--timeout", type=int, default=5)
    scan_parser.add_argument("--concurrency", type=int, default=8,
                             help="max targets scanned in parallel (fleet mode)")
    scan_parser.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    scan_parser.add_argument("--output", "-o")
    scan_parser.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default="critical",
                             help="exit non-zero if a finding at/above this severity is found")
    scan_parser.add_argument("--checks", choices=["default", "all"], default="default",
                             help="'all' adds opt-in RCE-precondition checks "
                                  "(unauthenticated MCP config endpoint, DNS rebinding)")
    scan_parser.add_argument(
        "--header", "-H", action="append", metavar="NAME: VALUE", default=[],
        help="Extra header sent on every request; repeatable. Use to attach a "
             "program-required research/identifying header.",
    )

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "scan":
        try:
            headers = parse_headers(args.header)
            targets = load_targets(args.url, args.targets)
        except (ValueError, OSError) as exc:
            print(f"[!] Error: {exc}", file=sys.stderr)
            sys.exit(1)
        if not targets:
            print("[!] Error: no targets given (pass URLs or --targets FILE).", file=sys.stderr)
            sys.exit(1)

        # Single-target path: preserve the original output/exit contract exactly.
        if len(targets) == 1:
            url = targets[0]
            try:
                scanner = MCPScanner(url, timeout=args.timeout, headers=headers,
                                     checks=args.checks)
                print(f"[*] Scanning {url}...", file=sys.stderr)
                checks = scanner.scan()
                report = SecurityReport(checks, url)
                if args.format == "sarif":
                    output = json.dumps(build_sarif([(url, checks)], __version__), indent=2)
                elif args.format == "json":
                    output = report.json()
                else:
                    output = report.text()
                if args.output:
                    with open(args.output, 'w') as f:
                        f.write(output)
                    print(f"[+] Report saved to {args.output}", file=sys.stderr)
                else:
                    print(output)
                sys.exit(compute_exit_code(
                    [{"target": url, "status": "ok", "checks": checks}], args.fail_on))
            except Exception as e:
                if args.format == "json" and not args.output:
                    print(json.dumps({"status": "failed", "error": str(e)}))
                    sys.exit(1)
                print(f"[!] Error: {str(e)}", file=sys.stderr)
                sys.exit(1)

        # Fleet path: scan concurrently, aggregate, and gate on --fail-on.
        print(f"[*] Scanning {len(targets)} targets (concurrency {args.concurrency})...",
              file=sys.stderr)
        workers = max(1, min(args.concurrency, len(targets)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(
                lambda u: scan_one(u, args.timeout, headers, args.checks), targets))

        if args.format == "sarif":
            per_target = [(r["target"], r["checks"]) for r in results if r["status"] == "ok"]
            output = json.dumps(build_sarif(per_target, __version__), indent=2)
        elif args.format == "json":
            output = json.dumps(build_batch_dict(results), indent=2)
        else:
            output = build_batch_text(results)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"[+] Report saved to {args.output}", file=sys.stderr)
        else:
            print(output)
        sys.exit(compute_exit_code(results, args.fail_on))


if __name__ == "__main__":
    main()
