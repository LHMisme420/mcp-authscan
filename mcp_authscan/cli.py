import argparse, json, sys
from .scanner import MCPScanner
from .report import SecurityReport


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


def main():
    parser = argparse.ArgumentParser(description="mcp-authscan: MCP security scanner")
    subparsers = parser.add_subparsers(dest="command")
    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("url")
    scan_parser.add_argument("--timeout", type=int, default=5)
    scan_parser.add_argument("--format", choices=["text", "json"], default="text")
    scan_parser.add_argument("--output", "-o")
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
            scanner = MCPScanner(args.url, timeout=args.timeout, headers=headers)
            print(f"[*] Scanning {args.url}...", file=sys.stderr)
            checks = scanner.scan()
            report = SecurityReport(checks, args.url)
            output = report.json() if args.format == "json" else report.text()
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(output)
                print(f"[+] Report saved to {args.output}", file=sys.stderr)
            else:
                print(output)
            summary = report.summary()
            if summary['critical'] > 0:
                sys.exit(1)
        except Exception as e:
            if args.format == "json" and not args.output:
                print(json.dumps({"status": "failed", "error": str(e)}))
                sys.exit(1)
            print(f"[!] Error: {str(e)}", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()
