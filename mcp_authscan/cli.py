import argparse, json, sys
from .scanner import MCPScanner
from .report import SecurityReport

def main():
    parser = argparse.ArgumentParser(description="mcp-authscan: MCP security scanner")
    subparsers = parser.add_subparsers(dest="command")
    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("url")
    scan_parser.add_argument("--timeout", type=int, default=5)
    scan_parser.add_argument("--format", choices=["text", "json"], default="text")
    scan_parser.add_argument("--output", "-o")
    
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == "scan":
        try:
            scanner = MCPScanner(args.url, timeout=args.timeout)
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
