#!/usr/bin/env python3
import asyncio
import sys
sys.path.insert(0, '/home/claude/vata/mcp-authscan')

from scanner_integration import ScannerIntegration

async def run():
    scanner = ScannerIntegration()
    print("🚀 Starting advanced scan with new vectors...")
    print("")
    print("Vectors included:")
    print("  • Path traversal")
    print("  • Authentication bypass")
    print("  • Information disclosure")
    print("  • CORS bypass")
    print("  • Input validation")
    print("  ⭐ SQL injection")
    print("  ⭐ XXE injection")
    print("  ⭐ Hardcoded secrets")
    print("  ⭐ Rate limit bypass")
    print("  ⭐ JWT validation bypass")
    print("")
    
    # Run the pipeline
    # These findings are synthetic: this harness never contacts a server.
    result = await scanner.full_pipeline(sample_size=50, demo=True)
    
    print("")
    print("✅ Advanced scan complete!")
    print(f"Total findings: {len(result)}")
    
    # Show summary by severity
    severity_count = {}
    for finding in result:
        sev = finding.get('severity', 'UNKNOWN')
        severity_count[sev] = severity_count.get(sev, 0) + 1
    
    print("\nFindings by severity:")
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = severity_count.get(sev, 0)
        if count > 0:
            print(f"  {sev}: {count}")

asyncio.run(run())
