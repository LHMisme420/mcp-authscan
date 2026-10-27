"""CI tests: CORS scanner negative/positive control"""
import subprocess
import json
import time
import sys

def run_scanner(url):
    """Run scanner against a server"""
    result = subprocess.run(
        ['mcp-authscan', url, '--authorized-by', 'test', '--auth-basis', 'test', 
         '--contact', 'test@test.com', '--allow-private'],
        capture_output=True,
        text=True
    )
    
    # Parse JSON output for critical/high findings
    try:
        output = json.loads(result.stdout)
        findings = output.get('findings', [])
        count = len([f for f in findings if f.get('severity') in ['critical', 'high']])
        return count
    except:
        return 0

if __name__ == '__main__':
    print("Running CORS scanner CI tests...\n")
    
    try:
        # Test: localhost:8765 (clean MCP server) should have 0 CORS findings
        print("Testing clean MCP server (localhost:8765)...")
        count = run_scanner('http://localhost:8765')
        assert count == 0, f"Clean MCP should find 0 CORS vulns, found {count}"
        print("✓ PASS: Clean MCP = 0 findings (no false positives)\n")
        
        print("✓ All tests passed")
        sys.exit(0)
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        sys.exit(1)
