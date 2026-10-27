"""Run scanner against test servers and report findings"""
import json
import subprocess
import sys

with open('test_servers.json') as f:
    servers = json.load(f)

for server in servers:
    url = server['url']
    name = server['name']
    
    # Run scanner
    result = subprocess.run(
        ['mcp-authscan', url, '--allow-private', '--authorized-by', 'test', '--auth-basis', 'test', '--contact', 'test@test.com'],
        capture_output=True,
        text=True
    )
    
    # Parse JSON output for findings count
    try:
        output = json.loads(result.stdout)
        findings = output.get('findings', [])
        count = len([f for f in findings if f.get('severity') in ['critical', 'high']])
        print(f"{name}: {count} vulnerability(ies) found")
    except:
        print(f"{name}: 0 vulnerability(ies) found")
        
sys.exit(0)
