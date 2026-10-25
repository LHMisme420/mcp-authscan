with open('mcp_authscan.py', 'r') as f:
    lines = f.readlines()

output = []
in_oauth_block = False
skip_until = 0

for i, line in enumerate(lines):
    if i < skip_until:
        continue
    
    if 'from mcp_authscan.oauth_probes import' in line:
        output.append('        from mcp_authscan.oauth_probes_v2 import run_oauth_assessment, count_probes, render_probe\n')
        continue
    
    if 'probes_run, oauth_findings = run_oauth_probes' in line:
        output.append('            records, oauth_findings = run_oauth_assessment(oauth_server_url, discovery_info, target_url)\n')
        output.append('            \n')
        output.append('            oauth_records.extend(records)\n')
        continue
    
    if 'for rule_num, rule_name, status, evidence, verdict in probes_run:' in line:
        output.append('            for record in records:\n')
        output.append('                print(render_probe(record), file=sys.stderr)\n')
        skip_until = i + 3
        continue
    
    output.append(line)

with open('mcp_authscan.py', 'w') as f:
    f.writelines(output)

print("Fixed OAuth integration")
