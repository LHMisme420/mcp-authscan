"""Integrate resource probes into scan_main.py"""
import re

with open("mcp_authscan/scan_main.py", "r") as f:
    content = f.read()

# 1. Add import
old_import = "from mcp_authscan.oauth_probes_v2 import count_probes, render_probe, run_oauth_assessment"
new_import = old_import + "\n        from mcp_authscan.resource_probes import run_resource_probes, RESOURCE_PROBE_SET_VERSION"
content = content.replace(old_import, new_import)

# 2. After oauth assessment, call resource_probes
old_section = """            records, oauth_findings = run_oauth_assessment(oauth_server_url, resource_metadata_doc, target_url)

            oauth_records.extend(records)

            for finding in oauth_findings:"""

new_section = """            records, oauth_findings = run_oauth_assessment(oauth_server_url, resource_metadata_doc, target_url)
            oauth_records.extend(records)
            
            # Resource endpoint probes
            resource_records = run_resource_probes(target_url)
            
            for finding in oauth_findings:"""

content = content.replace(old_section, new_section)

# 3. Replace canonical_payload to include both probe sets
pattern = r'canonical_payload = \{\s*"target": args\.target,\s*"scan_mode": scan_mode,\s*"probe_set_version": PROBE_SET_VERSION,.*?"findings": F,\s*\}'

new_payload = '''canonical_payload = {
        "target": args.target,
        "scan_mode": scan_mode,
        "probe_sets": [
            {
                "name": "Authorization server (OAuth 1.1.0)",
                "version": PROBE_SET_VERSION,
                "in_scope": 9,
                "coverage": "See coverage counts below"
            },
            {
                "name": "Resource endpoint (1.0.2)",
                "version": "1.0.2",
                "in_scope": 5,
                "coverage": "See coverage counts below"
            }
        ],
        "findings_count": len(F),
        "tool_version": VERSION,
        "findings": F,
    }'''

content = re.sub(pattern, new_payload, content, flags=re.DOTALL)

with open("mcp_authscan/scan_main.py", "w") as f:
    f.write(content)

print("✓ Resource probes integrated")
