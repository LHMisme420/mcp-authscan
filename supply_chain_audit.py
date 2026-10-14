#!/usr/bin/env python3
import json, subprocess, asyncio, aiohttp, tempfile, os
from datetime import datetime
import sys

class SupplyChainAuditor:
    def __init__(self, servers_file, output_file="supply_chain_findings.json"):
        self.servers_file = servers_file
        self.output_file = output_file
        self.total_scanned = 0
        self.vulnerable_deps = 0
        
    def load_servers(self):
        with open(self.servers_file) as f:
            data = json.load(f)
        servers = []
        for server_name, issues in data.get("findings", {}).items():
            servers.append({
                "name": server_name,
                "url": f"https://github.com/{server_name}",
                "issues": issues
            })
        return servers
    
    async def fetch_manifest_file(self, session, repo_url, filename):
        raw_url = repo_url.replace("github.com", "raw.githubusercontent.com").rstrip("/") + f"/main/{filename}"
        try:
            async with session.get(raw_url, timeout=5) as resp:
                if resp.status == 200:
                    return await resp.text()
                if resp.status == 404:
                    raw_url_master = raw_url.replace("/main/", "/master/")
                    async with session.get(raw_url_master, timeout=5) as resp2:
                        if resp2.status == 200:
                            return await resp2.text()
        except:
            pass
        return None
    
    def scan_npm_deps(self, package_json_content):
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                f.write(package_json_content)
                f.flush()
                result = subprocess.run(['npm', 'audit', '--json'], cwd=os.path.dirname(f.name), capture_output=True, timeout=10)
                if result.stdout:
                    audit_data = json.loads(result.stdout)
                    vulnerabilities = audit_data.get("vulnerabilities", {})
                    findings = []
                    for pkg, vuln_info in vulnerabilities.items():
                        if isinstance(vuln_info, dict):
                            findings.append({"package": pkg, "severity": vuln_info.get("severity", "unknown"), "fix_available": vuln_info.get("fixAvailable", False)})
                    os.unlink(f.name)
                    return findings
        except:
            pass
        return []
    
    def scan_pip_deps(self, requirements_content):
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write(requirements_content)
                f.flush()
                result = subprocess.run(['pip-audit', '--file', f.name, '--format', 'json'], capture_output=True, timeout=10)
                if result.stdout:
                    audit_data = json.loads(result.stdout)
                    vulnerabilities = audit_data.get("vulnerabilities", [])
                    findings = []
                    for vuln in vulnerabilities:
                        findings.append({"package": vuln.get("name", "unknown"), "version": vuln.get("installed_version", "unknown"), "vulnerability_id": vuln.get("id", "unknown"), "fix_available": len(vuln.get("fix_versions", [])) > 0})
                    os.unlink(f.name)
                    return findings
        except:
            pass
        return []
    
    async def audit_server(self, session, server):
        server_name = server["name"]
        repo_url = server["url"]
        findings = {"server": server_name, "timestamp": datetime.now().isoformat(), "dependencies": {"npm": [], "pip": []}, "risk_score": 0}
        
        package_json = await self.fetch_manifest_file(session, repo_url, "package.json")
        if package_json:
            npm_vulns = self.scan_npm_deps(package_json)
            findings["dependencies"]["npm"] = npm_vulns
            findings["risk_score"] += len(npm_vulns) * 3
        
        requirements = await self.fetch_manifest_file(session, repo_url, "requirements.txt")
        if requirements:
            pip_vulns = self.scan_pip_deps(requirements)
            findings["dependencies"]["pip"] = pip_vulns
            findings["risk_score"] += len(pip_vulns) * 3
        
        if findings["dependencies"]["npm"] or findings["dependencies"]["pip"]:
            self.vulnerable_deps += 1
        
        return findings
    
    async def run_audit(self):
        servers = self.load_servers()
        print(f"🔍 Starting supply chain audit of {len(servers)} MCP servers...")
        
        async with aiohttp.ClientSession() as session:
            tasks = [self.audit_server(session, server) for server in servers]
            results = await asyncio.gather(*tasks, return_exceptions=True)
        
        self.total_scanned = len(servers)
        audit_results = [r for r in results if isinstance(r, dict)]
        
        output = {
            "audit_timestamp": datetime.now().isoformat(),
            "total_scanned": self.total_scanned,
            "vulnerable_servers": self.vulnerable_deps,
            "methodology": "npm audit + pip-audit on GitHub manifests",
            "findings": audit_results
        }
        
        with open(self.output_file, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"\n{'='*70}")
        print(f"📊 SUPPLY CHAIN AUDIT COMPLETE")
        print(f"{'='*70}")
        print(f"Total Scanned: {self.total_scanned}")
        print(f"Vulnerable: {self.vulnerable_deps} ({(self.vulnerable_deps/self.total_scanned*100):.1f}%)")
        print(f"Output: {self.output_file}")
        print(f"{'='*70}\n")

if __name__ == "__main__":
    input_file = sys.argv[1] if len(sys.argv) > 1 else "combined_vata_audit.json"
    output_file = sys.argv[2] if len(sys.argv) > 2 else "supply_chain_findings.json"
    auditor = SupplyChainAuditor(input_file, output_file)
    asyncio.run(auditor.run_audit())
