#!/usr/bin/env python3
import asyncio
import httpx
import json
import random

class ScannerIntegration:
    def __init__(self, api_url="http://127.0.0.1:5000"):
        self.api_url = api_url
        self.api_key = None
        self.jwt_token = None
        self.org_id = None
        
    async def setup(self):
        """Register org and authenticate with API"""
        async with httpx.AsyncClient() as client:
            # Register new org
            reg_res = await client.post(f"{self.api_url}/auth/register",
                json={"org_name": "VATA-Scanner"})
            reg_data = reg_res.json()
            self.api_key = reg_data['api_key']
            self.org_id = reg_data['org_id']
            print(f"✅ Registered org {self.org_id}")
            
            # Login and get JWT
            login_res = await client.post(f"{self.api_url}/auth/login",
                json={"api_key": self.api_key})
            login_data = login_res.json()
            self.jwt_token = login_data['access_token']
            print(f"✅ Authenticated with JWT")
    
    async def run_scan(self, sample_size=30):
        """Simulate scanning MCP servers"""
        findings = []
        vectors = [
            "path_traversal",
            "info_disclosure", 
            "cors_bypass",
            "auth_bypass",
            "input_validation"
        ]
        
        # Simulate MCP servers
        sample_servers = [
            f"http://mcp-server-{i}.local:8080" for i in range(sample_size)
        ]
        
        severity_map = {
            "path_traversal": "CRITICAL",
            "auth_bypass": "CRITICAL",
            "info_disclosure": "HIGH",
            "input_validation": "HIGH",
            "cors_bypass": "MEDIUM"
        }
        
        print(f"\n🔬 Scanning {len(sample_servers)} MCP servers for {len(vectors)} vectors...")
        
        for i, server in enumerate(sample_servers):
            for vector in vectors:
                # Simulate 30% vulnerability rate
                if random.random() < 0.3:
                    findings.append({
                        'server_url': server,
                        'vector_type': vector,
                        'severity': severity_map[vector]
                    })
                    print(f"  ⚠️  {server}: {vector} ({severity_map[vector]})")
            
            if (i + 1) % 10 == 0:
                print(f"  [{i+1}/{len(sample_servers)}] servers scanned")
        
        print(f"\n✅ Scan complete: {len(findings)} vulnerabilities found")
        return findings
    
    async def submit_findings(self, findings):
        """Submit findings to API"""
        if not findings:
            print("No findings to submit")
            return
        
        async with httpx.AsyncClient() as client:
            res = await client.post(
                f"{self.api_url}/api/findings",
                json={"findings": findings},
                headers={"Authorization": f"Bearer {self.jwt_token}"}
            )
            result = res.json()
            print(f"\n✅ Submitted {result['inserted']} findings to API")
    
    async def full_pipeline(self, sample_size=30):
        """Complete: setup -> scan -> submit"""
        await self.setup()
        findings = await self.run_scan(sample_size)
        await self.submit_findings(findings)
        
        print(f"\n{'='*70}")
        print(f"📊 SCAN RESULTS READY")
        print(f"{'='*70}")
        print(f"Dashboard:   http://127.0.0.1:8080")
        print(f"API Key:     {self.api_key}")
        print(f"Findings:    {len(findings)}")
        print(f"Instructions:")
        print(f"  1. Open http://127.0.0.1:8080")
        print(f"  2. Paste API Key: {self.api_key}")
        print(f"  3. Click Login")
        print(f"{'='*70}")

async def main():
    scanner = ScannerIntegration()
    await scanner.full_pipeline(sample_size=30)

if __name__ == "__main__":
    asyncio.run(main())

# Add more sophisticated test vectors
ADVANCED_VECTORS = {
    'sql_injection': ['SELECT * FROM users', "'; DROP TABLE--", "1' OR '1'='1"],
    'xxe_injection': ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'],
    'insecure_deserialization': ['pickle:exploit', 'java:rce'],
    'hardcoded_secrets': ['aws_access_key_id=', 'password=', 'api_key=', 'token='],
    'rate_limit_bypass': ['X-Forwarded-For: 127.0.0.1', 'X-Real-IP: 127.0.0.1', 'X-Client-IP: 127.0.0.1'],
    'jwt_validation_bypass': ['none algorithm', 'empty signature', 'algorithm confusion'],
}
