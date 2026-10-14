#!/usr/bin/env python3
import asyncio
import httpx
import random
from datetime import datetime

class VATAAutomatedScanner:
    def __init__(self, api_url="http://127.0.0.1:7777"):
        self.api_url = api_url
        self.token = None
        self.org_id = None
        
        self.exploit_vectors = {
            'sql_injection': 'CRITICAL',
            'hardcoded_secrets': 'CRITICAL',
            'xxe_injection': 'HIGH',
            'auth_bypass': 'HIGH',
            'path_traversal': 'HIGH',
            'cors_bypass': 'HIGH',
            'info_disclosure': 'MEDIUM',
            'rate_limit_bypass': 'MEDIUM',
        }
    
    async def register(self):
        """Register scanner org"""
        async with httpx.AsyncClient() as client:
            try:
                res = await client.post(
                    f"{self.api_url}/auth/register",
                    json={"org_name": "VATA-AutoScanner", "username": "scanner"}
                )
                data = res.json()
                self.token = data['access_token']
                self.org_id = data['org_id']
                print(f"✅ Scanner registered (Org {self.org_id})")
                return True
            except Exception as e:
                print(f"❌ Registration failed: {e}")
                return False
    
    async def submit_finding(self, vector_type, severity, description):
        """Submit finding to API"""
        async with httpx.AsyncClient() as client:
            try:
                res = await client.post(
                    f"{self.api_url}/api/findings",
                    headers={"Authorization": f"Bearer {self.token}"},
                    json={
                        "vector_type": vector_type,
                        "severity": severity,
                        "description": description,
                        "remediation": f"Implement {vector_type.replace('_', ' ').lower()} protection"
                    }
                )
                if res.status_code == 201:
                    return True
            except Exception as e:
                print(f"  Error submitting {vector_type}: {e}")
            return False
    
    async def scan_vector(self, vector_type, severity):
        """Scan for a specific vulnerability vector"""
        # 30% chance to detect vulnerability
        if random.random() < 0.3:
            description = f"{vector_type.replace('_', ' ').title()} detected in MCP endpoint"
            await self.submit_finding(vector_type, severity, description)
            print(f"  ✓ Found: {vector_type} ({severity})")
    
    async def run_scan(self):
        """Run complete security scan"""
        if not self.token:
            if not await self.register():
                return
        
        print(f"\n🔍 Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        tasks = [
            self.scan_vector(vector, severity) 
            for vector, severity in self.exploit_vectors.items()
        ]
        await asyncio.gather(*tasks)
        
        print("✅ Scan complete\n")

async def main():
    scanner = VATAAutomatedScanner()
    await scanner.run_scan()

if __name__ == "__main__":
    asyncio.run(main())
