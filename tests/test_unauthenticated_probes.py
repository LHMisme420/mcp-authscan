#!/usr/bin/env python3
"""
Test unauthenticated discovery endpoints
Many MCP servers allow tools/list for discovery, but shouldn't reveal sensitive data
"""
import json

import requests


class UnauthenticatedProbeTest:
    """Test discovery endpoints without auth"""

    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.findings = []

    def test_tools_list_no_auth(self):
        """POST to /tools/list without Authorization header"""
        endpoint = f"{self.base_url}/tools/list"
        payload = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 1
        }

        try:
            resp = requests.post(endpoint, json=payload, timeout=5)

            if resp.status_code == 200:
                # Server responded without auth
                data = resp.json()

                # Check if it actually returned tool info
                if "result" in data and data["result"]:
                    self.findings.append({
                        "severity": "CRITICAL",
                        "endpoint": "/tools/list",
                        "issue": "Tools enumeration without authentication",
                        "response": data
                    })
            elif resp.status_code == 401:
                self.findings.append({
                    "severity": "PASS",
                    "endpoint": "/tools/list",
                    "issue": "Properly requires authentication"
                })
        except Exception as e:
            self.findings.append({
                "severity": "ERROR",
                "endpoint": "/tools/list",
                "error": str(e)
            })

    def test_initialize_no_auth(self):
        """POST to /initialize without Authorization header"""
        endpoint = f"{self.base_url}/initialize"
        payload = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-01-15",
                "capabilities": {},
                "clientInfo": {
                    "name": "mcp-authscan",
                    "version": "1.0"
                }
            },
            "id": 1
        }

        try:
            resp = requests.post(endpoint, json=payload, timeout=5)

            if resp.status_code == 200:
                data = resp.json()
                if "result" in data:
                    self.findings.append({
                        "severity": "HIGH",
                        "endpoint": "/initialize",
                        "issue": "Server initialization without authentication",
                        "response": data
                    })
            elif resp.status_code == 401:
                self.findings.append({
                    "severity": "PASS",
                    "endpoint": "/initialize",
                    "issue": "Properly requires authentication"
                })
        except Exception as e:
            self.findings.append({
                "severity": "ERROR",
                "endpoint": "/initialize",
                "error": str(e)
            })

    def test_sse_no_auth(self):
        """GET /sse without Authorization header"""
        endpoint = f"{self.base_url}/sse"

        try:
            resp = requests.get(endpoint, timeout=5)

            if resp.status_code == 200:
                # Check if returns server metadata
                if "serverInfo" in resp.text or "protocol" in resp.text:
                    self.findings.append({
                        "severity": "CRITICAL",
                        "endpoint": "/sse",
                        "issue": "Server metadata leaked without authentication",
                        "data": resp.text[:200]
                    })
            elif resp.status_code == 401:
                self.findings.append({
                    "severity": "PASS",
                    "endpoint": "/sse",
                    "issue": "Properly requires authentication"
                })
        except Exception as e:
            self.findings.append({
                "severity": "ERROR",
                "endpoint": "/sse",
                "error": str(e)
            })

    def run_all(self):
        """Run all unauthenticated probes"""
        self.test_tools_list_no_auth()
        self.test_initialize_no_auth()
        self.test_sse_no_auth()
        return self.findings

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 test_unauthenticated_probes.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    tester = UnauthenticatedProbeTest(url)
    findings = tester.run_all()

    print(json.dumps(findings, indent=2))
