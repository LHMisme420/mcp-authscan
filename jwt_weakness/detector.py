"""
Main detection logic for JWT secret weakness
"""
import requests
import asyncio
from jwt_weakness.weak_secrets import WEAK_JWT_SECRETS, INSECURE_CONFIG_PATTERNS
from jwt_weakness.token_forge import forge_admin_jwt, validate_token_signature

class JWTWeaknessDetector:
    def __init__(self, mcp_server_url: str, timeout: int = 10):
        self.mcp_server_url = mcp_server_url.rstrip("/")
        self.timeout = timeout
        self.findings = []
    
    def test_known_secret_forgery(self, secret_name: str, secret_value: str) -> dict:
        """
        Test if a known weak secret can forge valid admin tokens.
        """
        try:
            # Forge token
            token = forge_admin_jwt(secret_value)
            
            # Test on common protected endpoints
            protected_endpoints = [
                "/gateways",
                "/admin/users",
                "/admin/config",
                "/admin/servers",
                "/api/servers"
            ]
            
            for endpoint in protected_endpoints:
                try:
                    response = requests.get(
                        f"{self.mcp_server_url}{endpoint}",
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=self.timeout
                    )
                    
                    if response.status_code == 200:
                        return {
                            "vulnerable": True,
                            "secret_name": secret_name,
                            "secret_value": secret_value,
                            "endpoint": endpoint,
                            "status_code": response.status_code,
                            "severity": "CRITICAL"
                        }
                except requests.RequestException:
                    continue
            
            return {"vulnerable": False, "secret_name": secret_name}
        
        except Exception as e:
            return {"error": str(e), "secret_name": secret_name}
    
    def run(self) -> list:
        """
        Execute all JWT weakness tests.
        """
        print(f"[*] Testing {self.mcp_server_url} for JWT weaknesses...")
        
        # Test known secrets
        for secret_name, secret_data in WEAK_JWT_SECRETS.items():
            if isinstance(secret_data, dict) and "secret" in secret_data:
                result = self.test_known_secret_forgery(secret_name, secret_data["secret"])
                if result.get("vulnerable"):
                    self.findings.append({
                        "type": "JWT_SECRET_WEAKNESS",
                        "severity": "CRITICAL",
                        "cve": secret_data.get("cve"),
                        "finding": result
                    })
        
        return self.findings
