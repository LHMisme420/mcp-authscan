"""
Extended JWT weakness detection - comprehensive checks
"""
from jwt_weakness.weak_secrets import WEAK_JWT_SECRETS
from jwt_weakness.token_forge import forge_admin_jwt, validate_token_signature

class ExtendedJWTDetector:
    """Detect multiple JWT vulnerability patterns."""
    
    def __init__(self, mcp_server_url: str, timeout: int = 5):
        self.url = mcp_server_url
        self.timeout = timeout
        self.findings = []
    
    def check_weak_secrets(self) -> list:
        """Test for known weak JWT secrets."""
        findings = []
        for secret_name, secret_data in WEAK_JWT_SECRETS.items():
            if isinstance(secret_data, dict) and "secret" in secret_data:
                try:
                    token = forge_admin_jwt(secret_data["secret"])
                    if self._test_token_accepted(token):
                        findings.append({
                            "type": "WEAK_JWT_SECRET",
                            "severity": "CRITICAL",
                            "secret": secret_name,
                            "cve": secret_data.get("cve"),
                            "message": f"Known weak secret: {secret_name}"
                        })
                except:
                    pass
        return findings
    
    def check_algorithm_confusion(self) -> list:
        """Test for algorithm confusion (HS256 when RS256 expected)."""
        findings = []
        try:
            # Try forging with HS256 against RS256 endpoint
            token = forge_admin_jwt("secret", algorithm="HS256")
            if self._test_token_accepted(token):
                findings.append({
                    "type": "ALGORITHM_CONFUSION",
                    "severity": "CRITICAL",
                    "message": "Server accepts HS256 when RS256 expected"
                })
        except:
            pass
        return findings
    
    def check_missing_validation(self) -> list:
        """Test for missing signature/expiration validation."""
        findings = []
        try:
            # Expired token
            import time
            import jwt
            secret = "test-secret-32-bytes-long!!!!!"
            past = int(time.time()) - 3600  # 1 hour ago
            payload = {
                "sub": "attacker",
                "exp": past,  # Expired
                "iat": past - 7200
            }
            token = jwt.encode(payload, secret, algorithm="HS256")
            if self._test_token_accepted(token):
                findings.append({
                    "type": "MISSING_EXPIRATION_CHECK",
                    "severity": "HIGH",
                    "message": "Expired JWT accepted"
                })
        except:
            pass
        return findings
    
    def check_rbac_bypass(self) -> list:
        """Test for RBAC bypass via token manipulation."""
        findings = []
        try:
            # Forge admin token
            token = forge_admin_jwt("any-secret", is_admin=True, teams=None)
            if self._test_token_accepted(token):
                findings.append({
                    "type": "RBAC_BYPASS_POSSIBLE",
                    "severity": "HIGH",
                    "message": "Forged admin token accepted"
                })
        except:
            pass
        return findings
    
    def _test_token_accepted(self, token: str) -> bool:
        """Test if a token is accepted by any endpoint."""
        endpoints = [
            "/gateways", "/admin", "/api/admin",
            "/servers", "/tools", "/auth/verify"
        ]
        
        try:
            import requests
            for endpoint in endpoints:
                try:
                    resp = requests.get(
                        f"{self.url}{endpoint}",
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=self.timeout
                    )
                    if resp.status_code == 200:
                        return True
                except:
                    continue
        except:
            pass
        return False
    
    def run(self) -> list:
        """Execute all JWT checks."""
        all_findings = []
        all_findings.extend(self.check_weak_secrets())
        all_findings.extend(self.check_algorithm_confusion())
        all_findings.extend(self.check_missing_validation())
        all_findings.extend(self.check_rbac_bypass())
        return all_findings
