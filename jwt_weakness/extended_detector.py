"""Extended JWT weakness detection"""
from jwt_weakness.weak_secrets import WEAK_JWT_SECRETS
from jwt_weakness.token_forge import forge_admin_jwt

class ExtendedJWTDetector:
    def __init__(self, url, timeout=5):
        self.url = url
        self.timeout = timeout
    
    def check_weak_secrets(self):
        findings = []
        for secret_name, secret_data in WEAK_JWT_SECRETS.items():
            if isinstance(secret_data, dict) and "secret" in secret_data:
                try:
                    token = forge_admin_jwt(secret_data["secret"])
                    if self._test_token(token):
                        findings.append({"type": "WEAK_SECRET", "secret": secret_name})
                except:
                    pass
        return findings
    
    def _test_token(self, token):
        try:
            import requests
            for ep in ["/gateways", "/admin", "/api"]:
                try:
                    r = requests.get(f"{self.url}{ep}", 
                                   headers={"Authorization": f"Bearer {token}"},
                                   timeout=1)
                    if r.status_code == 200:
                        return True
                except:
                    pass
        except:
            pass
        return False
    
    def run(self):
        return self.check_weak_secrets()
