"""Extended JWT weakness detection"""
import base64
import json

from jwt_weakness.token_forge import forge_admin_jwt
from jwt_weakness.weak_secrets import WEAK_JWT_SECRETS


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unsigned_token(algorithm):
    """Build a JWT whose signature segment is empty.

    No secret and no target key material is involved: the token declares an
    algorithm in its header and carries nothing to verify. That is enough to
    observe whether the server checks signatures at all, without forging one.
    """
    header = {"alg": algorithm, "typ": "JWT"}
    payload = {
        "sub": "mcp-authscan-alg-confusion-probe",
        "role": "admin",
        "exp": 4102444800,  # 2100-01-01, keeps exp validators quiet
    }
    header_part = _b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_part = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    return f"{header_part}.{payload_part}."


class ExtendedJWTDetector:
    # Variants that need no key material. The asymmetric-key-signed-with-HMAC
    # variant is deliberately absent: it requires forging a signature over an
    # attacker payload using the target's public key, which turns a
    # precondition check into an exploit (see CONTRIBUTING.md).
    ALGORITHM_CONFUSION_VARIANTS = ("none", "HS256")

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

    def check_algorithm_confusion(self):
        """Detect servers that accept a token whose signature was never verified.

        Each variant is an unsigned token (empty signature segment) declaring a
        different algorithm. A server that answers 200 has skipped signature
        verification entirely - the precondition behind every
        algorithm-confusion attack, whatever the key type.
        """
        findings = []
        for algorithm in self.ALGORITHM_CONFUSION_VARIANTS:
            try:
                token = _unsigned_token(algorithm)
            except Exception:
                continue
            try:
                accepted = self._test_token(token)
            except Exception:
                accepted = False
            if accepted:
                findings.append({
                    "type": "ALGORITHM_CONFUSION",
                    "variant": "unsigned_" + algorithm.lower(),
                    "detail": f"server accepted an unsigned {algorithm} token",
                })
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
