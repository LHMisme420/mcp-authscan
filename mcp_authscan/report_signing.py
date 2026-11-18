"""Opt-in signatures for schema-3 CLI JSON; never generates or publishes keys."""
import base64
import hashlib
from pathlib import Path
import sys


def sign_report(report, content):
    """Sign the exact bytes returned by compute(include_bytes=True)."""
    if report.get("schema_version") != 3 or report.get("hash_scheme") != "verdict-v3":
        raise ValueError("Signing requires verdict-v3 schema version 3")
    try:
        from cryptography.exceptions import UnsupportedAlgorithm
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        print("[!] Report unsigned: install mcp-authscan[signing] to use --sign.",
              file=sys.stderr)
        return False
    try:
        path = Path.home() / ".config" / "mcp-authscan" / "report-signing.pem"
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("Signing key is not Ed25519")
        public = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        key_id = hashlib.sha256(public).hexdigest()
        value = base64.urlsafe_b64encode(key.sign(content)).rstrip(b"=").decode("ascii")
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm) as error:
        # Do not include exception details: key material or filesystem details
        # must never end up in a machine-readable report or terminal logs.
        print(f"[!] Report unsigned: signing key unavailable or invalid ({type(error).__name__}).",
              file=sys.stderr)
        return False
    report["key_id"] = key_id
    report["signature"] = {"alg": "ed25519", "key_id": key_id, "value": value}
    return True
