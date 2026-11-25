"""Opt-in signatures for schema-3 CLI JSON; never generates or publishes keys.

``--sign`` is an assertion: a run that asked to sign either produces a
signed report or produces no report at all. The key comes from
``MCP_AUTHSCAN_SIGNING_KEY`` (a path to an Ed25519 PEM), falling back to
``~/.config/mcp-authscan/report-signing.pem``.
"""
import base64
import hashlib
import os
import sys
from pathlib import Path

KEY_ENV = "MCP_AUTHSCAN_SIGNING_KEY"


class SigningError(Exception):
    """Signing is impossible. The message never contains key material or paths."""


def key_path():
    """MCP_AUTHSCAN_SIGNING_KEY if set and non-empty, else the per-user default."""
    configured = os.environ.get(KEY_ENV)
    if configured:
        return Path(configured)
    return Path.home() / ".config" / "mcp-authscan" / "report-signing.pem"


def load_signing_key():
    """Return the Ed25519 private key, or raise SigningError.

    Exception details are deliberately dropped: key material or filesystem
    details must never end up in a machine-readable report or terminal logs.
    Only the exception type name is reported.
    """
    try:
        from cryptography.exceptions import UnsupportedAlgorithm
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        raise SigningError("install mcp-authscan[signing] to use --sign") from None
    try:
        key = serialization.load_pem_private_key(key_path().read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("Signing key is not Ed25519")
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm) as error:
        raise SigningError(
            f"signing key unavailable or invalid ({type(error).__name__})") from None
    return key


def sign_statement(key, content):
    """Ed25519-sign ``content``; return {alg, key_id, value} (key_id = sha256 of the raw public key)."""
    from cryptography.hazmat.primitives import serialization
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key_id = hashlib.sha256(public).hexdigest()
    value = base64.urlsafe_b64encode(key.sign(content)).rstrip(b"=").decode("ascii")
    return {"alg": "ed25519", "key_id": key_id, "value": value}


def sign_report(report, content, key=None):
    """Sign the exact bytes the report's signature covers.

    ``content`` is report_verify.signed_content(...) for this report. Returns
    True on success. On failure prints one line naming only the error type and
    returns False, leaving ``report`` unchanged.
    """
    if report.get("schema_version") != 3 or report.get("hash_scheme") not in ("verdict-v3", "verdict-v4"):
        raise ValueError("Signing requires verdict-v3 or verdict-v4 schema version 3")
    try:
        key = key or load_signing_key()
        signature = sign_statement(key, content)
    except SigningError as error:
        print(f"[!] Signing failed: {error}.", file=sys.stderr)
        return False
    except ImportError:
        print("[!] Signing failed: install mcp-authscan[signing] to use --sign.", file=sys.stderr)
        return False
    except (ValueError, TypeError) as error:
        print(f"[!] Signing failed: {type(error).__name__}.", file=sys.stderr)
        return False
    report["key_id"] = signature["key_id"]
    report["signature"] = signature
    return True
