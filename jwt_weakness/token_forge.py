"""
JWT token forgery testing - forge tokens with known secrets
"""
import jwt
import json
import time
import uuid
from typing import Dict, Optional

def forge_admin_jwt(
    secret: str,
    algorithm: str = "HS256",
    issuer: str = "mcpgateway",
    audience: str = "mcpgateway-api",
    subject: str = "admin@example.com",
    is_admin: bool = True,
    teams: Optional[list] = None
) -> str:
    """
    Forge a JWT token with admin claims using a known secret.
    """
    now = int(time.time())
    
    payload = {
        "sub": subject,
        "is_admin": is_admin,
        "teams": teams,
        "aud": audience,
        "iss": issuer,
        "iat": now,
        "exp": now + 3600,
        "jti": str(uuid.uuid4())
    }
    
    try:
        token = jwt.encode(payload, secret, algorithm=algorithm)
        return token
    except Exception as e:
        raise ValueError(f"Token forgery failed: {e}")

def validate_token_signature(
    token: str, 
    secret: str, 
    algorithm: str = "HS256",
    audience: str = "mcpgateway-api",
    skip_validation: bool = False
) -> bool:
    """
    Verify that a forged token can be validated with the known secret.
    Returns True if token is valid, False otherwise.
    """
    try:
        if skip_validation:
            # For testing: skip audience/issuer validation
            decoded = jwt.decode(
                token, 
                secret, 
                algorithms=[algorithm],
                options={"verify_aud": False, "verify_iss": False}
            )
        else:
            # For production: validate everything
            decoded = jwt.decode(
                token, 
                secret, 
                algorithms=[algorithm],
                audience=audience
            )
        return True
    except jwt.InvalidSignatureError:
        return False
    except jwt.DecodeError:
        return False
    except Exception as e:
        print(f"Token validation error: {e}")
        return False
