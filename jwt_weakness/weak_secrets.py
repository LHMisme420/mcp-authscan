"""
Registry of known weak/default JWT secrets in MCP tools
"""

WEAK_JWT_SECRETS = {
    "mcp-contextforge": {
        "secret": "my-test-key-but-now-longer-than-32-bytes",
        "algorithm": "HS256",
        "known_since": "2026-08-25",
        "cve": "GHSA-8pcq-mx48-hjvj",
        "severity": "CRITICAL",
        "description": "Default JWT secret in docker-compose.yml enables forged admin tokens"
    },
    "generic_weak": [
        "changeme", "test", "secret", "key", "password",
        "my-test-key", "default", "admin", "12345678",
        "jwt_secret", "signing_key", "token_secret"
    ]
}

INSECURE_CONFIG_PATTERNS = {
    "ENVIRONMENT=development": "HIGH",
    "REQUIRE_USER_IN_DB=false": "HIGH",
    "AUTH_REQUIRED=false": "CRITICAL",
    "DEBUG=true": "MEDIUM",
    "JWT_ALGORITHM=HS256": "MEDIUM"  # Symmetric algorithm weakness
}
