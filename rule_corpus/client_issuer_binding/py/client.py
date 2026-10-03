# Fixture: MCP Python client M2M providers. Lines are pinned in ground_truth.json.
from mcp.client.auth import ClientCredentialsOAuthProvider, PrivateKeyJWTOAuthProvider
from mcp.client.auth import RFC7523OAuthClientProvider

unbound = ClientCredentialsOAuthProvider(
    server_url="https://mcp.example.com/mcp",
    storage=store,
    client_id="svc", client_secret=SECRET,
)

bound = ClientCredentialsOAuthProvider(
    server_url="https://mcp.example.com/mcp",
    storage=store,
    client_id="svc", client_secret=SECRET,
    issuer="https://auth.example.com",
)

legacy = RFC7523OAuthClientProvider(server_url="https://mcp.example.com/mcp", storage=store)

jwt_spread = PrivateKeyJWTOAuthProvider(**provider_kwargs)
