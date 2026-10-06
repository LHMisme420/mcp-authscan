from fastmcp.client.auth import ClientCredentialsOAuthProvider
auth = ClientCredentialsOAuthProvider(
    client_id="svc",
    client_secret="s3cr3t",
    scopes=["read"],
)
