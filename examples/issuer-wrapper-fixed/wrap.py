class ClientCredentialsOAuthProvider:
    pass
class Wrapper(ClientCredentialsOAuthProvider):
    def __init__(self):
        super().__init__(server_url="https://mcp.example", client_id="svc", client_secret="s3cr3t", issuer="https://auth.example.com")
