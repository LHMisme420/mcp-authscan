class ClientCredentialsOAuthProvider:
    pass
class Wrapper(ClientCredentialsOAuthProvider):
    def __init__(self):
        super().__init__(issuer="https://auth.example.com")
