from mcp.client.auth.extensions.client_credentials import _preferred_authorization_server as pick
A = "https://auth.attacker.example"
B = "https://auth.legit.example"
cases = [
    ("no issuer, [A,B]", [A, B], None),
    ("no issuer, [B,A]", [B, A], None),
    ("issuer=B,  [A,B]", [A, B], B),
    ("issuer=B,  [B,A]", [B, A], B),
    ("issuer=B,  [A]  ", [A], B),
]
for name, adv, iss in cases:
    print(name, "->", pick(adv, iss))
