# Issuer binding is a call-site requirement

GHSA-qx49-fqc8-xw99 and GHSA-6qxp-vccf-f47h say upgrading the MCP SDK does not close machine-to-machine credential redirection. The caller must pass issuer= (Python ClientCredentialsOAuthProvider / PrivateKeyJWTOAuthProvider) or expectedIssuer (TypeScript ClientCredentialsProvider and the private-key providers). Without it, a pre-provisioned secret follows whatever authorization server the MCP server advertises.

mcp-authscan rule C1 fails a build on that omission. It does not fail a call that passes the argument.

pip install mcp-authscan==0.9.4
mcp-authscan . --fail-on high

Fixture: examples/fastmcp-issuer/. Scan the directory. bad.py must exit 1. fixed.py must stay quiet. A directory named fixtures is skipped.

A wrapper that constructs those providers and has no issuer parameter cannot comply. Passing issuer= through is the fix. Absence of a C1 finding is not proof the client is safe.
