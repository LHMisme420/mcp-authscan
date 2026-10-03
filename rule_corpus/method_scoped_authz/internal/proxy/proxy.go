// Fixture for VATA mcp-authscan rule A6 (method-scoped authorization).
// Minimal reproduction of the pattern: an authz deny gated on one JSON-RPC
// method, with no catch-all deny for other methods. Synthetic, not real code.
package proxy

func dispatch(req Request, tenant Tenant) error {
	switch req.Method {
	case "tools/call":
		if !tenant.ToolAllowed(req.Name) {
			return ErrForbidden // DeniedRBAC
		}
	}
	// NOTE: resources/*, prompts/* fall through here with no authz check.
	return forward(req)
}
