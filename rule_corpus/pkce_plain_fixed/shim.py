# FIXTURE (synthetic) — PKCE S256 enforced. B1 must STAY SILENT (fail-closed).
# No plain default; non-S256 methods are rejected outright, raw verifier is never
# accepted as a challenge comparison.
import hashlib, base64
async def authorize(request):
    p = await form(request)
    method = p.get("code_challenge_method", "S256")
    if method != "S256": return err("invalid_request", "S256 required")  # reject plain
    codes[newcode] = {"challenge": p.get("code_challenge", ""), "method": "S256"}
async def token(request):
    form_d = await form(request)
    if form_d.get("grant_type") == "authorization_code":
        rec = codes.pop(form_d.get("code", ""), None)
        if not rec: return err("invalid_grant")
        verifier = form_d.get("code_verifier", "")
        if rec["method"] != "S256": return err("invalid_grant")  # no plain path at all
        calc = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        if calc != rec["challenge"]: return err("invalid_grant")
    return ok()
