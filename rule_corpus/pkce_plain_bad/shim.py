# FIXTURE (synthetic) — Python PKCE-plain downgrade. B1 MUST fire.
# Authorize defaults code_challenge_method to "plain"; token handler honors it by
# comparing the RAW verifier (no S256 transform) -> plain PKCE, OAuth 2.1 forbidden.
import hashlib, base64
async def authorize(request):
    p = await form(request)
    codes[newcode] = {"challenge": p.get("code_challenge", ""),
                      "method": p.get("code_challenge_method", "plain")}  # defaults plain
async def token(request):
    form_d = await form(request)
    if form_d.get("grant_type") == "authorization_code":
        rec = codes.pop(form_d.get("code", ""), None)
        if not rec: return err("invalid_grant")
        verifier = form_d.get("code_verifier", "")
        if rec["method"] == "S256":
            calc = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        else:
            calc = verifier          # BUG: plain honored, challenge == verifier
        if calc != rec["challenge"]: return err("invalid_grant")
    return ok()
