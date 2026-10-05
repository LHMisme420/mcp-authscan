package oauth

import "net/http"

// A1 MUST fire: the handler trusts the client-supplied destination with no allowlist.
func (h *Handler) handleOAuthAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("response_type") != "code" {
		http.Error(w, "unsupported response_type", http.StatusBadRequest)
		return
	}
	dest := r.URL.Query().Get("redirect_uri")
	code := newAuthCode(r.URL.Query().Get("client_id"))
	http.Redirect(w, r, dest+"?code="+code, http.StatusFound)
}
