package oauth

import "net/http"

// Thin handler that delegates the whole authorize to a service; validation happens
// inside StartAuthorization, not inline. A1 must NOT fire here either.
func (h *oauthHandler) handleAuthorizeDelegated(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	req := AuthorizeRequest{
		ClientID:    q.Get("client_id"),
		RedirectURI: q.Get("redirect_uri"),
	}
	if _, err := h.authorize.StartAuthorization(r.Context(), req); err != nil {
		http.Error(w, "invalid_request", http.StatusBadRequest)
	}
}
