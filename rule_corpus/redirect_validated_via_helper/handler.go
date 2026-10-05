package oauth

import "net/http"

// handleAuthorize reads redirect_uri from the request but validates it against the
// client's REGISTERED uris via a helper before any redirect. A1 must NOT fire here.
func (h *Handler) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")

	client, err := h.store.GetClient(r.Context(), clientID)
	if err != nil {
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	}
	registered, ok := registeredRedirect(client, redirectURI)
	if !ok {
		http.Error(w, "redirect_uri not registered for this client", http.StatusBadRequest)
		return
	}
	redirectURI = registered // never follow the request's copy
	_ = redirectURI
}
