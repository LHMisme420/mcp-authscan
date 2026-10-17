package main

import "net/http"

func h(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.URL.Query().Get("next"), 302) // T9-REDIR
}
