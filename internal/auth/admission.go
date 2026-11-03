package auth

import (
	"database/sql"
	"errors"
	"net/http"
	"net/mail"
	"strings"
)

// Account admission is a secondary check for an application's independently
// authenticated credentials. It creates neither a login nor a session/token.
// Browser logout does not disable personal API keys; central account removal does.
func (a *Server) admission(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok || a.Store.AuthorizeClientIDSecret(r.Context(), id, secret) != nil {
		http.Error(w, "Invalid client credentials", 401)
		return
	}
	var input struct {
		Email         string `json:"email"`
		GoogleSubject string `json:"google_sub"`
	}
	if decodeJSON(r, &input) != nil {
		http.Error(w, "Invalid admission request", 400)
		return
	}
	email := strings.ToLower(strings.TrimSpace(input.Email))
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email || len(email) > 254 || len(input.GoogleSubject) > 512 {
		http.Error(w, "Invalid admission request", 400)
		return
	}
	allowed := a.Store.config.AllowedEmails[email]
	if allowed && input.GoogleSubject != "" {
		var subject string
		err = a.Store.db.QueryRowContext(r.Context(), `SELECT google_sub FROM users WHERE email=?`, email).Scan(&subject)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "Admission unavailable", 503)
			return
		}
		if err == nil && subject != input.GoogleSubject {
			allowed = false
		}
	}
	writeJSON(w, 200, map[string]bool{"allowed": allowed})
}
