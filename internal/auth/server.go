package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	googleoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/rs/cors"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/time/rate"
)

const sessionCookie = "__Host-nox-auth"

type googleIdentity struct {
	Subject, Email, Name string
	Verified             bool
}
type googleTransaction struct {
	Created                                 time.Time
	RequestID, Nonce, Verifier, BrowserHash string
}
type Server struct {
	limiter        *rate.Limiter
	Store          *Store
	Provider       *op.Provider
	oauth          oauth2.Config
	googleVerifier *googleoidc.IDTokenVerifier
	verifyGoogle   func(context.Context, string, string) (googleIdentity, error)
	httpClient     *http.Client
}

func New(s *Store) (*Server, error) {
	corsOptions := &cors.Options{AllowedOrigins: []string{}, AllowedMethods: []string{http.MethodGet, http.MethodPost}}
	p, e := op.NewOpenIDProvider(s.config.PublicURL, &op.Config{CryptoKey: s.cryptoKey, CryptoKeyId: s.key.id, CodeMethodS256: true, SupportedScopes: []string{"openid", "email", "profile"}}, s, op.WithCORSOptions(corsOptions), op.WithCrypto(op.NewAES256GCMCrypto(s.cryptoKey, s.key.id)))
	if e != nil {
		return nil, e
	}
	client := &http.Client{Timeout: 15 * time.Second}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)
	// Static Google metadata avoids a discovery network dependency at startup.
	verifier := googleoidc.NewVerifier("https://accounts.google.com", googleoidc.NewRemoteKeySet(ctx, "https://www.googleapis.com/oauth2/v3/certs"), &googleoidc.Config{ClientID: s.config.GoogleClientID, SupportedSigningAlgs: []string{"RS256"}})
	a := &Server{Store: s, Provider: p, httpClient: client, googleVerifier: verifier, oauth: oauth2.Config{ClientID: s.config.GoogleClientID, ClientSecret: s.config.GoogleClientSecret, RedirectURL: s.config.PublicURL + "/auth/google/callback", Endpoint: google.Endpoint, Scopes: []string{"openid", "email", "profile"}}}
	a.limiter = rate.NewLimiter(20, 40)
	a.verifyGoogle = a.exchangeGoogle
	return a, nil
}
func (a *Server) exchangeGoogle(ctx context.Context, code, transactionID string) (googleIdentity, error) {
	tx, ok := ctx.Value(googleTransactionKey{}).(googleTransaction)
	if !ok {
		return googleIdentity{}, ErrDenied
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, a.httpClient)
	token, e := a.oauth.Exchange(ctx, code, oauth2.VerifierOption(tx.Verifier))
	if e != nil {
		return googleIdentity{}, ErrDenied
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		return googleIdentity{}, ErrDenied
	}
	id, e := a.googleVerifier.Verify(ctx, raw)
	if e != nil || id.Nonce != tx.Nonce {
		return googleIdentity{}, ErrDenied
	}
	var claims struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
		Name     string `json:"name"`
	}
	if e = id.Claims(&claims); e != nil || !claims.Verified || id.Subject == "" {
		return googleIdentity{}, ErrDenied
	}
	return googleIdentity{id.Subject, strings.ToLower(claims.Email), claims.Name, claims.Verified}, nil
}
func security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		r.Body = http.MaxBytesReader(w, r.Body, 32768)
		defer func() {
			if recover() != nil {
				http.Error(w, "Internal authentication error", 500)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
func (a *Server) PublicHandler() http.Handler {
	return security(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", 405)
			return
		}
		switch r.URL.Path {
		case "/authorize", "/login", "/authorize/callback", "/auth/google/callback":
			if !a.limiter.Allow() {
				w.Header().Set("Retry-After", "1")
				http.Error(w, "Too many login requests", 429)
				return
			}
		}
		switch r.URL.Path {
		case "/healthz":
			a.health(w, r)
		case "/readyz":
			a.health(w, r)
		case "/":
			writeJSON(w, 200, map[string]any{"productId": "nox-auth", "service": "NoX Login", "dashboard": false})
		case "/login":
			a.login(w, r)
		case "/auth/google/callback":
			a.googleCallback(w, r)
		case "/authorize/callback":
			a.authorizeCallback(w, r)
		case "/authorize", "/keys", "/.well-known/openid-configuration":
			a.Provider.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
}
func (a *Server) PrivateHandler() http.Handler {
	return security(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token", "/oauth/introspect", "/revoke":
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", 405)
				return
			}
			a.Provider.ServeHTTP(w, r)
		case "/userinfo":
			if r.Method != http.MethodGet && r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", 405)
				return
			}
			a.Provider.ServeHTTP(w, r)
		case "/v1/logout":
			a.logout(w, r)
		case "/healthz":
			a.health(w, r)
		case "/keys", "/.well-known/openid-configuration":
			if r.Method != http.MethodGet {
				http.Error(w, "Method not allowed", 405)
				return
			}
			a.Provider.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
}
func (a *Server) AdminHandler() http.Handler {
	return security(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This handler is ONLY attached to the separately mounted administrator Unix socket.
		if !strings.HasPrefix(r.URL.Path, "/v1/clients/") {
			http.NotFound(w, r)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/v1/clients/")
		if !clientIDPattern.MatchString(id) {
			http.Error(w, "Invalid client id", 400)
			return
		}
		if r.Method == http.MethodDelete {
			if e := a.Store.remove("client", id); e != nil {
				http.Error(w, "Storage unavailable", 503)
				return
			}
			if e := a.Store.invalidateClient(id); e != nil {
				http.Error(w, "Storage unavailable", 503)
				return
			}
			w.WriteHeader(204)
			return
		}
		if r.Method != http.MethodPut {
			http.Error(w, "Method not allowed", 405)
			return
		}
		var input struct {
			Secret      string   `json:"client_secret"`
			Redirects   []string `json:"redirect_uris"`
			SuiteLogout bool     `json:"suite_logout"`
		}
		if e := decodeJSON(r, &input); e != nil || len(input.Secret) < 43 || len(input.Secret) > 256 {
			http.Error(w, "A randomly generated client secret of at least 32 bytes and exact callbacks are required", 400)
			return
		}
		c := Client{ID: id, Redirects: input.Redirects, SecretHash: hash(input.Secret), SuiteLogout: input.SuiteLogout, Revision: random()}
		if e := validateClient(&c); e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		// Repeating an unchanged enrollment is safe; changing its credentials/callbacks revokes old tokens.
		old, e := a.Store.GetClientByClientID(r.Context(), id)
		if e == nil {
			c.Revision = old.(*Client).Revision
			previous, _ := json.Marshal(old)
			next, _ := json.Marshal(&c)
			if string(previous) != string(next) {
				c.Revision = random()
				if e = a.Store.invalidateClient(id); e != nil {
					http.Error(w, "Storage unavailable", 503)
					return
				}
			}
		}
		if e = a.Store.put("client", id, &c); e != nil {
			http.Error(w, "Storage unavailable", 503)
			return
		}
		writeJSON(w, 200, map[string]any{"client_id": id, "redirect_uris": c.Redirects, "suite_logout": c.SuiteLogout})
	}))
}
func (a *Server) health(w http.ResponseWriter, r *http.Request) {
	if a.Store.Health(r.Context()) != nil {
		writeJSON(w, 503, map[string]string{"status": "unavailable"})
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}
func (a *Server) browserSession(r *http.Request) (string, Session, error) {
	c, e := r.Cookie(sessionCookie)
	if e != nil {
		return "", Session{}, ErrDenied
	}
	s, e := a.Store.session(hash(c.Value))
	return c.Value, s, e
}
func setSession(w http.ResponseWriter, raw string) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: raw, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(SessionLifetime.Seconds()), Expires: time.Now().Add(SessionLifetime)})
}
func (a *Server) login(w http.ResponseWriter, r *http.Request) {
	request, e := a.Store.AuthRequestByID(r.Context(), r.URL.Query().Get("id"))
	if e != nil {
		http.Error(w, "Invalid or expired login request", 400)
		return
	}
	req := request.(*Request)
	// Invalid hints do not authenticate a browser; only the server's own cookie does.
	raw, session, e := a.browserSession(r)
	force := false
	none := false
	for _, prompt := range req.Request.Prompt {
		switch prompt {
		case "login", "select_account":
			force = true
		case "none":
			none = true
		case "":
		default:
			http.Error(w, "Unsupported login prompt", 400)
			return
		}
	}
	if req.Request.MaxAge != nil && session.AuthTime.Add(time.Duration(*req.Request.MaxAge)*time.Second).Before(a.Store.now()) {
		force = true
	}
	if e == nil && !force {
		if !a.complete(w, r, req, session) {
			return
		}
		setSession(w, raw)
		http.Redirect(w, r, "/authorize/callback?id="+url.QueryEscape(req.ID), 302)
		return
	}
	if none {
		op.AuthRequestError(w, r, &req.Request, oidc.ErrLoginRequired(), a.Provider)
		return
	}
	state := random()
	browser := random()
	tx := googleTransaction{Created: a.Store.now(), RequestID: req.ID, Nonce: random(), Verifier: oauth2.GenerateVerifier(), BrowserHash: hash(browser)}
	if e = a.Store.put("google", hash(state), tx); e != nil {
		http.Error(w, "Authentication storage unavailable", 503)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "__Host-nox-login-" + state[:12], Value: browser, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(TransactionLifetime.Seconds())})
	options := []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("nonce", tx.Nonce), oauth2.S256ChallengeOption(tx.Verifier)}
	if force {
		options = append(options, oauth2.SetAuthURLParam("prompt", "select_account"))
	}
	http.Redirect(w, r, a.oauth.AuthCodeURL(state, options...), 302)
}
func (a *Server) complete(w http.ResponseWriter, r *http.Request, req *Request, session Session) bool {
	if req.Complete && req.SessionID != session.ID {
		http.Error(w, "Login transaction belongs to another session", 403)
		return false
	}
	req.Complete = true
	req.UserID = session.UserID
	req.SessionID = session.ID
	req.AuthTime = session.AuthTime
	if e := a.Store.put("request", req.ID, req); e != nil {
		http.Error(w, "Authentication storage unavailable", 503)
		return false
	}
	if _, e := a.Store.db.Exec(`UPDATE root_sessions SET expires=? WHERE id=? AND revoked=0`, a.Store.now().Add(SessionLifetime).Unix(), session.ID); e != nil {
		http.Error(w, "Authentication storage unavailable", 503)
		return false
	}
	return true
}
func (a *Server) googleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if len(state) != 43 {
		http.Error(w, "Invalid login transaction", 400)
		return
	}
	var tx googleTransaction
	e := a.Store.get("google", hash(state), &tx)
	cookieName := "__Host-nox-login-" + state[:12]
	cookie, ce := r.Cookie(cookieName)
	if e != nil || ce != nil || !a.Store.now().Before(tx.Created.Add(TransactionLifetime)) || subtle.ConstantTimeCompare([]byte(hash(cookie.Value)), []byte(tx.BrowserHash)) != 1 {
		http.Error(w, "Invalid or expired login transaction", 400)
		return
	}
	// Consume the transaction atomically before the external exchange; callbacks cannot replay.
	result, e := a.Store.db.Exec(`DELETE FROM records WHERE kind='google' AND id=?`, hash(state))
	if e != nil {
		http.Error(w, "Authentication unavailable", 503)
		return
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		http.Error(w, "Login transaction already used", 400)
		return
	}
	// The verifier needs the PKCE/nonce record during its call, so provide it via context rather than reloading consumed state.
	ctx := context.WithValue(r.Context(), googleTransactionKey{}, tx)
	identity, e := a.verifyGoogle(ctx, r.URL.Query().Get("code"), hash(state))
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	if e != nil || !identity.Verified || !a.Store.config.AllowedEmails[identity.Email] {
		http.Error(w, "This Google account is not authorized for NoX Login", 403)
		return
	}
	request, e := a.Store.AuthRequestByID(r.Context(), tx.RequestID)
	if e != nil {
		http.Error(w, "Login request expired", 400)
		return
	}
	user, e := a.Store.login(identity.Subject, identity.Email, identity.Name)
	if e != nil {
		http.Error(w, "Account admission failed", 403)
		return
	}
	raw, session, e := a.Store.newSession(user)
	if e != nil {
		http.Error(w, "Authentication storage unavailable", 503)
		return
	}
	if !a.complete(w, r, request.(*Request), session) {
		return
	}
	setSession(w, raw)
	http.Redirect(w, r, "/authorize/callback?id="+url.QueryEscape(tx.RequestID), 302)
}

type googleTransactionKey struct{}

func (a *Server) authorizeCallback(w http.ResponseWriter, r *http.Request) {
	req, e := a.Store.AuthRequestByID(r.Context(), r.URL.Query().Get("id"))
	_, session, se := a.browserSession(r)
	if e != nil || se != nil || !req.Done() || req.(*Request).SessionID != session.ID {
		http.Error(w, "Invalid authorization transaction", 403)
		return
	}
	a.Provider.ServeHTTP(w, r)
}
func (a *Server) logout(w http.ResponseWriter, r *http.Request) {
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
		Token string `json:"token"`
		Scope string `json:"scope"`
	}
	if decodeJSON(r, &input) != nil {
		http.Error(w, "Invalid logout request", 400)
		return
	}
	decrypted, e := a.Provider.Crypto().Decrypt(input.Token)
	if e != nil {
		http.Error(w, "Invalid session credential", 401)
		return
	}
	parts := strings.Split(decrypted, ":")
	if len(parts) != 2 {
		http.Error(w, "Invalid session credential", 401)
		return
	}
	token, session, e := a.Store.token(parts[0], id, false)
	if e != nil || token.UserID != parts[1] {
		http.Error(w, "Invalid session credential", 401)
		return
	}
	switch input.Scope {
	case "app":
		_, e = a.Store.db.Exec(`UPDATE access_tokens SET revoked=1 WHERE id=?`, token.ID)
	case "suite":
		client, ce := a.Store.GetClientByClientID(r.Context(), id)
		if ce != nil || !client.(*Client).SuiteLogout {
			http.Error(w, "Client has no Suite logout permission", 403)
			return
		}
		e = a.Store.revokeSession(session.ID)
	default:
		http.Error(w, "Logout scope must be app or suite", 400)
		return
	}
	if e != nil {
		http.Error(w, "Session revocation unavailable", 503)
		return
	}
	w.WriteHeader(204)
}
func decodeJSON(r *http.Request, v any) error {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		return errors.New("JSON content type required")
	}
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return errors.New("unexpected trailing input")
	}
	return nil
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
