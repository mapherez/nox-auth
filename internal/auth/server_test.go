package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	googleoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/mapherez/nox-auth/client"
	"golang.org/x/oauth2"
)

type fixture struct {
	t           *testing.T
	store       *Store
	server      *Server
	public      *httptest.Server
	browser     *http.Client
	socket      string
	googleCalls int
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t}
	public := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.server.PublicHandler().ServeHTTP(w, r) }))
	f.public = public
	t.Cleanup(public.Close)
	config := Config{PublicURL: public.URL, GoogleClientID: "test-google-client", GoogleClientSecret: random(), AllowedEmails: map[string]bool{"admin@example.test": true}, DataDir: t.TempDir()}
	store, e := Open(config)
	if e != nil {
		t.Fatal(e)
	}
	f.store = store
	t.Cleanup(func() { _ = f.store.Close() })
	f.server, e = New(store)
	if e != nil {
		t.Fatal(e)
	}
	f.server.verifyGoogle = func(_ context.Context, code, _ string) (googleIdentity, error) {
		f.googleCalls++
		if code != "allowed" {
			return googleIdentity{"other", "other@example.test", "Other", true}, nil
		}
		return googleIdentity{"google-subject", "admin@example.test", "Admin", true}, nil
	}
	jar, _ := cookiejar.New(nil)
	f.browser = public.Client()
	f.browser.Jar = jar
	f.browser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	// Use the OS temporary directory and a short suffix, respecting macOS socket limits.
	directory, e := os.MkdirTemp("", "na")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	listener, e := ListenLocal(directory, "p")
	if e != nil {
		t.Fatal(e)
	}
	f.socket = filepath.Join(directory, "p")
	private := &http.Server{Handler: f.server.PrivateHandler()}
	go func() { _ = private.Serve(listener) }()
	t.Cleanup(func() { _ = private.Close(); _ = listener.Close() })
	return f
}
func (f *fixture) app(id, callback string, global bool) *client.Client {
	f.t.Helper()
	secret := client.GenerateSecret()
	body, _ := json.Marshal(map[string]any{"client_secret": secret, "redirect_uris": []string{callback}, "suite_logout": global})
	req := httptest.NewRequest(http.MethodPut, "http://control/v1/clients/"+id, strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.server.AdminHandler().ServeHTTP(w, req)
	if w.Code != 200 {
		f.t.Fatal(w.Code, w.Body.String())
	}
	c, e := client.New(client.Config{Issuer: f.public.URL, ClientID: id, ClientSecret: secret, SocketPath: f.socket})
	if e != nil {
		f.t.Fatal(e)
	}
	return c
}
func (f *fixture) visit(raw string) *http.Response {
	f.t.Helper()
	if strings.HasPrefix(raw, "/") {
		raw = f.public.URL + raw
	}
	resp, e := f.browser.Get(raw)
	if e != nil {
		f.t.Fatal(e)
	}
	resp.Body.Close()
	return resp
}
func (f *fixture) authorize(c *client.Client, callback string) (client.Transaction, url.Values) {
	f.t.Helper()
	tx, loginURL, e := c.Begin(callback, "/projects?view=active")
	if e != nil {
		f.t.Fatal(e)
	}
	resp := f.visit(loginURL)
	if resp.StatusCode != 302 {
		f.t.Fatalf("authorize: %d", resp.StatusCode)
	}
	resp = f.visit(resp.Header.Get("Location"))
	if resp.StatusCode != 302 {
		f.t.Fatalf("login: %d", resp.StatusCode)
	}
	location := resp.Header.Get("Location")
	if strings.HasPrefix(location, "https://accounts.google.com/") {
		u, _ := url.Parse(location)
		q := u.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" {
			f.t.Fatal("Google transaction lacks PKCE/nonce")
		}
		resp = f.visit("/auth/google/callback?" + url.Values{"state": {q.Get("state")}, "code": {"allowed"}}.Encode())
		if resp.StatusCode != 302 {
			f.t.Fatalf("Google callback: %d", resp.StatusCode)
		}
		location = resp.Header.Get("Location")
	}
	resp = f.visit(location)
	if resp.StatusCode != 302 {
		f.t.Fatalf("authorize callback: %d", resp.StatusCode)
	}
	u, e := url.Parse(resp.Header.Get("Location"))
	if e != nil {
		f.t.Fatal(e)
	}
	if u.Scheme+"://"+u.Host+u.Path != callback {
		f.t.Fatal("wrong app callback", u)
	}
	return tx, u.Query()
}

func (f *fixture) login(c *client.Client, callback string) (client.Credentials, url.Values) {
	f.t.Helper()
	tx, query := f.authorize(c, callback)
	credentials, e := c.Complete(context.Background(), callback, tx, query)
	if e != nil {
		f.t.Fatal("complete:", e)
	}
	return credentials, query
}

func TestRealOIDCCodeFlowPrivateCallbacksSSOAndLogout(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	appA := f.app("test-app-a", "http://192.0.2.10:8095/auth/callback", true)
	appB := f.app("test-app-b", "http://another.home.arpa/auth/callback", false)
	first, _ := f.login(appA, "http://192.0.2.10:8095/auth/callback")
	second, _ := f.login(appB, "http://another.home.arpa/auth/callback")
	if f.googleCalls != 1 {
		t.Fatal("SSO repeated Google login", f.googleCalls)
	}
	decision, e := appA.Check(ctx, first)
	if e != nil || !decision.Identity.Admin || decision.Identity.Subject != second.Identity.Subject {
		t.Fatal("identity/admission mismatch", e)
	}
	if decision.ValidUntil.After(time.Now().Add(5*time.Minute)) || time.Until(decision.ValidUntil) < 4*time.Minute {
		t.Fatal("invalid admission lifetime")
	}
	if _, e = appB.Check(ctx, first); e == nil {
		t.Fatal("another app inspected a credential")
	}
	if e = appB.Logout(ctx, second, true); e == nil {
		t.Fatal("unprivileged client logged out Suite")
	}
	if e = appA.Logout(ctx, first, false); e != nil {
		t.Fatal(e)
	}
	if _, e = appA.Check(ctx, first); e == nil {
		t.Fatal("local logout did not revoke app credential")
	}
	if _, e = appB.Check(ctx, second); e != nil {
		t.Fatal("local logout affected another app", e)
	}
	first, _ = f.login(appA, "http://192.0.2.10:8095/auth/callback")
	if f.googleCalls != 1 {
		t.Fatal("local logout removed Auth SSO session")
	}
	if e = appA.Logout(ctx, first, true); e != nil {
		t.Fatal(e)
	}
	if _, e = appA.Check(ctx, first); e == nil {
		t.Fatal("Suite logout kept initiating session")
	}
	if _, e = appB.Check(ctx, second); e == nil {
		t.Fatal("Suite logout kept another app session")
	}
}
func TestPublicIngressCannotRedeemEnrollOrLogOut(t *testing.T) {
	f := newFixture(t)
	for _, path := range []string{"/oauth/token", "/oauth/introspect", "/v1/clients/test-client", "/v1/logout", "/userinfo", "/revoke", "/end_session"} {
		for _, method := range []string{"GET", "POST", "PUT"} {
			req, e := http.NewRequest(method, f.public.URL+path, strings.NewReader("{}"))
			if e != nil {
				t.Fatal(e)
			}
			resp, e := f.browser.Do(req)
			if e != nil {
				t.Fatal(e)
			}
			resp.Body.Close()
			if resp.StatusCode < 400 {
				t.Fatal("public private endpoint", method, path, resp.StatusCode)
			}
		}
	}
	req := httptest.NewRequest("PUT", "http://local/v1/clients/test-client", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	f.server.PrivateHandler().ServeHTTP(w, req)
	if w.Code != 404 {
		t.Fatal("runtime channel allows enrollment")
	}
}
func TestCallbackMismatchMissingPKCEAndCodeReplay(t *testing.T) {
	f := newFixture(t)
	callback := "https://example.test/auth/callback"
	c := f.app("test-client", callback, false)
	tx, authURL, e := c.Begin(callback, "/")
	if e != nil {
		t.Fatal(e)
	}
	u, _ := url.Parse(authURL)
	q := u.Query()
	q.Set("redirect_uri", "https://attacker.example/callback")
	u.RawQuery = q.Encode()
	resp := f.visit(u.String())
	if resp.StatusCode < 400 || resp.Header.Get("Location") != "" {
		t.Fatal("unsafe callback accepted")
	}
	u, _ = url.Parse(authURL)
	q = u.Query()
	q.Del("code_challenge")
	q.Del("code_challenge_method")
	u.RawQuery = q.Encode()
	resp = f.visit(u.String())
	if resp.StatusCode == 302 {
		target, _ := url.Parse(resp.Header.Get("Location"))
		if target.Host == "" {
			t.Fatal("missing PKCE reached login")
		}
	}
	_, query := f.login(c, callback)
	// A consumed code cannot be redeemed a second time, even with a new transaction.
	query.Set("state", tx.State)
	if _, e = c.Complete(context.Background(), callback, tx, query); e == nil {
		t.Fatal("consumed code was replayed")
	}
	req := httptest.NewRequest("PUT", "http://control/v1/clients/test-client", strings.NewReader(`{"client_secret":"`+random()+`","redirect_uris":["https://*.example.test/callback"]}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.server.AdminHandler().ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatal("wildcard callback accepted")
	}
}
func TestGoogleCallbackBrowserBindingRejectionAndReplay(t *testing.T) {
	f := newFixture(t)
	callback := "http://app.home.arpa/auth/callback"
	c := f.app("test-client", callback, false)
	_, authURL, _ := c.Begin(callback, "/")
	resp := f.visit(authURL)
	resp = f.visit(resp.Header.Get("Location"))
	googleURL, _ := url.Parse(resp.Header.Get("Location"))
	state := googleURL.Query().Get("state")
	path := "/auth/google/callback?state=" + state + "&code=disallowed"
	anonymousCopy := *f.public.Client()
	anonymous := &anonymousCopy
	anonymous.Jar = nil
	anonymous.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, e := anonymous.Get(f.public.URL + path)
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatal("unbound browser accepted")
	}
	resp = f.visit(path)
	if resp.StatusCode != 403 {
		t.Fatal("unlisted Google account accepted")
	}
	resp = f.visit(path)
	if resp.StatusCode != 400 {
		t.Fatal("Google callback replay accepted")
	}
}
func TestPersistentKeysSessionsAllowlistRemovalAndNoResurrection(t *testing.T) {
	f := newFixture(t)
	c := f.app("test-client", "http://app.home.arpa/callback", false)
	credentials, _ := f.login(c, "http://app.home.arpa/callback")
	plain, e := f.server.Provider.Crypto().Decrypt(credentials.AccessToken)
	if e != nil {
		t.Fatal(e)
	}
	id := strings.Split(plain, ":")[0]
	config := f.store.config
	keyID := f.store.key.id
	if e = f.store.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := Open(config)
	if e != nil {
		t.Fatal(e)
	}
	f.store = reopened
	if reopened.key.id != keyID {
		t.Fatal("signing key changed on restart")
	}
	restored, e := New(reopened)
	if e != nil {
		t.Fatal(e)
	}
	if p, e := restored.Provider.Crypto().Decrypt(credentials.AccessToken); e != nil || p != plain {
		t.Fatal("encryption identity changed")
	}
	if _, _, e = reopened.token(id, "test-client", false); e != nil {
		t.Fatal("session lost on restart", e)
	}
	reopened.Close()
	config.AllowedEmails = map[string]bool{"replacement@example.test": true}
	reopened, e = Open(config)
	if e != nil {
		t.Fatal(e)
	}
	f.store = reopened
	if _, _, e = reopened.token(id, "test-client", false); e == nil {
		t.Fatal("removed account still admitted")
	}
	reopened.Close()
	config.AllowedEmails = map[string]bool{"admin@example.test": true}
	reopened, e = Open(config)
	if e != nil {
		t.Fatal(e)
	}
	f.store = reopened
	if _, _, e = reopened.token(id, "test-client", false); e == nil {
		t.Fatal("old session resurrected after re-adding email")
	}
	if e = reopened.Cleanup(); e != nil {
		t.Fatal(e)
	}
}
func TestGoogleIDTokenSignatureAudienceNonceAndVerification(t *testing.T) {
	f := newFixture(t)
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: &jose.JSONWebKey{Key: key, KeyID: "google-test"}}, nil)
	if e != nil {
		t.Fatal(e)
	}
	var response atomic.Value
	response.Store("")
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/keys" {
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "google-test", Algorithm: "RS256", Use: "sig"}}})
			return
		}
		if e := r.ParseForm(); e != nil || r.Form.Get("code_verifier") == "" {
			http.Error(w, "PKCE missing", 400)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "test-google-token", "token_type": "Bearer", "expires_in": 3600, "id_token": response.Load().(string)})
	}))
	defer upstream.Close()
	f.server.httpClient = upstream.Client()
	f.server.oauth.Endpoint.TokenURL = upstream.URL + "/token"
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, upstream.Client())
	f.server.googleVerifier = googleoidc.NewVerifier("https://accounts.google.com", googleoidc.NewRemoteKeySet(ctx, upstream.URL+"/keys"), &googleoidc.Config{ClientID: f.store.config.GoogleClientID})
	transaction := googleTransaction{Nonce: random(), Verifier: oauth2.GenerateVerifier()}
	ctx = context.WithValue(ctx, googleTransactionKey{}, transaction)
	for _, test := range []struct {
		name   string
		change func(map[string]any)
		valid  bool
	}{
		{"valid", func(map[string]any) {}, true},
		{"wrong audience", func(m map[string]any) { m["aud"] = "other" }, false},
		{"wrong issuer", func(m map[string]any) { m["iss"] = "https://attacker.example" }, false},
		{"wrong nonce", func(m map[string]any) { m["nonce"] = "wrong" }, false},
		{"expired", func(m map[string]any) { m["exp"] = time.Now().Add(-time.Hour).Unix() }, false},
		{"unverified email", func(m map[string]any) { m["email_verified"] = false }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims := map[string]any{"iss": "https://accounts.google.com", "sub": "google-stable-subject", "aud": f.store.config.GoogleClientID, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": transaction.Nonce, "email": "admin@example.test", "email_verified": true}
			test.change(claims)
			b, _ := json.Marshal(claims)
			signed, e := signer.Sign(b)
			if e != nil {
				t.Fatal(e)
			}
			raw, e := signed.CompactSerialize()
			if e != nil {
				t.Fatal(e)
			}
			response.Store(raw)
			_, e = f.server.exchangeGoogle(ctx, "code", "")
			if (e == nil) != test.valid {
				t.Fatal("Google validation mismatch", e)
			}
		})
	}
}

func TestSingleUseCodesBindingAndExpiry(t *testing.T) {
	f := newFixture(t)
	callback := "http://app.home.arpa/callback"
	c := f.app("test-client", callback, false)
	for _, test := range []struct {
		name  string
		alter func(*client.Transaction, url.Values)
	}{
		{"wrong PKCE", func(tx *client.Transaction, _ url.Values) { tx.Verifier = client.GenerateSecret() }},
		{"wrong nonce", func(tx *client.Transaction, _ url.Values) { tx.Nonce = client.GenerateSecret() }},
		{"wrong state", func(_ *client.Transaction, q url.Values) { q.Set("state", client.GenerateSecret()) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx, q := f.authorize(c, callback)
			test.alter(&tx, q)
			if _, e := c.Complete(context.Background(), callback, tx, q); e == nil {
				t.Fatal("invalid binding accepted")
			}
		})
	}
	tx, q := f.authorize(c, callback)
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { _, e := c.Complete(context.Background(), callback, tx, q); results <- e }()
	}
	successes := 0
	for i := 0; i < 2; i++ {
		if <-results == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatal("concurrent code redemption successes", successes)
	}
	tx, q = f.authorize(c, callback)
	f.store.now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	if _, e := c.Complete(context.Background(), callback, tx, q); e == nil {
		t.Fatal("expired authorization code accepted")
	}
}
func TestAdministratorSocketIsExclusiveAndCannotReplaceFiles(t *testing.T) {
	directory, e := os.MkdirTemp("", "na")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(directory)
	listener, e := ListenLocal(directory, "c")
	if e != nil {
		t.Fatal(e)
	}
	if other, e := ListenLocal(directory, "c"); e == nil {
		other.Close()
		t.Fatal("duplicate instance replaced active socket")
	}
	listener.Close()
	path := filepath.Join(directory, "c")
	if e = os.WriteFile(path, []byte("preserve"), 0600); e != nil {
		t.Fatal(e)
	}
	if other, e := ListenLocal(directory, "c"); e == nil {
		other.Close()
		t.Fatal("regular file was replaced")
	}
}

func TestClientChangesCancelPendingLoginsAndRevokeTokens(t *testing.T) {
	f := newFixture(t)
	callback := "http://app.home.arpa/callback"
	c := f.app("test-client", callback, false)
	credentials, _ := f.login(c, callback)
	tx, q := f.authorize(c, callback)
	old, _ := f.store.GetClientByClientID(context.Background(), "test-client")
	// An administrative reconfiguration gets a new client revision and cancels old grants.
	c = f.app("test-client", callback, false)
	next, _ := f.store.GetClientByClientID(context.Background(), "test-client")
	if old.(*Client).Revision == next.(*Client).Revision {
		t.Fatal("changed client kept revision")
	}
	if _, e := c.Check(context.Background(), credentials); e == nil {
		t.Fatal("changed client kept old session")
	}
	if _, e := c.Complete(context.Background(), callback, tx, q); e == nil {
		t.Fatal("changed client kept pending login")
	}
	if duplicate, e := Open(f.store.config); e == nil {
		duplicate.Close()
		t.Fatal("duplicate Auth process shared private data")
	}
}
func TestSuiteLogoutDoesNotRevokeAnotherDevice(t *testing.T) {
	f := newFixture(t)
	callback := "http://app.home.arpa/callback"
	c := f.app("test-client", callback, true)
	first, _ := f.login(c, callback)
	firstJar := f.browser.Jar
	secondJar, _ := cookiejar.New(nil)
	f.browser.Jar = secondJar
	second, _ := f.login(c, callback)
	f.browser.Jar = firstJar
	if e := c.Logout(context.Background(), first, true); e != nil {
		t.Fatal(e)
	}
	if _, e := c.Check(context.Background(), first); e == nil {
		t.Fatal("original device stayed authorized")
	}
	if _, e := c.Check(context.Background(), second); e != nil {
		t.Fatal("independent device was logged out", e)
	}
}
