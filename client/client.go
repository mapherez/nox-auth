// Package client integrates server-side applications with NoX Login. Browser
// transaction state and application cookies remain owned by the application.
package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const RevalidationInterval = 5 * time.Minute
const BrowserRenewalInterval = 30 * 24 * time.Hour

var ErrDenied = errors.New("NoX Login session is not authorized")

type Config struct{ Issuer, ClientID, ClientSecret, SocketPath string }
type Client struct {
	config   Config
	http     *http.Client
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
}
type Transaction struct {
	State, Nonce, Verifier, ReturnPath string
	Created                            time.Time
}
type Identity struct {
	Subject       string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Admin         bool   `json:"nox_admin"`
	GoogleSubject string `json:"google_sub"`
	GoogleIssuer  string `json:"google_iss"`
}

// Credentials are server-side secrets. Persist in the app's protected session
// storage, never in a browser cookie, URL, response, localStorage or log.
type Credentials struct {
	AccessToken    string
	Identity       Identity
	ExpiresAt      time.Time
	BrowserRenewAt time.Time
}
type Decision struct {
	Identity              Identity
	ValidUntil, ExpiresAt time.Time
}

type unixTransport struct {
	host      string
	transport *http.Transport
}

func (t unixTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.Host != t.host || r.URL.User != nil {
		return nil, errors.New("NoX Auth transport refuses another issuer")
	}
	clone := r.Clone(r.Context())
	u := *r.URL
	u.Scheme = "http"
	u.Host = "nox-auth"
	clone.URL = &u
	return t.transport.RoundTrip(clone)
}
func HTTPClient(issuer, socket string) (*http.Client, error) {
	u, e := url.Parse(issuer)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(issuer, "#") || u.Fragment != "" || !filepath.IsAbs(socket) {
		return nil, errors.New("an HTTPS issuer origin and absolute local socket path are required")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socket)
	}, ResponseHeaderTimeout: 10 * time.Second, IdleConnTimeout: 60 * time.Second}
	return &http.Client{Transport: unixTransport{u.Host, transport}, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
func New(c Config) (*Client, error) {
	h, e := HTTPClient(c.Issuer, c.SocketPath)
	if e != nil {
		return nil, e
	}
	if c.ClientID == "" || len(c.ClientSecret) < 43 {
		return nil, errors.New("registered client identity and generated secret required")
	}
	ctx := oidc.ClientContext(context.Background(), h)
	return &Client{config: c, http: h, oauth: oauth2.Config{ClientID: c.ClientID, ClientSecret: c.ClientSecret, Endpoint: oauth2.Endpoint{AuthURL: c.Issuer + "/authorize", TokenURL: c.Issuer + "/oauth/token", AuthStyle: oauth2.AuthStyleInHeader}, Scopes: []string{"openid", "email", "profile"}}, verifier: oidc.NewVerifier(c.Issuer, oidc.NewRemoteKeySet(ctx, c.Issuer+"/keys"), &oidc.Config{ClientID: c.ClientID, SupportedSigningAlgs: []string{"ES256"}})}, nil
}
func random() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func SafeReturnPath(path string) bool {
	u, e := url.Parse(path)
	return e == nil && strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "//") && !strings.ContainsAny(path, "\\\r\n") && !u.IsAbs() && u.Host == "" && u.User == nil && !strings.HasPrefix(u.Path, "//") && !strings.ContainsAny(u.Path, "\\\r\n")
}
func (c *Client) Begin(callback, returnPath string) (Transaction, string, error) {
	if !SafeReturnPath(returnPath) {
		return Transaction{}, "", errors.New("return path must stay inside the application")
	}
	u, e := url.Parse(callback)
	if e != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return Transaction{}, "", errors.New("exact configured HTTP(S) callback required")
	}
	t := Transaction{random(), random(), oauth2.GenerateVerifier(), returnPath, time.Now()}
	config := c.oauth
	config.RedirectURL = callback
	return t, config.AuthCodeURL(t.State, oauth2.S256ChallengeOption(t.Verifier), oauth2.SetAuthURLParam("nonce", t.Nonce)), nil
}

// Complete consumes a transaction supplied by the app's single-use,
// browser-bound transaction store. Callers must atomically delete it there.
func (c *Client) Complete(ctx context.Context, callback string, t Transaction, query url.Values) (Credentials, error) {
	if time.Since(t.Created) < 0 || time.Since(t.Created) > 10*time.Minute || !SafeReturnPath(t.ReturnPath) || len(t.State) < 22 || subtle.ConstantTimeCompare([]byte(t.State), []byte(query.Get("state"))) != 1 || query.Get("code") == "" || query.Get("error") != "" {
		return Credentials{}, ErrDenied
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.http)
	config := c.oauth
	config.RedirectURL = callback
	token, e := config.Exchange(ctx, query.Get("code"), oauth2.VerifierOption(t.Verifier))
	if e != nil {
		return Credentials{}, ErrDenied
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		return Credentials{}, ErrDenied
	}
	id, e := c.verifier.Verify(ctx, raw)
	if e != nil || subtle.ConstantTimeCompare([]byte(id.Nonce), []byte(t.Nonce)) != 1 {
		return Credentials{}, ErrDenied
	}
	if id.AccessTokenHash != "" && id.VerifyAccessToken(token.AccessToken) != nil {
		return Credentials{}, ErrDenied
	}
	var identity Identity
	if id.Claims(&identity) != nil || identity.Subject == "" || !identity.EmailVerified || !identity.Admin || identity.GoogleSubject == "" {
		return Credentials{}, ErrDenied
	}
	return Credentials{token.AccessToken, identity, token.Expiry, time.Now().Add(BrowserRenewalInterval)}, nil
}
func (c *Client) Check(ctx context.Context, credentials Credentials) (Decision, error) {
	started := time.Now()
	values := url.Values{"token": {credentials.AccessToken}}
	r, e := http.NewRequestWithContext(ctx, http.MethodPost, c.config.Issuer+"/oauth/introspect", strings.NewReader(values.Encode()))
	if e != nil {
		return Decision{}, e
	}
	r.SetBasicAuth(url.QueryEscape(c.config.ClientID), url.QueryEscape(c.config.ClientSecret))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, e := c.http.Do(r)
	if e != nil {
		return Decision{}, e
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return Decision{}, fmt.Errorf("NoX Auth validation unavailable (status %d)", resp.StatusCode)
	}
	var result struct {
		Active     bool   `json:"active"`
		Expiration int64  `json:"exp"`
		ClientID   string `json:"client_id"`
		Identity
	}
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&result) != nil || !result.Active || result.ClientID != c.config.ClientID || result.Subject != credentials.Identity.Subject || !result.Admin || !result.EmailVerified {
		return Decision{}, ErrDenied
	}
	expiry := time.Unix(result.Expiration, 0)
	until := started.Add(RevalidationInterval)
	if expiry.Before(until) {
		until = expiry
	}
	if !time.Now().Before(until) {
		return Decision{}, ErrDenied
	}
	return Decision{result.Identity, until, expiry}, nil
}
func (c *Client) Logout(ctx context.Context, credentials Credentials, all bool) error {
	scope := "app"
	if all {
		scope = "suite"
	}
	body, _ := json.Marshal(map[string]string{"token": credentials.AccessToken, "scope": scope})
	r, e := http.NewRequestWithContext(ctx, http.MethodPost, c.config.Issuer+"/v1/logout", bytes.NewReader(body))
	if e != nil {
		return e
	}
	r.SetBasicAuth(c.config.ClientID, c.config.ClientSecret)
	r.Header.Set("Content-Type", "application/json")
	resp, e := c.http.Do(r)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 204 {
		return fmt.Errorf("NoX logout failed with status %d", resp.StatusCode)
	}
	return nil
}

// Session bounds positive validation reuse. Instantiate from the application's
// protected persistent credentials after restart; validation is then required.
type Session struct {
	mu          sync.Mutex
	credentials Credentials
	decision    Decision
	invalid     bool
}

func NewSession(credentials Credentials) *Session { return &Session{credentials: credentials} }
func (s *Session) Authenticate(ctx context.Context, c *Client) (Decision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.invalid {
		return Decision{}, ErrDenied
	}
	if time.Now().Before(s.decision.ValidUntil) {
		return s.decision, nil
	}
	decision, e := c.Check(ctx, s.credentials)
	if e != nil {
		if errors.Is(e, ErrDenied) {
			s.invalid = true
		}
		s.decision = Decision{}
		return Decision{}, e
	}
	s.decision = decision
	s.credentials.Identity = decision.Identity
	s.credentials.ExpiresAt = decision.ExpiresAt
	return decision, nil
}
func (s *Session) Snapshot() Credentials { s.mu.Lock(); defer s.mu.Unlock(); return s.credentials }
func (s *Session) Invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invalid = true
	s.decision = Decision{}
}

// Register is for authorized setup controllers that possess the separately
// mounted administrative socket. Runtime apps must not mount that volume.
func Register(ctx context.Context, socket, id string, redirects []string, secret string, suiteLogout bool) error {
	if len(secret) < 43 {
		return errors.New("generate and persist at least 32 random bytes for the client secret")
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
	body, _ := json.Marshal(map[string]any{"client_secret": secret, "redirect_uris": redirects, "suite_logout": suiteLogout})
	r, e := http.NewRequestWithContext(ctx, http.MethodPut, "http://nox-auth/v1/clients/"+url.PathEscape(id), bytes.NewReader(body))
	if e != nil {
		return e
	}
	r.Header.Set("Content-Type", "application/json")
	resp, e := client.Do(r)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("client enrollment failed with status %d", resp.StatusCode)
	}
	return nil
}

// GenerateSecret supplies the value to persist once in the application's data
// volume; never generate a fresh registration secret on every app startup.
func GenerateSecret() string { return random() }
func PKCEChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// NeedsBrowserRenewal lets the app renew the Auth cookie through the normal
// browser redirect while that cookie is still valid, without choosing Google again.
func (s *Session) NeedsBrowserRenewal() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !time.Now().Before(s.credentials.BrowserRenewAt)
}
