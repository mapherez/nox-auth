package auth

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

var ErrDenied = errors.New("authentication or authorization denied")
var clientIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)

type Client struct {
	Revision    string   `json:"revision"`
	ID          string   `json:"client_id"`
	Redirects   []string `json:"redirect_uris"`
	SecretHash  string   `json:"secret_hash"`
	SuiteLogout bool     `json:"suite_logout"`
}

func (c *Client) GetID() string                     { return c.ID }
func (c *Client) RedirectURIs() []string            { return c.Redirects }
func (c *Client) PostLogoutRedirectURIs() []string  { return nil }
func (*Client) ApplicationType() op.ApplicationType { return op.ApplicationTypeWeb }
func (*Client) AuthMethod() oidc.AuthMethod         { return oidc.AuthMethodBasic }
func (*Client) ResponseTypes() []oidc.ResponseType  { return []oidc.ResponseType{oidc.ResponseTypeCode} }
func (*Client) GrantTypes() []oidc.GrantType        { return []oidc.GrantType{oidc.GrantTypeCode} }
func (*Client) LoginURL(id string) string           { return "/login?id=" + url.QueryEscape(id) }
func (*Client) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeBearer }
func (*Client) IDTokenLifetime() time.Duration      { return RevalidationLifetime }
func (*Client) DevMode() bool                       { return false }
func (*Client) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}
func (*Client) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}
func (*Client) IsScopeAllowed(string) bool           { return false }
func (*Client) IDTokenUserinfoClaimsAssertion() bool { return true }
func (*Client) ClockSkew() time.Duration             { return 0 }

func validateClient(c *Client) error {
	if !clientIDPattern.MatchString(c.ID) || len(c.Redirects) < 1 || len(c.Redirects) > 8 || c.SecretHash == "" {
		return errors.New("client id, secret and 1–8 exact callback URLs required")
	}
	for _, raw := range c.Redirects {
		u, e := url.Parse(raw)
		if e != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") || u.Path == "" || strings.ContainsAny(raw, "\r\n\\*") {
			return errors.New("callback must be an exact HTTP(S) URL with a path, without query, fragment, credentials or wildcards")
		}
	}
	return nil
}

type User struct{ ID, GoogleSubject, Email, Name string }
type Session struct {
	ID, UserID string
	Expires    time.Time
	AuthTime   time.Time
	Revoked    bool
}
type Token struct {
	ID, ClientID, UserID, SessionID string
	Scopes                          []string
	Expires                         time.Time
	Revoked                         bool
}
type Request struct {
	ClientRevision    string
	ID                string
	Created           time.Time
	Request           oidc.AuthRequest
	UserID, SessionID string
	AuthTime          time.Time
	Complete          bool
}

func (r *Request) GetID() string          { return r.ID }
func (r *Request) GetACR() string         { return "" }
func (r *Request) GetAMR() []string       { return []string{"federated"} }
func (r *Request) GetAudience() []string  { return []string{r.Request.ClientID} }
func (r *Request) GetAuthTime() time.Time { return r.AuthTime }
func (r *Request) GetClientID() string    { return r.Request.ClientID }
func (r *Request) GetCodeChallenge() *oidc.CodeChallenge {
	return &oidc.CodeChallenge{Challenge: r.Request.CodeChallenge, Method: r.Request.CodeChallengeMethod}
}
func (r *Request) GetNonce() string                   { return r.Request.Nonce }
func (r *Request) GetRedirectURI() string             { return r.Request.RedirectURI }
func (r *Request) GetResponseType() oidc.ResponseType { return r.Request.ResponseType }
func (r *Request) GetResponseMode() oidc.ResponseMode { return r.Request.ResponseMode }
func (r *Request) GetScopes() []string                { return r.Request.Scopes }
func (r *Request) GetState() string                   { return r.Request.State }
func (r *Request) GetSubject() string                 { return r.UserID }
func (r *Request) Done() bool                         { return r.Complete }

type signingKey struct {
	key *ecdsa.PrivateKey
	id  string
}

func (k signingKey) Algorithm() jose.SignatureAlgorithm { return jose.ES256 }
func (k signingKey) Key() any                           { return k.key }
func (k signingKey) ID() string                         { return k.id }

type publicKey struct{ signingKey }

func (k publicKey) Key() any    { return &k.key.PublicKey }
func (k publicKey) Use() string { return "sig" }
func hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

var _ op.Storage = (*Store)(nil)
var _ op.CanSetUserinfoFromRequest = (*Store)(nil)

func (k signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.ES256 }
