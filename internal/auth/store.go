package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	_ "modernc.org/sqlite"
)

type Store struct {
	dataLock   *os.File
	closeOnce  sync.Once
	closeError error
	db         *sql.DB
	mu         sync.Mutex
	config     Config
	key        signingKey
	cryptoKey  [32]byte
	now        func() time.Time
}
type material struct {
	Issuer     string
	PrivateKey []byte
	CryptoKey  []byte
	KeyID      string
}

func random() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func Open(c Config) (*Store, error) {
	if e := os.MkdirAll(c.DataDir, 0700); e != nil {
		return nil, e
	}
	if e := os.Chmod(c.DataDir, 0700); e != nil {
		return nil, e
	}
	dataLock, err := lockData(c.DataDir)
	if err != nil {
		return nil, err
	}
	initialized := false
	defer func() {
		if !initialized {
			dataLock.Close()
		}
	}()
	path := filepath.Join(c.DataDir, "auth.sqlite")
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	f.Close()
	if e = os.Chmod(path, 0600); e != nil {
		return nil, e
	}
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, config: c, now: time.Now, dataLock: dataLock}
	success := false
	defer func() {
		if !success {
			db.Close()
		}
	}()
	_, e = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
 CREATE TABLE IF NOT EXISTS records(kind TEXT NOT NULL,id TEXT NOT NULL,body BLOB NOT NULL,PRIMARY KEY(kind,id));
 CREATE TABLE IF NOT EXISTS auth_codes(code TEXT PRIMARY KEY,request_id TEXT NOT NULL UNIQUE,used INTEGER NOT NULL DEFAULT 0);
 CREATE TABLE IF NOT EXISTS root_sessions(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,expires INTEGER NOT NULL,auth_time INTEGER NOT NULL,revoked INTEGER NOT NULL DEFAULT 0);
 CREATE TABLE IF NOT EXISTS access_tokens(id TEXT PRIMARY KEY,client_id TEXT NOT NULL,user_id TEXT NOT NULL,session_id TEXT NOT NULL,expires INTEGER NOT NULL,revoked INTEGER NOT NULL DEFAULT 0,scopes BLOB NOT NULL);
 CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,google_sub TEXT NOT NULL UNIQUE,email TEXT NOT NULL,name TEXT NOT NULL);`)
	if e != nil {
		return nil, e
	}
	var m material
	e = s.get("system", "material", &m)
	if errors.Is(e, sql.ErrNoRows) {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return nil, e
		}
		der, e := x509.MarshalECPrivateKey(key)
		if e != nil {
			return nil, e
		}
		b := make([]byte, 32)
		if _, e = rand.Read(b); e != nil {
			return nil, e
		}
		m = material{c.PublicURL, der, b, random()}
		if e = s.put("system", "material", m); e != nil {
			return nil, e
		}
	} else if e != nil {
		return nil, e
	}
	if m.Issuer != c.PublicURL {
		return nil, errors.New("NOX_AUTH_PUBLIC_URL differs from the persisted issuer; restore the configured URL instead of silently changing identities")
	}
	key, e := x509.ParseECPrivateKey(m.PrivateKey)
	if e != nil || len(m.CryptoKey) != 32 {
		return nil, errors.New("invalid persisted Auth key material")
	}
	s.key = signingKey{key, m.KeyID}
	copy(s.cryptoKey[:], m.CryptoKey)
	// Sweep on every applied configuration, even if an absent account returns in a later update.
	rows, e := db.Query(`SELECT id,email FROM users`)
	if e != nil {
		return nil, e
	}
	var removed []string
	for rows.Next() {
		var id, email string
		if e = rows.Scan(&id, &email); e != nil {
			rows.Close()
			return nil, e
		}
		if !c.AllowedEmails[email] {
			removed = append(removed, id)
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	for _, id := range removed {
		if _, e = db.Exec(`UPDATE root_sessions SET revoked=1 WHERE user_id=?`, id); e != nil {
			return nil, e
		}
	}
	success = true
	initialized = true
	return s, nil
}
func (s *Store) Close() error {
	s.closeOnce.Do(func() { s.closeError = s.db.Close(); _ = s.dataLock.Close() })
	return s.closeError
}
func (s *Store) get(kind, id string, v any) error {
	var b []byte
	if e := s.db.QueryRow(`SELECT body FROM records WHERE kind=? AND id=?`, kind, id).Scan(&b); e != nil {
		return e
	}
	return json.Unmarshal(b, v)
}
func (s *Store) put(kind, id string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	_, e = s.db.Exec(`INSERT INTO records VALUES(?,?,?) ON CONFLICT(kind,id) DO UPDATE SET body=excluded.body`, kind, id, b)
	return e
}
func (s *Store) remove(kind, id string) error {
	_, e := s.db.Exec(`DELETE FROM records WHERE kind=? AND id=?`, kind, id)
	return e
}
func (s *Store) Health(ctx context.Context) error { return s.db.PingContext(ctx) }
func (s *Store) GetClientByClientID(_ context.Context, id string) (op.Client, error) {
	var c Client
	e := s.get("client", id, &c)
	return &c, e
}
func (s *Store) AuthorizeClientIDSecret(ctx context.Context, id, secret string) error {
	c, e := s.GetClientByClientID(ctx, id)
	if e != nil {
		return ErrDenied
	}
	if subtle.ConstantTimeCompare([]byte(c.(*Client).SecretHash), []byte(hash(secret))) != 1 {
		return ErrDenied
	}
	return nil
}
func (s *Store) user(id string) (User, error) {
	var u User
	e := s.db.QueryRow(`SELECT id,google_sub,email,name FROM users WHERE id=?`, id).Scan(&u.ID, &u.GoogleSubject, &u.Email, &u.Name)
	if e != nil || !s.config.AllowedEmails[u.Email] {
		return u, ErrDenied
	}
	return u, nil
}
func (s *Store) login(sub, email, name string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sub == "" || !s.config.AllowedEmails[email] {
		return User{}, ErrDenied
	}
	id := random()
	_, e := s.db.Exec(`INSERT INTO users VALUES(?,?,?,?) ON CONFLICT(google_sub) DO UPDATE SET email=excluded.email,name=excluded.name`, id, sub, email, name)
	if e != nil {
		return User{}, e
	}
	var u User
	e = s.db.QueryRow(`SELECT id,google_sub,email,name FROM users WHERE google_sub=?`, sub).Scan(&u.ID, &u.GoogleSubject, &u.Email, &u.Name)
	return u, e
}
func (s *Store) newSession(u User) (string, Session, error) {
	raw := random()
	now := s.now()
	session := Session{ID: hash(raw), UserID: u.ID, Expires: now.Add(SessionLifetime), AuthTime: now}
	_, e := s.db.Exec(`INSERT INTO root_sessions(id,user_id,expires,auth_time) VALUES(?,?,?,?)`, session.ID, u.ID, session.Expires.Unix(), now.Unix())
	return raw, session, e
}
func (s *Store) session(id string) (Session, error) {
	var r Session
	var expires, auth int64
	e := s.db.QueryRow(`SELECT id,user_id,expires,auth_time,revoked FROM root_sessions WHERE id=?`, id).Scan(&r.ID, &r.UserID, &expires, &auth, &r.Revoked)
	r.Expires = time.Unix(expires, 0)
	r.AuthTime = time.Unix(auth, 0)
	if e != nil || r.Revoked || !s.now().Before(r.Expires) {
		return r, ErrDenied
	}
	if _, e = s.user(r.UserID); e != nil {
		return r, ErrDenied
	}
	return r, nil
}
func (s *Store) token(id, client string, touch bool) (Token, Session, error) {
	var t Token
	var expires int64
	var scopes []byte
	e := s.db.QueryRow(`SELECT id,client_id,user_id,session_id,expires,revoked,scopes FROM access_tokens WHERE id=?`, id).Scan(&t.ID, &t.ClientID, &t.UserID, &t.SessionID, &expires, &t.Revoked, &scopes)
	t.Expires = time.Unix(expires, 0)
	if e != nil || t.Revoked || (client != "" && client != t.ClientID) || !s.now().Before(t.Expires) {
		return t, Session{}, ErrDenied
	}
	r, e := s.session(t.SessionID)
	if e != nil || r.UserID != t.UserID {
		return t, r, ErrDenied
	}
	if _, e = s.GetClientByClientID(context.Background(), t.ClientID); e != nil {
		return t, r, ErrDenied
	}
	if e = json.Unmarshal(scopes, &t.Scopes); e != nil {
		return t, r, e
	}
	if touch {
		t.Expires = s.now().Add(SessionLifetime)
		r.Expires = t.Expires
		if _, e = s.db.Exec(`UPDATE root_sessions SET expires=? WHERE id=? AND revoked=0`, r.Expires.Unix(), r.ID); e != nil {
			return t, r, e
		}
		if _, e = s.db.Exec(`UPDATE access_tokens SET expires=? WHERE id=? AND revoked=0`, t.Expires.Unix(), t.ID); e != nil {
			return t, r, e
		}
	}
	return t, r, nil
}
func (s *Store) revokeSession(id string) error {
	_, e := s.db.Exec(`UPDATE root_sessions SET revoked=1 WHERE id=?`, id)
	return e
}
func (s *Store) CreateAuthRequest(_ context.Context, a *oidc.AuthRequest, _ string) (op.AuthRequest, error) {
	if a.ResponseType != oidc.ResponseTypeCode || a.CodeChallengeMethod != oidc.CodeChallengeMethodS256 || len(a.CodeChallenge) != 43 || len(a.State) < 22 || len(a.State) > 1024 || len(a.Nonce) < 22 || len(a.Nonce) > 1024 {
		return nil, oidc.ErrInvalidRequest().WithDescription("NoX Login requires code flow, PKCE S256, state and nonce")
	}
	hasOpenID := false
	for _, scope := range a.Scopes {
		switch scope {
		case "openid":
			hasOpenID = true
		case "email", "profile":
		default:
			return nil, oidc.ErrInvalidScope()
		}
	}
	challenge, e := base64.RawURLEncoding.DecodeString(a.CodeChallenge)
	if !hasOpenID || e != nil || len(challenge) != 32 || (a.ResponseMode != "" && a.ResponseMode != oidc.ResponseModeQuery) {
		return nil, oidc.ErrInvalidRequest()
	}
	var count int
	if e = s.db.QueryRow(`SELECT count(*) FROM records WHERE kind='request'`).Scan(&count); e != nil {
		return nil, e
	}
	if count >= 10000 {
		if e = s.Cleanup(); e != nil {
			return nil, e
		}
		if e = s.db.QueryRow(`SELECT count(*) FROM records WHERE kind='request'`).Scan(&count); e != nil {
			return nil, e
		}
		if count >= 10000 {
			return nil, oidc.ErrServerError().WithDescription("Too many pending login transactions")
		}
	}
	registered, e := s.GetClientByClientID(context.Background(), a.ClientID)
	if e != nil {
		return nil, ErrDenied
	}
	r := &Request{ID: random(), Created: s.now(), Request: *a, ClientRevision: registered.(*Client).Revision}
	return r, s.put("request", r.ID, r)
}
func (s *Store) AuthRequestByID(_ context.Context, id string) (op.AuthRequest, error) {
	var r Request
	if e := s.get("request", id, &r); e != nil {
		return nil, ErrDenied
	}
	if !s.now().Before(r.Created.Add(TransactionLifetime)) {
		return nil, ErrDenied
	}
	return &r, nil
}
func (s *Store) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	var id string
	e := s.db.QueryRow(`UPDATE auth_codes SET used=1 WHERE code=? AND used=0 RETURNING request_id`, hash(code)).Scan(&id)
	if e != nil {
		return nil, ErrDenied
	}
	return s.AuthRequestByID(ctx, id)
}
func (s *Store) SaveAuthCode(_ context.Context, id, code string) error {
	_, e := s.db.Exec(`INSERT INTO auth_codes(code,request_id) VALUES(?,?)`, hash(code), id)
	return e
}
func (s *Store) DeleteAuthRequest(_ context.Context, id string) error {
	_, e := s.db.Exec(`DELETE FROM auth_codes WHERE request_id=?`, id)
	if e != nil {
		return e
	}
	return s.remove("request", id)
}
func (s *Store) CreateAccessToken(_ context.Context, request op.TokenRequest) (string, time.Time, error) {
	r, ok := request.(*Request)
	if !ok || !r.Complete {
		return "", time.Time{}, ErrDenied
	}
	registered, e := s.GetClientByClientID(context.Background(), r.GetClientID())
	if e != nil || registered.(*Client).Revision != r.ClientRevision {
		return "", time.Time{}, ErrDenied
	}
	session, e := s.session(r.SessionID)
	if e != nil || session.UserID != r.UserID {
		return "", time.Time{}, ErrDenied
	}
	id := random()
	expires := s.now().Add(SessionLifetime)
	scopes, e := json.Marshal(r.GetScopes())
	if e != nil {
		return "", time.Time{}, e
	}
	_, e = s.db.Exec(`INSERT INTO access_tokens(id,client_id,user_id,session_id,expires,scopes) VALUES(?,?,?,?,?,?)`, id, r.GetClientID(), r.UserID, r.SessionID, expires.Unix(), scopes)
	return id, expires, e
}
func (s *Store) CreateAccessAndRefreshTokens(context.Context, op.TokenRequest, string) (string, string, time.Time, error) {
	return "", "", time.Time{}, ErrDenied
}
func (s *Store) TokenRequestByRefreshToken(context.Context, string) (op.RefreshTokenRequest, error) {
	return nil, op.ErrInvalidRefreshToken
}
func (s *Store) TerminateSession(context.Context, string, string) error { return ErrDenied }
func (s *Store) RevokeToken(_ context.Context, id, subject, client string) *oidc.Error {
	if _, _, e := s.token(id, client, false); e != nil {
		return nil
	}
	if _, e := s.db.Exec(`UPDATE access_tokens SET revoked=1 WHERE id=? AND user_id=?`, id, subject); e != nil {
		return oidc.ErrServerError()
	}
	return nil
}
func (s *Store) GetRefreshTokenInfo(context.Context, string, string) (string, string, error) {
	return "", "", op.ErrInvalidRefreshToken
}
func (s *Store) SigningKey(context.Context) (op.SigningKey, error) { return s.key, nil }
func (s *Store) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.ES256}, nil
}
func (s *Store) KeySet(context.Context) ([]op.Key, error) { return []op.Key{publicKey{s.key}}, nil }
func (s *Store) SetUserinfoFromScopes(context.Context, *oidc.UserInfo, string, string, []string) error {
	return nil
}
func (s *Store) fill(info *oidc.UserInfo, id string) error {
	u, e := s.user(id)
	if e != nil {
		return e
	}
	info.Subject = u.ID
	info.Email = u.Email
	info.EmailVerified = oidc.Bool(true)
	info.Name = u.Name
	info.AppendClaims("nox_admin", true)
	info.AppendClaims("google_sub", u.GoogleSubject)
	info.AppendClaims("google_iss", "https://accounts.google.com")
	return nil
}
func (s *Store) SetUserinfoFromRequest(_ context.Context, info *oidc.UserInfo, request op.IDTokenRequest, _ []string) error {
	return s.fill(info, request.GetSubject())
}
func (s *Store) SetUserinfoFromToken(_ context.Context, info *oidc.UserInfo, id, subject, origin string) error {
	t, _, e := s.token(id, "", false)
	if e != nil || t.UserID != subject || origin != "" {
		return ErrDenied
	}
	return s.fill(info, subject)
}
func (s *Store) SetIntrospectionFromToken(_ context.Context, info *oidc.IntrospectionResponse, id, subject, client string) error {
	t, _, e := s.token(id, client, true)
	if e != nil || t.UserID != subject {
		return ErrDenied
	}
	u := new(oidc.UserInfo)
	if e = s.fill(u, subject); e != nil {
		return e
	}
	info.SetUserInfo(u)
	info.Expiration = oidc.FromTime(t.Expires)
	info.ClientID = client
	info.Scope = t.Scopes
	return nil
}
func (s *Store) GetPrivateClaimsFromScopes(context.Context, string, string, []string) (map[string]any, error) {
	return nil, nil
}
func (s *Store) GetKeyByIDAndClientID(context.Context, string, string) (*jose.JSONWebKey, error) {
	return nil, ErrDenied
}
func (s *Store) ValidateJWTProfileScopes(context.Context, string, []string) ([]string, error) {
	return nil, ErrDenied
}
func (s *Store) Cleanup() error {
	// Expired login transactions/codes and credentials do not accumulate indefinitely.
	now := s.now().Unix()
	_, e := s.db.Exec(`DELETE FROM records WHERE kind IN ('request','google') AND json_extract(body,'$.Created') < ?`, s.now().Add(-TransactionLifetime).Format(time.RFC3339Nano))
	if e != nil {
		return fmt.Errorf("cleanup transactions: %w", e)
	}
	_, e = s.db.Exec(`DELETE FROM auth_codes WHERE request_id NOT IN (SELECT id FROM records WHERE kind='request'); DELETE FROM access_tokens WHERE expires < ?; DELETE FROM root_sessions WHERE expires < ?`, now, now)
	return e
}

func (s *Store) invalidateClient(id string) error {
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec(`UPDATE access_tokens SET revoked=1 WHERE client_id=?`, id); e != nil {
		return e
	}
	if _, e = tx.Exec(`DELETE FROM records WHERE kind='request' AND json_extract(body,'$.Request.client_id')=?`, id); e != nil {
		return e
	}
	if _, e = tx.Exec(`DELETE FROM auth_codes WHERE request_id NOT IN(SELECT id FROM records WHERE kind='request')`); e != nil {
		return e
	}
	return tx.Commit()
}
