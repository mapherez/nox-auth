package client

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestCacheExpiryCannotExtendDuringOutageOrDenial(t *testing.T) {
	calls := 0
	body := `{"active":true,"client_id":"test-client","exp":4102444800,"sub":"subject","email":"test@example.test","email_verified":true,"nox_admin":true}`
	status := 200
	c := &Client{config: Config{Issuer: "https://auth.example.test", ClientID: "test-client", ClientSecret: GenerateSecret()}, http: &http.Client{Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
	})}}
	s := NewSession(Credentials{AccessToken: "opaque", Identity: Identity{Subject: "subject"}})
	first, e := s.Authenticate(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Authenticate(context.Background(), c); e != nil || calls != 1 {
		t.Fatal("positive admission was not reused")
	}
	if first.ValidUntil.After(time.Now().Add(5 * time.Minute)) {
		t.Fatal("cache exceeds agreed bound")
	}
	s.decision.ValidUntil = time.Now().Add(-time.Second)
	status = 503
	if _, e = s.Authenticate(context.Background(), c); e == nil {
		t.Fatal("expired admission extended during outage")
	}
	status = 200
	body = `{"active":false}`
	if _, e = s.Authenticate(context.Background(), c); e == nil {
		t.Fatal("denied account kept access")
	}
	if _, e = s.Authenticate(context.Background(), c); e == nil || calls != 3 {
		t.Fatal("denied session was resurrected or revalidated")
	}
}
func TestUnsafeReturnDestinations(t *testing.T) {
	for _, path := range []string{"https://attacker.example/", "//attacker.example/", "/\\attacker.example/", "/%2f%2fattacker.example/", "/%5cattacker.example/", "/\r\nLocation: x"} {
		if SafeReturnPath(path) {
			t.Fatal("unsafe return accepted", path)
		}
	}
	if !SafeReturnPath("/projects?view=active") {
		t.Fatal("valid return rejected")
	}
}
