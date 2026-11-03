package auth

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccountAdmissionIsPrivateAuthenticatedAndIndependentOfBrowserSession(t *testing.T) {
	f := newFixture(t)
	secret := random()
	if err := f.store.put("client", "credential-app", &Client{ID: "credential-app", SecretHash: hash(secret), Redirects: []string{"http://app.example.test/callback"}}); err != nil {
		t.Fatal(err)
	}
	check := func(email, subject, password string) (int, bool) {
		body, _ := json.Marshal(map[string]string{"email": email, "google_sub": subject})
		r := httptest.NewRequest("POST", "http://local/v1/admission", strings.NewReader(string(body)))
		r.Header.Set("Content-Type", "application/json")
		r.SetBasicAuth("credential-app", password)
		w := httptest.NewRecorder()
		f.server.PrivateHandler().ServeHTTP(w, r)
		var result struct {
			Allowed bool `json:"allowed"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &result)
		return w.Code, result.Allowed
	}
	if code, _ := check("admin@example.test", "", "wrong"); code != 401 {
		t.Fatal("unregistered credentials admitted", code)
	}
	if code, allowed := check("admin@example.test", "", secret); code != 200 || !allowed {
		t.Fatal("pre-existing application account needs a browser session", code)
	}
	if _, allowed := check("outside@example.test", "", secret); allowed {
		t.Fatal("non-allowed account admitted")
	}
	if _, err := f.store.login("google-subject", "admin@example.test", "Admin"); err != nil {
		t.Fatal(err)
	}
	if _, allowed := check("admin@example.test", "different-google-subject", secret); allowed {
		t.Fatal("conflicting Google identity admitted")
	}
	if _, allowed := check("admin@example.test", "google-subject", secret); !allowed {
		t.Fatal("matching verified identity refused")
	}
	// No token/root-session was supplied or created by this admission API.
	if f.googleCalls != 0 {
		t.Fatal("admission contacted Google")
	}
	for _, method := range []string{"GET", "POST"} {
		r := httptest.NewRequest(method, "https://public/v1/admission", strings.NewReader(`{"email":"admin@example.test"}`))
		r.SetBasicAuth("credential-app", secret)
		w := httptest.NewRecorder()
		f.server.PublicHandler().ServeHTTP(w, r)
		if w.Code < 400 {
			t.Fatal("admission exposed through public transport")
		}
	}
	delete(f.store.config.AllowedEmails, "admin@example.test")
	if _, allowed := check("admin@example.test", "google-subject", secret); allowed {
		t.Fatal("removed account remains admitted")
	}
}
