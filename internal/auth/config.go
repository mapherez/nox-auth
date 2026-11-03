package auth

import (
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"os"
	"strings"
	"time"
)

const SessionLifetime = 365 * 24 * time.Hour
const RevalidationLifetime = 5 * time.Minute
const TransactionLifetime = 10 * time.Minute

type Config struct {
	PublicURL, GoogleClientID, GoogleClientSecret, ListenAddr, DataDir, SocketDir, AdminDir string
	AllowedEmails                                                                           map[string]bool
}

func LoadConfig() (Config, error) {
	c := Config{PublicURL: strings.TrimRight(os.Getenv("NOX_AUTH_PUBLIC_URL"), "/"), GoogleClientID: os.Getenv("NOX_AUTH_GOOGLE_CLIENT_ID"), GoogleClientSecret: os.Getenv("NOX_AUTH_GOOGLE_CLIENT_SECRET"), AllowedEmails: map[string]bool{}}
	c.ListenAddr = env("NOX_AUTH_LISTEN_ADDR", "127.0.0.1:8080")
	c.DataDir = env("NOX_AUTH_DATA_DIR", "/data")
	c.SocketDir = env("NOX_AUTH_SUITE_SOCKET_DIR", "/run/nox-suite")
	c.AdminDir = env("NOX_AUTH_ADMIN_SOCKET_DIR", "/run/nox-auth-admin")
	for _, value := range strings.Split(os.Getenv("NOX_AUTH_ALLOWED_EMAILS"), ",") {
		email := strings.ToLower(strings.TrimSpace(value))
		if email == "" {
			continue
		}
		parsed, err := mail.ParseAddress(email)
		if err != nil || parsed.Address != email {
			return c, fmt.Errorf("NOX_AUTH_ALLOWED_EMAILS must contain comma-separated email addresses")
		}
		c.AllowedEmails[email] = true
	}
	return c, c.Validate()
}
func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
func (c Config) Validate() error {
	u, err := url.Parse(c.PublicURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(c.PublicURL, "#") || u.Fragment != "" || u.Opaque != "" {
		return fmt.Errorf("NOX_AUTH_PUBLIC_URL must be an HTTPS origin without a path, query or credentials")
	}
	if c.GoogleClientID == "" || c.GoogleClientSecret == "" {
		return fmt.Errorf("configure NOX_AUTH_GOOGLE_CLIENT_ID and NOX_AUTH_GOOGLE_CLIENT_SECRET")
	}
	if len(c.AllowedEmails) == 0 {
		return fmt.Errorf("configure at least one email in NOX_AUTH_ALLOWED_EMAILS")
	}
	if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
		return fmt.Errorf("invalid NOX_AUTH_LISTEN_ADDR")
	}
	if c.DataDir == "" || c.SocketDir == "" || c.AdminDir == "" || c.AdminDir == c.SocketDir {
		return fmt.Errorf("data, shared socket and separate administrator socket directories are required")
	}
	return nil
}
