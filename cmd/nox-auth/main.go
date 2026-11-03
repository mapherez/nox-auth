package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/mapherez/nox-auth/internal/auth"
)

var version = "dev"

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
		switch a.Key {
		case "state", "session_state", "url", "parent":
			return slog.Attr{}
		}
		return a
	}})))
	if e := run(); e != nil {
		slog.Error("auth_stopped", "error", e.Error())
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println(version)
		return nil
	}
	if len(os.Args) == 2 && os.Args[1] == "--healthcheck" {
		dir := os.Getenv("NOX_AUTH_SUITE_SOCKET_DIR")
		if dir == "" {
			dir = "/run/nox-suite"
		}
		client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(dir, "nox-auth.sock"))
		}}}
		r, e := client.Get("http://nox-auth/healthz")
		if e != nil {
			return fmt.Errorf("healthcheck failed")
		}
		defer r.Body.Close()
		if r.StatusCode != 200 {
			return fmt.Errorf("healthcheck failed")
		}
		return nil
	}
	if len(os.Args) > 1 {
		return fmt.Errorf("usage: nox-auth [--version|--healthcheck]")
	}
	c, e := auth.LoadConfig()
	if e != nil {
		return e
	}
	store, e := auth.Open(c)
	if e != nil {
		return e
	}
	defer store.Close()
	server, e := auth.New(store)
	if e != nil {
		return e
	}
	shared, e := auth.ListenLocal(c.SocketDir, "nox-auth.sock")
	if e != nil {
		return e
	}
	defer shared.Close()
	admin, e := auth.ListenLocal(c.AdminDir, "control.sock")
	if e != nil {
		return e
	}
	defer admin.Close()
	sharedInfo, err := os.Stat(c.SocketDir)
	if err != nil {
		return err
	}
	adminInfo, err := os.Stat(c.AdminDir)
	if err != nil {
		return err
	}
	if os.SameFile(sharedInfo, adminInfo) {
		return fmt.Errorf("administrator and runtime socket volumes must be different")
	}
	tcp, e := net.Listen("tcp", c.ListenAddr)
	if e != nil {
		return e
	}
	defer tcp.Close()
	configs := []struct {
		listener net.Listener
		handler  http.Handler
	}{{tcp, server.PublicHandler()}, {shared, server.PrivateHandler()}, {admin, server.AdminHandler()}}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	failures := make(chan error, 3)
	var servers []*http.Server
	for _, entry := range configs {
		srv := &http.Server{Handler: entry.handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 25 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
		servers = append(servers, srv)
		go func() {
			if e := srv.Serve(entry.listener); e != nil && e != http.ErrServerClosed {
				failures <- e
			}
		}()
	}
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if store.Cleanup() != nil {
					slog.Warn("auth_cleanup_failed")
				}
			}
		}
	}()
	slog.Info("auth_listening", "address", c.ListenAddr, "version", version)
	select {
	case <-ctx.Done():
	case e = <-failures:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(shutdown)
	}
	return e
}
