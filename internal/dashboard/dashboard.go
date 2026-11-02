// Package dashboard serves the browser UI on authenticated loopback only.
package dashboard

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"

	resourcemap "github.com/Parallax-Web-Services/nucleus/apps/resource-map"
	"github.com/Parallax-Web-Services/nucleus/positronic"
)

func Start(ctx context.Context, address string, noOpen bool, view func() (positronic.View, error)) (string, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil || host != "127.0.0.1" {
		return "", errors.New("browser UI must bind 127.0.0.1:PORT")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return "", err
	}
	var secret [32]byte
	if _, err = rand.Read(secret[:]); err != nil {
		listener.Close()
		return "", err
	}
	token := hex.EncodeToString(secret[:])
	expectedHost := listener.Addr().String()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'")
		if r.Host != expectedHost {
			http.Error(w, "invalid host", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "read only", http.StatusMethodNotAllowed)
			return
		}
		if r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
			http.Error(w, "no request body", http.StatusBadRequest)
			return
		}
		if r.URL.Path == "/api/v1/fabric" {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			data, err := view()
			w.Header().Set("Content-Type", "application/json")
			if err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			_ = json.NewEncoder(w).Encode(data)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/")
		switch name {
		case "", "index.html":
			name = "index.html"
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		case "styles.css":
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		case "app.js":
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		default:
			http.NotFound(w, r)
			return
		}
		data, err := resourcemap.Assets.ReadFile(name)
		if err != nil {
			http.Error(w, "asset unavailable", 500)
			return
		}
		_, _ = w.Write(data)
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 16384}
	go func() { _ = server.Serve(listener) }()
	go func() {
		<-ctx.Done()
		closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(closeCtx)
	}()
	url := "http://" + expectedHost + "/#token=" + token
	fmt.Println("Resource map: " + url)
	if !noOpen {
		openBrowser(url)
	}
	return url, nil
}
func openBrowser(url string) {
	for _, name := range []string{"chromium", "chromium-browser", "google-chrome", "wslview", "xdg-open"} {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		var command *exec.Cmd
		if strings.Contains(name, "chrom") {
			command = exec.Command(path, "--app="+url)
		} else {
			command = exec.Command(path, url)
		}
		if command.Start() == nil {
			go func() { _ = command.Wait() }()
			return
		}
	}
	fmt.Println("Open the resource map URL in a Chromium-compatible browser.")
}
