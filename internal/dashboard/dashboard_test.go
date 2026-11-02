package dashboard

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Parallax-Web-Services/nucleus/positronic"
)

func TestDashboardRequiresTokenHostAndReadOnlyMethod(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	address, err := Start(ctx, "127.0.0.1:0", true, func() (positronic.View, error) { return positronic.View{SchemaVersion: 1}, nil })
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(address)
	token := strings.TrimPrefix(parsed.Fragment, "token=")
	base := "http://" + parsed.Host
	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	cases := []struct {
		method, token, host string
		status              int
	}{
		{"GET", "", "", 401}, {"GET", token, "", 200}, {"GET", token, "evil.example", 403}, {"POST", token, "", 405},
	}
	for _, test := range cases {
		request, _ := http.NewRequest(test.method, base+"/api/v1/fabric", nil)
		if test.token != "" {
			request.Header.Set("Authorization", "Bearer "+test.token)
		}
		if test.host != "" {
			request.Host = test.host
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != test.status {
			t.Fatalf("%s: got %d want %d", test.method, response.StatusCode, test.status)
		}
		if response.Header.Get("Content-Security-Policy") == "" || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("missing browser boundary headers")
		}
	}
	if _, err := Start(ctx, "0.0.0.0:0", true, func() (positronic.View, error) { return positronic.View{}, nil }); err == nil {
		t.Fatal("public UI listener accepted")
	}
}
