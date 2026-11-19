package dashboard

import (
	"context"
	"encoding/json"
	"github.com/Parallax-Web-Services/nucleus/positronic"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestStandaloneDashboardAccountStatusIsOptionalAndAuthenticated(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	address, err := Start(ctx, "127.0.0.1:0", true, func() (positronic.View, error) { return positronic.View{SchemaVersion: 1}, nil })
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(address)
	endpoint := "http://" + parsed.Host + "/api/v1/account"
	response, err := http.Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatal("account metadata was not authenticated")
	}
	request, _ := http.NewRequest(http.MethodGet, endpoint, nil)
	request.Header.Set("Authorization", "Bearer "+strings.TrimPrefix(parsed.Fragment, "token="))
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result struct {
		Linked     bool `json:"linked"`
		Standalone bool `json:"standalone"`
	}
	if json.NewDecoder(response.Body).Decode(&result) != nil || result.Linked || !result.Standalone {
		t.Fatal("standalone dashboard required an account")
	}
}
