package positronic

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWorkloadHookRequiresCurrentAuthenticatedMembership(t *testing.T) {
	f := newFixture(t)
	calls := 0
	f.coordinator.SetWorkloadHandler(func(w http.ResponseWriter, r *http.Request, node string) {
		calls++
		if node != f.memberID {
			t.Error("wrong authenticated identity")
		}
		w.WriteHeader(204)
	})
	req := httptest.NewRequest("POST", "/v1/inference/worker/acquire", nil)
	rec := httptest.NewRecorder()
	f.coordinator.Handler().ServeHTTP(rec, req)
	if rec.Code != 403 || calls != 0 {
		t.Fatal("unauthenticated workload dispatched")
	}
	rec = f.request("POST", "/v1/inference/worker/acquire", nil)
	if rec.Code != 204 || calls != 1 {
		t.Fatalf("member hook %d calls=%d", rec.Code, calls)
	}
	f.mu.Lock()
	delete(f.state.Members, f.memberID)
	f.mu.Unlock()
	rec = f.request("POST", "/v1/inference/worker/acquire", nil)
	if rec.Code != 403 || calls != 1 {
		t.Fatal("revoked member dispatched")
	}
}
