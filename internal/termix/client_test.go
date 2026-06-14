package termix

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNormalizeBaseURL(t *testing.T) {
	got, err := NormalizeBaseURL("https://termix.example/base/?ignored=true#fragment")
	if err != nil {
		t.Fatalf("NormalizeBaseURL returned error: %v", err)
	}
	if got != "https://termix.example/base" {
		t.Fatalf("unexpected normalized URL %q", got)
	}
}

func TestCurrentUserSendsBearerToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/users/me" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tmx_secret" {
			t.Fatalf("unexpected Authorization header %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"userId":"u1","username":"nermius","data_unlocked":true}`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, Options{Token: "tmx_secret"})
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	user, err := client.CurrentUser(context.Background())
	if err != nil {
		t.Fatalf("CurrentUser returned error: %v", err)
	}
	if user.UserID != "u1" || user.Username != "nermius" || !user.DataUnlocked {
		t.Fatalf("unexpected user: %#v", user)
	}
}
