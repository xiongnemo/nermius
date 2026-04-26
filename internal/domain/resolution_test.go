package domain

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestResolveHostPrecedenceAndForwardMerging(t *testing.T) {
	port2200 := 2200
	usernameBob := "bob"
	usernameCarol := "carol"
	identityRef := "identity-1"
	hostKeyRef := "key-1"

	resolved, err := ResolveHost(ResolveInputs{
		Host: Host{
			ID:               "host-1",
			Title:            "prod",
			Hostname:         "prod.example.com",
			Port:             &port2200,
			Username:         &usernameCarol,
			IdentityRef:      &identityRef,
			KeyRef:           &hostKeyRef,
			PasswordSecretID: "host-password",
			ForwardIDs:       []string{"f-host"},
		},
		Profiles: []Profile{
			{
				ID:         "profile-1",
				Name:       "shared",
				Username:   &usernameBob,
				ForwardIDs: []string{"f-profile"},
				KnownHosts: &KnownHostsConfig{Policy: KnownHostsAcceptNew},
			},
		},
		Identity: &Identity{
			ID:       "identity-1",
			Name:     "primary",
			Username: "alice",
			Methods:  []AuthMethod{{Type: AuthMethodPassword, PasswordSecretID: "secret-1"}},
		},
		Forwards: map[string]Forward{
			"f-profile": {ID: "f-profile", Name: "profile-forward"},
			"f-host":    {ID: "f-host", Name: "host-forward"},
		},
	})
	if err != nil {
		t.Fatalf("ResolveHost returned unexpected error: %v", err)
	}
	if resolved.Username != "carol" {
		t.Fatalf("expected host username override, got %q", resolved.Username)
	}
	if resolved.Port != 2200 {
		t.Fatalf("expected host port override, got %d", resolved.Port)
	}
	if resolved.KnownHosts.Policy != KnownHostsAcceptNew {
		t.Fatalf("expected profile known_hosts policy, got %q", resolved.KnownHosts.Policy)
	}
	if resolved.KnownHosts.Backend != KnownHostsBackendVaultFile {
		t.Fatalf("expected default known_hosts backend, got %q", resolved.KnownHosts.Backend)
	}
	if len(resolved.AuthMethods) != 3 {
		t.Fatalf("expected 3 auth methods, got %d", len(resolved.AuthMethods))
	}
	if resolved.AuthMethods[0].Type != AuthMethodKey || resolved.AuthMethods[0].KeyID != "key-1" {
		t.Fatalf("expected host key override first, got %+v", resolved.AuthMethods[0])
	}
	if resolved.AuthMethods[1].Type != AuthMethodPassword || resolved.AuthMethods[1].PasswordSecretID != "host-password" {
		t.Fatalf("expected host password override second, got %+v", resolved.AuthMethods[1])
	}
	if resolved.AuthMethods[2].Type != AuthMethodPassword || resolved.AuthMethods[2].PasswordSecretID != "secret-1" {
		t.Fatalf("expected identity auth last, got %+v", resolved.AuthMethods[2])
	}
	if len(resolved.Forwards) != 2 {
		t.Fatalf("expected merged forwards, got %d", len(resolved.Forwards))
	}
	if resolved.Forwards[0].ID != "f-profile" || resolved.Forwards[1].ID != "f-host" {
		t.Fatalf("unexpected forward order: %+v", resolved.Forwards)
	}
}

func TestForwardHostRefJSONRoundTrip(t *testing.T) {
	forward := Forward{
		ID:         "forward-1",
		Name:       "db",
		HostRef:    "host-1",
		Type:       ForwardLocal,
		ListenHost: "127.0.0.1",
		ListenPort: 15432,
		TargetHost: "db.internal",
		TargetPort: 5432,
		Enabled:    true,
	}
	data, err := json.Marshal(forward)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if !strings.Contains(string(data), `"host_ref":"host-1"`) {
		t.Fatalf("expected host_ref in JSON: %s", data)
	}
	var decoded Forward
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if decoded.HostRef != "host-1" {
		t.Fatalf("host_ref roundtrip = %q", decoded.HostRef)
	}
}

func TestResolveHostIdentityUsernameOverridesProfileUsername(t *testing.T) {
	usernameBob := "bob"

	resolved, err := ResolveHost(ResolveInputs{
		Host: Host{
			ID:       "host-identity-wins",
			Hostname: "prod.example.com",
		},
		Profiles: []Profile{
			{
				ID:       "profile-1",
				Name:     "shared",
				Username: &usernameBob,
			},
		},
		Identity: &Identity{
			ID:       "identity-1",
			Name:     "primary",
			Username: "alice",
			Methods:  []AuthMethod{{Type: AuthMethodAgent}},
		},
	})
	if err != nil {
		t.Fatalf("ResolveHost returned unexpected error: %v", err)
	}
	if resolved.Username != "alice" {
		t.Fatalf("expected identity username override, got %q", resolved.Username)
	}
}

func TestResolveHostDefaultsKnownHostsBackend(t *testing.T) {
	resolved, err := ResolveHost(ResolveInputs{
		Host: Host{
			ID:       "host-3",
			Hostname: "example.com",
		},
		Identity: &Identity{
			ID:       "identity-2",
			Name:     "default",
			Username: "alice",
			Methods:  []AuthMethod{{Type: AuthMethodAgent}},
		},
	})
	if err != nil {
		t.Fatalf("ResolveHost returned unexpected error: %v", err)
	}
	if resolved.KnownHosts.Backend != KnownHostsBackendVaultFile {
		t.Fatalf("expected default vault+file backend, got %q", resolved.KnownHosts.Backend)
	}
}

func TestResolveHostReportsMissingFields(t *testing.T) {
	_, err := ResolveHost(ResolveInputs{
		Host: Host{
			ID:       "host-2",
			Hostname: "",
		},
	})
	if !errors.Is(err, ErrHostNotConnectable) {
		t.Fatalf("expected ErrHostNotConnectable, got %v", err)
	}
}
