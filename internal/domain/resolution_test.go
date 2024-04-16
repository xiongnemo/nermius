package domain

import (
	"errors"
	"testing"
)

func TestResolveHostPrecedenceAndForwardMerging(t *testing.T) {
	port2200 := 2200
	usernameBob := "bob"
	usernameCarol := "carol"
	identityRef := "identity-1"

	resolved, err := ResolveHost(ResolveInputs{
		Host: Host{
			ID:          "host-1",
			Title:       "prod",
			Hostname:    "prod.example.com",
			Port:        &port2200,
			Username:    &usernameCarol,
			IdentityRef: &identityRef,
			ForwardIDs:  []string{"f-host"},
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
	if len(resolved.Forwards) != 2 {
		t.Fatalf("expected merged forwards, got %d", len(resolved.Forwards))
	}
	if resolved.Forwards[0].ID != "f-profile" || resolved.Forwards[1].ID != "f-host" {
		t.Fatalf("unexpected forward order: %+v", resolved.Forwards)
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
