package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/nermius/nermius/internal/domain"
)

func TestStrictKnownHostsPromptsAndPersistsUnknownKeyToFile(t *testing.T) {
	ctx := context.Background()
	pub := mustPublicKey(t)
	path := filepath.Join(t.TempDir(), "known_hosts")
	catalog, cleanup := newTestCatalog(t)
	defer cleanup()

	connector := NewConnector(catalog, path)
	resolved := domain.ResolvedConfig{
		Hostname: "example.com",
		Port:     22,
		KnownHosts: domain.KnownHostsConfig{
			Policy:  domain.KnownHostsStrict,
			Backend: domain.KnownHostsBackendFile,
		},
	}
	verifier := mustPrepareKnownHostsVerifier(t, ctx, catalog, resolved, path)
	defer verifier.Close()

	prompted := false
	callback := connector.hostKeyCallback(ctx, resolved, Prompts{
		Confirm: func(label string) (bool, error) {
			prompted = true
			if !strings.Contains(label, ssh.FingerprintSHA256(pub)) {
				t.Fatalf("prompt did not include fingerprint: %s", label)
			}
			if !strings.Contains(label, "file") {
				t.Fatalf("prompt did not include backend target: %s", label)
			}
			return true, nil
		},
	}, verifier)

	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 22}
	if err := callback("example.com:22", remote, pub); err != nil {
		t.Fatalf("callback returned error: %v", err)
	}
	if !prompted {
		t.Fatal("expected confirm prompt to be called")
	}

	verify, err := knownhosts.New(path)
	if err != nil {
		t.Fatalf("knownhosts.New failed: %v", err)
	}
	if err := verify("example.com:22", remote, pub); err != nil {
		t.Fatalf("persisted known host did not verify: %v", err)
	}
}

func TestAcceptNewKnownHostsPersistsUnknownKeyToVaultByDefault(t *testing.T) {
	ctx := context.Background()
	pub := mustPublicKey(t)
	path := filepath.Join(t.TempDir(), "known_hosts")
	catalog, cleanup := newTestCatalog(t)
	defer cleanup()

	connector := NewConnector(catalog, path)
	resolved := domain.ResolvedConfig{
		Hostname: "vault.example",
		Port:     22,
		KnownHosts: domain.KnownHostsConfig{
			Policy:  domain.KnownHostsAcceptNew,
			Backend: domain.KnownHostsBackendVaultFile,
		},
	}
	verifier := mustPrepareKnownHostsVerifier(t, ctx, catalog, resolved, path)
	defer verifier.Close()

	callback := connector.hostKeyCallback(ctx, resolved, Prompts{}, verifier)
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.14"), Port: 22}
	if err := callback("vault.example:22", remote, pub); err != nil {
		t.Fatalf("callback returned error: %v", err)
	}

	entries, err := catalog.ListKnownHosts(ctx)
	if err != nil {
		t.Fatalf("ListKnownHosts failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 vault known host entry, got %d", len(entries))
	}
	if entries[0].Algorithm != ssh.KeyAlgoED25519 {
		t.Fatalf("expected ed25519 algorithm, got %q", entries[0].Algorithm)
	}
	if entries[0].FingerprintSHA256 != ssh.FingerprintSHA256(pub) {
		t.Fatalf("unexpected fingerprint: %q", entries[0].FingerprintSHA256)
	}
}

func TestStrictKnownHostsWithoutConfirmStillFailsOnUnknownKey(t *testing.T) {
	ctx := context.Background()
	pub := mustPublicKey(t)
	path := filepath.Join(t.TempDir(), "known_hosts")
	catalog, cleanup := newTestCatalog(t)
	defer cleanup()

	connector := NewConnector(catalog, path)
	resolved := domain.ResolvedConfig{
		Hostname: "example.org",
		Port:     22,
		KnownHosts: domain.KnownHostsConfig{
			Policy:  domain.KnownHostsStrict,
			Backend: domain.KnownHostsBackendFile,
		},
	}
	verifier := mustPrepareKnownHostsVerifier(t, ctx, catalog, resolved, path)
	defer verifier.Close()

	callback := connector.hostKeyCallback(ctx, resolved, Prompts{}, verifier)

	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.11"), Port: 22}
	err := callback("example.org:22", remote, pub)
	var keyErr *knownhosts.KeyError
	if !errors.As(err, &keyErr) || len(keyErr.Want) != 0 {
		t.Fatalf("expected unknown host key error, got %v", err)
	}
}

func TestStrictKnownHostsDeclineFails(t *testing.T) {
	ctx := context.Background()
	pub := mustPublicKey(t)
	path := filepath.Join(t.TempDir(), "known_hosts")
	catalog, cleanup := newTestCatalog(t)
	defer cleanup()

	connector := NewConnector(catalog, path)
	resolved := domain.ResolvedConfig{
		Hostname: "decline.example",
		Port:     22,
		KnownHosts: domain.KnownHostsConfig{
			Policy:  domain.KnownHostsStrict,
			Backend: domain.KnownHostsBackendFile,
		},
	}
	verifier := mustPrepareKnownHostsVerifier(t, ctx, catalog, resolved, path)
	defer verifier.Close()

	callback := connector.hostKeyCallback(ctx, resolved, Prompts{
		Confirm: func(label string) (bool, error) {
			return false, nil
		},
	}, verifier)

	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.12"), Port: 22}
	err := callback("decline.example:22", remote, pub)
	if err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("expected declined host key error, got %v", err)
	}
}

func TestBuildClientConfigPrefersSavedHostKeyAlgorithms(t *testing.T) {
	ctx := context.Background()
	pub := mustPublicKey(t)
	path := filepath.Join(t.TempDir(), "known_hosts")
	catalog, cleanup := newTestCatalog(t)
	defer cleanup()

	if err := appendKnownHost(path, "example.net:22", &net.TCPAddr{IP: net.ParseIP("192.0.2.13"), Port: 22}, pub); err != nil {
		t.Fatalf("appendKnownHost failed: %v", err)
	}

	connector := NewConnector(catalog, path)
	cfg, closers, err := connector.buildClientConfig(ctx, domain.ResolvedConfig{
		Hostname: "example.net",
		Port:     22,
		Username: "nemo",
		Identity: &domain.Identity{
			Name:     "runtime",
			Username: "nemo",
			Methods: []domain.AuthMethod{
				{Type: domain.AuthMethodPassword, Password: "secret"},
			},
		},
		KnownHosts: domain.KnownHostsConfig{
			Policy:  domain.KnownHostsStrict,
			Backend: domain.KnownHostsBackendFile,
		},
	}, Prompts{})
	if err != nil {
		t.Fatalf("buildClientConfig failed: %v", err)
	}
	defer closeAll(closers)
	if len(cfg.HostKeyAlgorithms) == 0 {
		t.Fatal("expected host key algorithms to be populated")
	}
	if cfg.HostKeyAlgorithms[0] != ssh.KeyAlgoED25519 {
		t.Fatalf("expected ed25519 to be preferred, got %v", cfg.HostKeyAlgorithms)
	}
}

func TestKnownHostAddressesDedupes(t *testing.T) {
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 22}
	addresses := knownHostAddresses("192.0.2.10:22", remote)
	if len(addresses) != 1 {
		t.Fatalf("expected deduped addresses, got %v", addresses)
	}
}

func TestAppendKnownHostUsesNormalizedAddresses(t *testing.T) {
	pub := mustPublicKey(t)
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := ensureKnownHostsFile(path); err != nil {
		t.Fatalf("ensureKnownHostsFile failed: %v", err)
	}
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.13"), Port: 2222}
	if err := appendKnownHost(path, "example.net:2222", remote, pub); err != nil {
		t.Fatalf("appendKnownHost failed: %v", err)
	}
	verify, err := knownhosts.New(path)
	if err != nil {
		t.Fatalf("knownhosts.New failed: %v", err)
	}
	if err := verify("example.net:2222", remote, pub); err != nil {
		t.Fatalf("known host append did not verify: %v", err)
	}
}

func TestKnownHostPromptTargetNormalizesHostname(t *testing.T) {
	target := knownHostPromptTarget("example.net:2222")
	if target != "[example.net]:2222" {
		t.Fatalf("expected normalized hostname, got %q", target)
	}
}

func TestCommandExitErrorExitCode(t *testing.T) {
	err := &CommandExitError{Code: 17}
	if err.ExitCode() != 17 {
		t.Fatalf("expected exit code 17, got %d", err.ExitCode())
	}
	if err.Error() != "" {
		t.Fatalf("expected empty error message, got %q", err.Error())
	}
}

func mustPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey failed: %v", err)
	}
	return signer.PublicKey()
}

func mustPrepareKnownHostsVerifier(t *testing.T, ctx context.Context, catalog *Catalog, resolved domain.ResolvedConfig, path string) *knownHostsVerifier {
	t.Helper()
	verifier, err := prepareKnownHostsVerifier(ctx, catalog, resolved, path)
	if err != nil {
		t.Fatalf("prepareKnownHostsVerifier failed: %v", err)
	}
	return verifier
}
