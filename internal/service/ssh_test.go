package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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

func TestDetectTerminalSizeFromFDsPrefersFirstWorkingDescriptor(t *testing.T) {
	getSize := func(fd int) (int, int, error) {
		switch fd {
		case 10:
			return 0, 0, errors.New("not a tty")
		case 11:
			return 160, 48, nil
		default:
			return 200, 60, nil
		}
	}

	cols, rows := detectTerminalSizeFromFDs([]int{10, 11, 12}, getSize, 120, 32)
	if cols != 160 || rows != 48 {
		t.Fatalf("expected first working size 160x48, got %dx%d", cols, rows)
	}
}

func TestDetectTerminalSizeFromFDsFallsBackWhenAllDescriptorsFail(t *testing.T) {
	getSize := func(fd int) (int, int, error) {
		return 0, 0, errors.New("not a tty")
	}

	cols, rows := detectTerminalSizeFromFDs([]int{10, 11, 12}, getSize, 120, 32)
	if cols != 120 || rows != 32 {
		t.Fatalf("expected fallback size 120x32, got %dx%d", cols, rows)
	}
}

func TestWatchTerminalResizeReportsChanges(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		mu     sync.Mutex
		sizes  = [][2]int{{120, 32}, {120, 32}, {180, 52}, {180, 52}}
		index  int
		events [][2]int
		done   = make(chan struct{})
	)

	currentSize := func() (int, int) {
		mu.Lock()
		defer mu.Unlock()
		size := sizes[index]
		if index < len(sizes)-1 {
			index++
		}
		return size[0], size[1]
	}

	go watchTerminalResize(ctx, 5*time.Millisecond, currentSize, func(cols, rows int) {
		mu.Lock()
		events = append(events, [2]int{cols, rows})
		mu.Unlock()
		close(done)
		cancel()
	})

	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timed out waiting for resize event")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 1 {
		t.Fatalf("expected 1 resize event, got %d", len(events))
	}
	if events[0] != [2]int{180, 52} {
		t.Fatalf("expected resize to 180x52, got %v", events[0])
	}
}

func TestWatchTerminalResizeIgnoresZeroSizes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		mu     sync.Mutex
		sizes  = [][2]int{{120, 32}, {0, 0}, {0, 40}, {120, 32}}
		index  int
		events int
	)

	currentSize := func() (int, int) {
		mu.Lock()
		defer mu.Unlock()
		size := sizes[index]
		if index < len(sizes)-1 {
			index++
		}
		return size[0], size[1]
	}

	go watchTerminalResize(ctx, 5*time.Millisecond, currentSize, func(cols, rows int) {
		mu.Lock()
		events++
		mu.Unlock()
	})

	time.Sleep(40 * time.Millisecond)
	cancel()
	time.Sleep(10 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if events != 0 {
		t.Fatalf("expected zero resize events, got %d", events)
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
