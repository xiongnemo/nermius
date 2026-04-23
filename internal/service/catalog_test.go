package service

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/nermius/nermius/internal/config"
	"github.com/nermius/nermius/internal/domain"
)

func TestResolveDocumentSupportsNameAndShortID(t *testing.T) {
	catalog, cleanup := newTestCatalog(t)
	defer cleanup()

	host := &domain.Host{
		Title:    "prod",
		Hostname: "prod.example.com",
	}
	if err := catalog.SaveHost(context.Background(), host); err != nil {
		t.Fatalf("SaveHost failed: %v", err)
	}

	byName, err := catalog.ResolveDocument(context.Background(), domain.KindHost, "prod")
	if err != nil {
		t.Fatalf("ResolveDocument by name failed: %v", err)
	}
	if byName.ID != host.ID {
		t.Fatalf("expected host ID %s, got %s", host.ID, byName.ID)
	}

	shortID := host.ID[:8]
	byShortID, err := catalog.ResolveDocument(context.Background(), domain.KindHost, shortID)
	if err != nil {
		t.Fatalf("ResolveDocument by short ID failed: %v", err)
	}
	if byShortID.ID != host.ID {
		t.Fatalf("expected host ID %s, got %s", host.ID, byShortID.ID)
	}
}

func TestSaveEntityRejectsDuplicateLabelWithinKind(t *testing.T) {
	catalog, cleanup := newTestCatalog(t)
	defer cleanup()

	first := &domain.Group{Name: "prod"}
	if err := catalog.SaveGroup(context.Background(), first); err != nil {
		t.Fatalf("SaveGroup failed: %v", err)
	}
	second := &domain.Group{Name: "prod"}
	if err := catalog.SaveGroup(context.Background(), second); err == nil {
		t.Fatal("expected duplicate group label error")
	}
}

func TestResolveDocumentFailsOnAmbiguousShortID(t *testing.T) {
	catalog, cleanup := newTestCatalog(t)
	defer cleanup()

	for _, name := range []string{"alpha", "beta"} {
		group := &domain.Group{ID: "deadbeef-" + name, Name: name}
		if err := catalog.SaveGroup(context.Background(), group); err != nil {
			t.Fatalf("SaveGroup failed: %v", err)
		}
	}

	_, err := catalog.ResolveDocument(context.Background(), domain.KindGroup, "deadbeef")
	if !errors.Is(err, ErrAmbiguousReference) {
		t.Fatalf("expected ErrAmbiguousReference, got %v", err)
	}
}

func TestSaveHostNormalizesDirectPassword(t *testing.T) {
	catalog, cleanup := newTestCatalog(t)
	defer cleanup()

	host := &domain.Host{
		Title:    "prod",
		Hostname: "prod.example.com",
		Password: "super-secret",
	}
	if err := catalog.SaveHost(context.Background(), host); err != nil {
		t.Fatalf("SaveHost failed: %v", err)
	}
	if host.Password != "" {
		t.Fatal("expected host password to be cleared after save")
	}
	if host.PasswordSecretID == "" {
		t.Fatal("expected password_secret_id to be populated")
	}

	stored, err := catalog.GetHost(context.Background(), host.ID)
	if err != nil {
		t.Fatalf("GetHost failed: %v", err)
	}
	if stored.Password != "" {
		t.Fatal("expected persisted host to omit plaintext password")
	}
	if stored.PasswordSecretID == "" {
		t.Fatal("expected persisted host to retain password_secret_id")
	}

	raw, err := catalog.OpenSecret(context.Background(), stored.PasswordSecretID)
	if err != nil {
		t.Fatalf("OpenSecret failed: %v", err)
	}
	if string(raw) != "super-secret" {
		t.Fatalf("unexpected secret payload %q", string(raw))
	}
}

func newTestCatalog(t *testing.T) (*Catalog, func()) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.db")
	manager := NewVaultManager(mustResolveTestPaths(t, path))
	db, err := manager.Open(context.Background())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	return NewCatalog(db, []byte("01234567890123456789012345678901")), func() {
		_ = db.Close()
	}
}

func mustResolveTestPaths(t *testing.T, path string) config.Paths {
	t.Helper()
	dir := filepath.Dir(path)
	return config.Paths{
		ConfigDir:      dir,
		CacheDir:       dir,
		VaultPath:      path,
		SessionPath:    filepath.Join(dir, "session.json"),
		KnownHostsPath: filepath.Join(dir, "known_hosts"),
	}
}
