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

func TestFindReferencesIncludesHostProfileAndIdentityRelations(t *testing.T) {
	catalog, cleanup := newTestCatalog(t)
	defer cleanup()

	group := &domain.Group{Name: "ops"}
	if err := catalog.SaveGroup(context.Background(), group); err != nil {
		t.Fatalf("SaveGroup failed: %v", err)
	}
	key := &domain.Key{
		Name:          "deploy",
		Kind:          domain.KeyKindPrivateKey,
		PrivateKeyPEM: testPrivateKeyPEM,
	}
	if err := catalog.SaveKey(context.Background(), key); err != nil {
		t.Fatalf("SaveKey failed: %v", err)
	}
	identity := &domain.Identity{
		Name:     "ops",
		Username: "root",
		Methods:  []domain.AuthMethod{{Type: domain.AuthMethodKey, KeyID: key.ID}},
	}
	if err := catalog.SaveIdentity(context.Background(), identity); err != nil {
		t.Fatalf("SaveIdentity failed: %v", err)
	}
	profile := &domain.Profile{
		Name:        "default",
		IdentityRef: &identity.ID,
	}
	if err := catalog.SaveProfile(context.Background(), profile); err != nil {
		t.Fatalf("SaveProfile failed: %v", err)
	}
	host := &domain.Host{
		Title:       "prod",
		Hostname:    "prod.example.com",
		GroupIDs:    []string{group.ID},
		ProfileIDs:  []string{profile.ID},
		IdentityRef: &identity.ID,
		KeyRef:      &key.ID,
	}
	if err := catalog.SaveHost(context.Background(), host); err != nil {
		t.Fatalf("SaveHost failed: %v", err)
	}

	groupRefs, err := catalog.FindReferences(context.Background(), group.ID)
	if err != nil {
		t.Fatalf("FindReferences(group) failed: %v", err)
	}
	if len(groupRefs) != 1 || groupRefs[0].Kind != domain.KindHost || groupRefs[0].Field != "group_ids" {
		t.Fatalf("unexpected group refs: %#v", groupRefs)
	}

	keyRefs, err := catalog.FindReferences(context.Background(), key.ID)
	if err != nil {
		t.Fatalf("FindReferences(key) failed: %v", err)
	}
	if len(keyRefs) != 2 {
		t.Fatalf("expected 2 key references, got %#v", keyRefs)
	}
	gotFields := []string{keyRefs[0].Field, keyRefs[1].Field}
	wantFields := []string{"key_ref", "methods.key_id"}
	if gotFields[0] != wantFields[0] || gotFields[1] != wantFields[1] {
		t.Fatalf("unexpected key ref fields %v", gotFields)
	}
}

const testPrivateKeyPEM = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEAwkwZ/Cfi+yF25vA5xXLN2FyaGWXQAgMUeTApSK5bii2iG3Z2fL9+
WBGn+pAODJlEQSQwPU5+rYwjnU+1Xod4qu6rnXZBwl3qHGFxu1j7dY4ENke5bq+t0qZIk0
c6iQqH2uQrjz3G9Gat/XgMu2X0mP8cPQ0koWd7r7eYfvfPnR4AAAIIAvr0i0L69ItCAAAA
Adzc2gtcnNhAAAAAwEAAQAAAIEAwkwZ/Cfi+yF25vA5xXLN2FyaGWXQAgMUeTApSK5bii2
iG3Z2fL9+WBGn+pAODJlEQSQwPU5+rYwjnU+1Xod4qu6rnXZBwl3qHGFxu1j7dY4ENke5bq
+t0qZIk0c6iQqH2uQrjz3G9Gat/XgMu2X0mP8cPQ0koWd7r7eYfvfPnR4AAAADAQABAAAAg
F6rV0QhW+uMjMNi+5D+7NQkl1uYk+iXahX4q2wI+3P4lPWKeFrRZ8QF4c9HgDqh0SxT2W1p
gI9e2Q/q6kcxx20yk8xtT4v7VRvE1K9VGVSmq6K4DCLfXo2FAZy2gVB30I4JeEw+VfzR8r7
9vpl4HJpXzM1r9KUUWZl+1GrUQAAAEEA8us2EnW53Q1kC4yAYqf4W8QXg3fO1x9g6+oQ+4w
XyA9Y6K84G3efk6vJ85W6TGz3FpqP0mX0aZ+U9r8OM6QAAAEEAzZ/Su2f0sBHVwP2Q3l+S+
YxgqW7jQkWw9sKQ3Q7B8b9aLwWz4z4k6M4EPl2V4ElVkzQh16ObxMZkBgB2ZgAAAEEA0vln
wwh4ovN+PJ0jS7IY6K4B2m4k4XoZcH7hOQ4p4y5YdxTX8nqD8vL7h4tWv1sm/9a0t8uR1J1D
S0qA+1oQAAAANuZXJtaXVzLXRlc3QBAg==
-----END OPENSSH PRIVATE KEY-----`

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
