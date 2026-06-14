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

func TestSaveForwardRequiresTargetForLocalAndRemote(t *testing.T) {
	catalog, cleanup := newTestCatalog(t)
	defer cleanup()

	forward := &domain.Forward{
		Name:       "db",
		Type:       domain.ForwardLocal,
		ListenPort: 15432,
		Enabled:    true,
	}
	if err := catalog.SaveForward(context.Background(), forward); err == nil {
		t.Fatal("expected local forward without target to be rejected")
	}

	forward.TargetHost = "db.internal"
	forward.TargetPort = 5432
	if err := catalog.SaveForward(context.Background(), forward); err != nil {
		t.Fatalf("SaveForward with target failed: %v", err)
	}

	remote := &domain.Forward{
		Name:       "reverse-api",
		Type:       domain.ForwardRemote,
		ListenPort: 18080,
		Enabled:    true,
	}
	if err := catalog.SaveForward(context.Background(), remote); err == nil {
		t.Fatal("expected remote forward without target to be rejected")
	}

	dynamic := &domain.Forward{
		Name:       "socks",
		Type:       domain.ForwardDynamic,
		ListenPort: 1080,
		Enabled:    true,
	}
	if err := catalog.SaveForward(context.Background(), dynamic); err != nil {
		t.Fatalf("dynamic forward without target should be allowed: %v", err)
	}
}

func TestSaveForwardNormalizesHostRef(t *testing.T) {
	catalog, cleanup := newTestCatalog(t)
	defer cleanup()

	host := &domain.Host{Title: "transport", Hostname: "transport.example"}
	if err := catalog.SaveHost(context.Background(), host); err != nil {
		t.Fatalf("SaveHost failed: %v", err)
	}
	forward := &domain.Forward{
		Name:       "db",
		HostRef:    "transport",
		Type:       domain.ForwardLocal,
		ListenPort: 15432,
		TargetHost: "db.internal",
		TargetPort: 5432,
		Enabled:    true,
	}
	if err := catalog.SaveForward(context.Background(), forward); err != nil {
		t.Fatalf("SaveForward failed: %v", err)
	}
	if forward.HostRef != host.ID {
		t.Fatalf("expected host_ref to normalize to %s, got %s", host.ID, forward.HostRef)
	}
}

func TestSaveBackendNormalizesTokenAndProfileRef(t *testing.T) {
	catalog, cleanup := newTestCatalog(t)
	defer cleanup()

	profile := &domain.Profile{Name: "termix-lab"}
	if err := catalog.SaveProfile(context.Background(), profile); err != nil {
		t.Fatalf("SaveProfile failed: %v", err)
	}
	backend := &domain.Backend{
		Name:             "lab",
		Type:             domain.BackendTypeTermix,
		URL:              "http://localhost:8080/",
		Token:            "tmx_secret",
		TargetProfileRef: "termix-lab",
	}
	if err := catalog.SaveBackend(context.Background(), backend); err != nil {
		t.Fatalf("SaveBackend failed: %v", err)
	}
	if backend.URL != "http://localhost:8080" {
		t.Fatalf("expected normalized URL, got %q", backend.URL)
	}
	if backend.Token != "" {
		t.Fatal("expected backend token to be cleared after save")
	}
	if backend.TokenSecretID == "" {
		t.Fatal("expected token_secret_id to be populated")
	}
	if backend.TargetProfileRef != profile.ID {
		t.Fatalf("expected target profile ref %s, got %s", profile.ID, backend.TargetProfileRef)
	}

	stored, err := catalog.GetBackend(context.Background(), backend.ID)
	if err != nil {
		t.Fatalf("GetBackend failed: %v", err)
	}
	if stored.Token != "" {
		t.Fatal("expected persisted backend to omit plaintext token")
	}
	raw, err := catalog.OpenSecret(context.Background(), stored.TokenSecretID)
	if err != nil {
		t.Fatalf("OpenSecret failed: %v", err)
	}
	if string(raw) != "tmx_secret" {
		t.Fatalf("unexpected backend token payload %q", string(raw))
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
	forward := &domain.Forward{
		Name:       "db",
		HostRef:    host.ID,
		Type:       domain.ForwardLocal,
		ListenPort: 15432,
		TargetHost: "db.internal",
		TargetPort: 5432,
		Enabled:    true,
	}
	if err := catalog.SaveForward(context.Background(), forward); err != nil {
		t.Fatalf("SaveForward failed: %v", err)
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

	hostRefs, err := catalog.FindReferences(context.Background(), host.ID)
	if err != nil {
		t.Fatalf("FindReferences(host) failed: %v", err)
	}
	if len(hostRefs) != 1 || hostRefs[0].Kind != domain.KindForward || hostRefs[0].Field != "host_ref" {
		t.Fatalf("unexpected host refs: %#v", hostRefs)
	}
}

func TestFindReferencesIncludesBackendRelations(t *testing.T) {
	catalog, cleanup := newTestCatalog(t)
	defer cleanup()

	profile := &domain.Profile{Name: "termix-lab"}
	if err := catalog.SaveProfile(context.Background(), profile); err != nil {
		t.Fatalf("SaveProfile failed: %v", err)
	}
	backend := &domain.Backend{
		Name:             "lab",
		Type:             domain.BackendTypeTermix,
		URL:              "https://termix.example",
		Token:            "tmx_secret",
		TargetProfileRef: profile.ID,
	}
	if err := catalog.SaveBackend(context.Background(), backend); err != nil {
		t.Fatalf("SaveBackend failed: %v", err)
	}
	host := &domain.Host{
		Title:    "prod",
		Hostname: "prod.example.com",
		External: &domain.ExternalRef{
			BackendRef: backend.ID,
			Kind:       "ssh_data",
			ID:         "remote-host-id",
		},
	}
	if err := catalog.SaveHost(context.Background(), host); err != nil {
		t.Fatalf("SaveHost failed: %v", err)
	}

	profileRefs, err := catalog.FindReferences(context.Background(), profile.ID)
	if err != nil {
		t.Fatalf("FindReferences(profile) failed: %v", err)
	}
	if len(profileRefs) != 1 || profileRefs[0].Kind != domain.KindBackend || profileRefs[0].Field != "target_profile_ref" {
		t.Fatalf("unexpected profile refs: %#v", profileRefs)
	}

	backendRefs, err := catalog.FindReferences(context.Background(), backend.ID)
	if err != nil {
		t.Fatalf("FindReferences(backend) failed: %v", err)
	}
	if len(backendRefs) != 1 || backendRefs[0].Kind != domain.KindHost || backendRefs[0].Field != "external.backend_ref" {
		t.Fatalf("unexpected backend refs: %#v", backendRefs)
	}
}

func TestSaveWorkspaceNormalizesHostRefsAndRatio(t *testing.T) {
	catalog, cleanup := newTestCatalog(t)
	defer cleanup()

	host := &domain.Host{Title: "prod", Hostname: "prod.example.com"}
	if err := catalog.SaveHost(context.Background(), host); err != nil {
		t.Fatalf("SaveHost failed: %v", err)
	}
	workspace := &domain.Workspace{
		Name: "ops",
		Root: &domain.WorkspaceNode{
			Split: &domain.WorkspaceSplit{
				Axis:  domain.WorkspaceSplitHorizontal,
				Ratio: 0.95,
				First: &domain.WorkspaceNode{Pane: &domain.WorkspacePane{
					Type:    domain.WorkspacePaneSSH,
					HostRef: "prod",
				}},
				Second: &domain.WorkspaceNode{Pane: &domain.WorkspacePane{Type: domain.WorkspacePaneEmpty}},
			},
		},
	}
	if err := catalog.SaveWorkspace(context.Background(), workspace); err != nil {
		t.Fatalf("SaveWorkspace failed: %v", err)
	}
	if workspace.Root.Split.Ratio != 0.8 {
		t.Fatalf("ratio = %v, want clamped 0.8", workspace.Root.Split.Ratio)
	}
	if workspace.Root.Split.First.Pane.HostRef != host.ID {
		t.Fatalf("host_ref = %q, want %q", workspace.Root.Split.First.Pane.HostRef, host.ID)
	}

	stored, err := catalog.GetWorkspace(context.Background(), workspace.ID)
	if err != nil {
		t.Fatalf("GetWorkspace failed: %v", err)
	}
	if stored.Name != "ops" || stored.Root.Split.First.Pane.HostRef != host.ID {
		t.Fatalf("stored workspace = %#v", stored)
	}
}

func TestSaveWorkspaceRejectsInvalidHostRef(t *testing.T) {
	catalog, cleanup := newTestCatalog(t)
	defer cleanup()

	workspace := &domain.Workspace{
		Name: "broken",
		Root: &domain.WorkspaceNode{Pane: &domain.WorkspacePane{
			Type:    domain.WorkspacePaneSSH,
			HostRef: "missing-host",
		}},
	}
	if err := catalog.SaveWorkspace(context.Background(), workspace); err == nil {
		t.Fatal("expected invalid host_ref to be rejected")
	}
}

func TestFindReferencesIncludesWorkspaceHostRefs(t *testing.T) {
	catalog, cleanup := newTestCatalog(t)
	defer cleanup()

	host := &domain.Host{Title: "prod", Hostname: "prod.example.com"}
	if err := catalog.SaveHost(context.Background(), host); err != nil {
		t.Fatalf("SaveHost failed: %v", err)
	}
	workspace := &domain.Workspace{
		Name: "ops",
		Root: &domain.WorkspaceNode{Pane: &domain.WorkspacePane{
			Type:    domain.WorkspacePaneSSH,
			HostRef: host.ID,
		}},
	}
	if err := catalog.SaveWorkspace(context.Background(), workspace); err != nil {
		t.Fatalf("SaveWorkspace failed: %v", err)
	}

	refs, err := catalog.FindReferences(context.Background(), host.ID)
	if err != nil {
		t.Fatalf("FindReferences failed: %v", err)
	}
	if len(refs) != 1 || refs[0].Kind != domain.KindWorkspace || refs[0].Field != "root.pane.host_ref" {
		t.Fatalf("unexpected workspace refs: %#v", refs)
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
