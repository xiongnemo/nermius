package service

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nermius/nermius/internal/config"
	"github.com/nermius/nermius/internal/domain"
	"github.com/nermius/nermius/internal/secret"
	"github.com/nermius/nermius/internal/store"
)

func TestVaultStatusAndResolveKeychain(t *testing.T) {
	ctx := context.Background()
	manager := NewVaultManager(mustResolveTestPaths(t, filepath.Join(t.TempDir(), "vault.db")))
	if err := manager.Init(ctx, "master-pass"); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	db, err := manager.Open(ctx)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer db.Close()
	expectedKey, err := manager.unwrapVaultKey(ctx, db, "master-pass")
	if err != nil {
		t.Fatalf("unwrapVaultKey failed: %v", err)
	}
	t.Cleanup(func() { zeroBytes(expectedKey) })

	vaultID, err := manager.vaultID(ctx, db)
	if err != nil {
		t.Fatalf("vaultID failed: %v", err)
	}

	fakeStore := &fakeUnlockStore{
		available: true,
		stored: map[string][]byte{
			vaultID: append([]byte(nil), expectedKey...),
		},
		enrolled: map[string]bool{
			vaultID: true,
		},
	}
	fakePresence := &fakePresence{available: true, presence: true}
	restore := installFakeVaultBackends(fakeStore, fakePresence)
	defer restore()

	status, err := manager.Status(ctx)
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if !status.Initialized || !status.KeychainEnabled {
		t.Fatalf("unexpected status: %+v", status)
	}
	if status.SchemaVersion != store.CurrentSchemaVersion {
		t.Fatalf("expected schema %s, got %s", store.CurrentSchemaVersion, status.SchemaVersion)
	}
	if status.CurrentVaultID != vaultID {
		t.Fatalf("expected vault id %s, got %s", vaultID, status.CurrentVaultID)
	}

	readKey, opened, err := manager.ResolveMasterKey(ctx, func(label string) (string, error) {
		t.Fatalf("ResolveMasterKey unexpectedly prompted for %s", label)
		return "", nil
	})
	if err != nil {
		t.Fatalf("ResolveMasterKey failed: %v", err)
	}
	defer opened.Close()
	defer zeroBytes(readKey)
	if string(readKey) != string(expectedKey) {
		t.Fatal("resolved read key did not match expected key")
	}
	writeKey, err := manager.ResolveWriteKey(ctx, opened, func(label string) (string, error) {
		t.Fatalf("ResolveWriteKey unexpectedly prompted for %s", label)
		return "", nil
	})
	if err != nil {
		t.Fatalf("ResolveWriteKey failed: %v", err)
	}
	defer zeroBytes(writeKey)
	if string(writeKey) != string(expectedKey) {
		t.Fatal("resolved write key did not match expected key")
	}
	if len(fakeStore.loadIntents) != 2 || fakeStore.loadIntents[0] != vaultAccessRead || fakeStore.loadIntents[1] != vaultAccessWrite {
		t.Fatalf("unexpected load intents: %v", fakeStore.loadIntents)
	}
	if len(fakePresence.required) != 2 || fakePresence.required[0] != vaultAccessRead || fakePresence.required[1] != vaultAccessWrite {
		t.Fatalf("unexpected presence intents: %v", fakePresence.required)
	}
}

func TestMigrateVaultMovesLegacyDataIntoEncryptedRecords(t *testing.T) {
	ctx := context.Background()
	vaultPath := filepath.Join(t.TempDir(), "vault.db")
	manager := NewVaultManager(mustResolveTestPaths(t, vaultPath))
	if err := manager.Init(ctx, "master-pass"); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	db, err := manager.Open(ctx)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	key, err := manager.unwrapVaultKey(ctx, db, "master-pass")
	if err != nil {
		t.Fatalf("unwrapVaultKey failed: %v", err)
	}
	defer zeroBytes(key)

	host := domain.Host{ID: "host-1", Title: "prod", Hostname: "prod.example.com"}
	hostBody, err := json.MarshalIndent(host, "", "  ")
	if err != nil {
		t.Fatalf("Marshal host failed: %v", err)
	}
	if err := db.PutLegacyDocument(ctx, store.DocumentRecord{
		ID:    host.ID,
		Kind:  string(domain.KindHost),
		Label: host.Label(),
		Body:  hostBody,
	}); err != nil {
		t.Fatalf("PutLegacyDocument failed: %v", err)
	}

	secretEnv, err := secret.SealEnvelope(key, []byte("super-secret"))
	if err != nil {
		t.Fatalf("SealEnvelope failed: %v", err)
	}
	if err := db.PutLegacySecret(ctx, store.LegacySecretRecord{
		ID:                   "secret-1",
		Kind:                 string(domain.SecretKindPassword),
		WrappedKeyNonce:      secretEnv.WrappedKeyNonce,
		WrappedKeyCiphertext: secretEnv.WrappedKeyCiphertext,
		PayloadNonce:         secretEnv.PayloadNonce,
		PayloadCiphertext:    secretEnv.PayloadCiphertext,
	}); err != nil {
		t.Fatalf("PutLegacySecret failed: %v", err)
	}
	if err := db.DeleteMeta(ctx, metaSchemaVersion); err != nil {
		t.Fatalf("DeleteMeta(schema) failed: %v", err)
	}
	if err := db.DeleteMeta(ctx, metaVaultID); err != nil {
		t.Fatalf("DeleteMeta(vault id) failed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if err := manager.MigrateVault(ctx, func(label string) (string, error) { return "master-pass", nil }); err != nil {
		t.Fatalf("MigrateVault failed: %v", err)
	}
	if _, err := os.Stat(vaultPath + ".bak.pre-schema-v2"); err != nil {
		t.Fatalf("expected migration backup, got %v", err)
	}

	db, err = manager.Open(ctx)
	if err != nil {
		t.Fatalf("Open after migrate failed: %v", err)
	}
	defer db.Close()
	if version, err := manager.schemaVersion(ctx, db); err != nil || version != store.CurrentSchemaVersion {
		t.Fatalf("unexpected schema after migrate: version=%q err=%v", version, err)
	}
	legacyPresent, err := db.LegacyDataPresent(ctx)
	if err != nil {
		t.Fatalf("LegacyDataPresent failed: %v", err)
	}
	if legacyPresent {
		t.Fatal("expected legacy plaintext tables to be empty after migration")
	}

	catalog := NewCatalog(db, key)
	gotHost, err := catalog.GetHost(ctx, host.ID)
	if err != nil {
		t.Fatalf("GetHost failed: %v", err)
	}
	if gotHost.Hostname != host.Hostname {
		t.Fatalf("expected hostname %s, got %s", host.Hostname, gotHost.Hostname)
	}
	rawSecret, err := catalog.OpenSecret(ctx, "secret-1")
	if err != nil {
		t.Fatalf("OpenSecret failed: %v", err)
	}
	if string(rawSecret) != "super-secret" {
		t.Fatalf("unexpected secret payload %q", string(rawSecret))
	}
	fileBytes, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	blob := string(fileBytes)
	if strings.Contains(blob, "prod.example.com") || strings.Contains(blob, "super-secret") {
		t.Fatalf("vault file still exposed plaintext business data: %q", blob)
	}
}

type fakeUnlockStore struct {
	available   bool
	stored      map[string][]byte
	enrolled    map[string]bool
	loadIntents []vaultAccessIntent
}

func (f *fakeUnlockStore) Kind() string { return "fake-keychain" }

func (f *fakeUnlockStore) Available(ctx context.Context) (bool, string) {
	if f.available {
		return true, "fake"
	}
	return false, "fake unavailable"
}

func (f *fakeUnlockStore) IsEnrolled(ctx context.Context, vaultID string) (bool, error) {
	return f.enrolled[vaultID], nil
}

func (f *fakeUnlockStore) Store(ctx context.Context, vaultID string, vaultKey []byte) error {
	if f.stored == nil {
		f.stored = map[string][]byte{}
	}
	if f.enrolled == nil {
		f.enrolled = map[string]bool{}
	}
	f.stored[vaultID] = append([]byte(nil), vaultKey...)
	f.enrolled[vaultID] = true
	return nil
}

func (f *fakeUnlockStore) Load(ctx context.Context, vaultID string, intent vaultAccessIntent) ([]byte, error) {
	f.loadIntents = append(f.loadIntents, intent)
	raw, ok := f.stored[vaultID]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), raw...), nil
}

func (f *fakeUnlockStore) Delete(ctx context.Context, vaultID string) error {
	delete(f.stored, vaultID)
	delete(f.enrolled, vaultID)
	return nil
}

type fakePresence struct {
	available bool
	presence  bool
	required  []vaultAccessIntent
}

func (f *fakePresence) Kind() string { return "fake-presence" }

func (f *fakePresence) Available(ctx context.Context) (bool, string) {
	if f.available {
		return true, "fake"
	}
	return false, "fake unavailable"
}

func (f *fakePresence) UserPresence() bool { return f.presence }

func (f *fakePresence) Require(ctx context.Context, vaultID string, intent vaultAccessIntent) error {
	f.required = append(f.required, intent)
	return nil
}

func installFakeVaultBackends(storeBackend UnlockMaterialStore, presence PresenceAuthorizer) func() {
	prevStore := newUnlockMaterialStore
	prevPresence := newPresenceAuthorizer
	newUnlockMaterialStore = func(paths config.Paths) UnlockMaterialStore { return storeBackend }
	newPresenceAuthorizer = func(paths config.Paths) PresenceAuthorizer { return presence }
	return func() {
		newUnlockMaterialStore = prevStore
		newPresenceAuthorizer = prevPresence
	}
}
