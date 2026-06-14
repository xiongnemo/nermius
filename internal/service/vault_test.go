package service

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nermius/nermius/internal/config"
	"github.com/nermius/nermius/internal/domain"
	"github.com/nermius/nermius/internal/secret"
	"github.com/nermius/nermius/internal/store"
)

func TestVaultStatusAndResolveKeychainDoesNotRequirePresenceByDefault(t *testing.T) {
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
	restore := installFakeVaultBackends(fakeStore, &fakeUnlockStore{}, fakePresence)
	defer restore()

	status, err := manager.Status(ctx)
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if !status.Initialized || !status.KeychainEnabled {
		t.Fatalf("unexpected status: %+v", status)
	}
	if status.KeychainRequirePresence {
		t.Fatalf("expected keychain presence requirement to default off: %+v", status)
	}
	if status.PresenceBackendKind != "fake-presence" || !status.UserPresenceCapable {
		t.Fatalf("unexpected presence status: %+v", status)
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
	if len(fakePresence.required) != 0 {
		t.Fatalf("expected no presence intents by default, got %v", fakePresence.required)
	}
}

func TestResolveKeychainRequiresPresenceWhenEnabled(t *testing.T) {
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
	restore := installFakeVaultBackends(fakeStore, &fakeUnlockStore{}, fakePresence)
	defer restore()
	if err := manager.setKeychainRequirePresence(ctx, db, true); err != nil {
		t.Fatalf("setKeychainRequirePresence failed: %v", err)
	}

	status, err := manager.Status(ctx)
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if !status.KeychainRequirePresence {
		t.Fatalf("expected keychain presence requirement in status: %+v", status)
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
	writeKey, err := manager.ResolveWriteKey(ctx, opened, func(label string) (string, error) {
		t.Fatalf("ResolveWriteKey unexpectedly prompted for %s", label)
		return "", nil
	})
	if err != nil {
		t.Fatalf("ResolveWriteKey failed: %v", err)
	}
	defer zeroBytes(writeKey)
	if len(fakePresence.required) != 2 || fakePresence.required[0] != vaultAccessRead || fakePresence.required[1] != vaultAccessWrite {
		t.Fatalf("unexpected presence intents: %v", fakePresence.required)
	}
}

func TestResolveStrongKeychainDoesNotUseAppLayerPresence(t *testing.T) {
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
	fakeStrongStore := &fakeUnlockStore{
		available: true,
		kind:      "fake-strong-keychain",
		stored: map[string][]byte{
			vaultID: append([]byte(nil), expectedKey...),
		},
		enrolled: map[string]bool{
			vaultID: true,
		},
	}
	fakePresence := &fakePresence{available: true, presence: true}
	restore := installFakeVaultBackends(&fakeUnlockStore{}, fakeStrongStore, fakePresence)
	defer restore()
	if err := manager.setKeychainMode(ctx, db, KeychainModeStrongPresence); err != nil {
		t.Fatalf("setKeychainMode failed: %v", err)
	}
	if err := manager.setKeychainRequirePresence(ctx, db, true); err != nil {
		t.Fatalf("setKeychainRequirePresence failed: %v", err)
	}

	status, err := manager.Status(ctx)
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if !status.KeychainEnabled || !status.KeychainRequirePresence || status.KeychainMode != KeychainModeStrongPresence {
		t.Fatalf("unexpected strong keychain status: %+v", status)
	}
	if status.PresenceBackendKind != "fake-strong-keychain" || !status.UserPresenceCapable {
		t.Fatalf("expected strong keychain to report presence capability: %+v", status)
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
	writeKey, err := manager.ResolveWriteKey(ctx, opened, func(label string) (string, error) {
		t.Fatalf("ResolveWriteKey unexpectedly prompted for %s", label)
		return "", nil
	})
	if err != nil {
		t.Fatalf("ResolveWriteKey failed: %v", err)
	}
	defer zeroBytes(writeKey)
	if len(fakePresence.required) != 0 {
		t.Fatalf("expected strong mode to skip app-layer presence, got %v", fakePresence.required)
	}
	if len(fakeStrongStore.loadIntents) != 2 || fakeStrongStore.loadIntents[0] != vaultAccessRead || fakeStrongStore.loadIntents[1] != vaultAccessWrite {
		t.Fatalf("unexpected strong load intents: %v", fakeStrongStore.loadIntents)
	}
}

func TestResolveDetailedReportsStrongKeychainFallbackToPassword(t *testing.T) {
	ctx := context.Background()
	manager := NewVaultManager(mustResolveTestPaths(t, filepath.Join(t.TempDir(), "vault.db")))
	if err := manager.Init(ctx, "master-pass"); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	db, err := manager.Open(ctx)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if err := manager.setKeychainMode(ctx, db, KeychainModeStrongPresence); err != nil {
		t.Fatalf("setKeychainMode failed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	fakeStrongStore := &fakeUnlockStore{
		available: true,
		kind:      "fake-strong-keychain",
		enrolled:  map[string]bool{},
	}
	restore := installFakeVaultBackends(&fakeUnlockStore{}, fakeStrongStore, &fakePresence{})
	defer restore()

	resolution, err := manager.ResolveMasterKeyDetailed(ctx, func(label string) (string, error) {
		if label != "Master password" {
			t.Fatalf("unexpected prompt label %q", label)
		}
		return "master-pass", nil
	})
	if err != nil {
		t.Fatalf("ResolveMasterKeyDetailed failed: %v", err)
	}
	defer resolution.DB.Close()
	defer zeroBytes(resolution.Key)
	if resolution.Source != MasterKeySourcePassword {
		t.Fatalf("expected password source, got %+v", resolution)
	}
	if !resolution.KeychainConfigured || resolution.KeychainMode != KeychainModeStrongPresence {
		t.Fatalf("expected configured strong keychain fallback, got %+v", resolution)
	}
	if resolution.KeychainError == nil {
		t.Fatalf("expected keychain error")
	}
}

func TestResolveDetailedFallsBackWhenKeychainProbeFails(t *testing.T) {
	ctx := context.Background()
	manager := NewVaultManager(mustResolveTestPaths(t, filepath.Join(t.TempDir(), "vault.db")))
	if err := manager.Init(ctx, "master-pass"); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	fakeStore := &fakeUnlockStore{available: true, isEnrolledErr: errors.New("probe failed")}
	restore := installFakeVaultBackends(fakeStore, &fakeUnlockStore{}, &fakePresence{})
	defer restore()

	resolution, err := manager.ResolveMasterKeyDetailed(ctx, func(label string) (string, error) {
		return "master-pass", nil
	})
	if err != nil {
		t.Fatalf("ResolveMasterKeyDetailed failed: %v", err)
	}
	defer resolution.DB.Close()
	defer zeroBytes(resolution.Key)
	if resolution.Source != MasterKeySourcePassword {
		t.Fatalf("expected password source, got %+v", resolution)
	}
	if !resolution.KeychainConfigured || resolution.KeychainError == nil {
		t.Fatalf("expected configured keychain probe error, got %+v", resolution)
	}
}

func TestEnableKeychainWithOptionsStoresPresenceRequirement(t *testing.T) {
	ctx := context.Background()
	manager := NewVaultManager(mustResolveTestPaths(t, filepath.Join(t.TempDir(), "vault.db")))
	if err := manager.Init(ctx, "master-pass"); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	fakeStore := &fakeUnlockStore{available: true}
	fakeStrongStore := &fakeUnlockStore{available: true, kind: "fake-strong-keychain"}
	fakePresence := &fakePresence{available: true, presence: true}
	restore := installFakeVaultBackends(fakeStore, fakeStrongStore, fakePresence)
	defer restore()

	if err := manager.EnableKeychainWithOptions(ctx, "master-pass", EnableKeychainOptions{RequirePresence: true}); err != nil {
		t.Fatalf("EnableKeychainWithOptions failed: %v", err)
	}
	status, err := manager.Status(ctx)
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if !status.KeychainEnabled || !status.KeychainRequirePresence || status.KeychainMode != KeychainModeStrongPresence {
		t.Fatalf("unexpected keychain status after enable: %+v", status)
	}
	if len(fakeStrongStore.stored) != 1 || len(fakeStrongStore.enrolled) != 1 {
		t.Fatalf("expected strong store enrollment, got stored=%v enrolled=%v", fakeStrongStore.stored, fakeStrongStore.enrolled)
	}
	if len(fakeStore.stored) != 0 || len(fakeStore.enrolled) != 0 {
		t.Fatalf("expected platform store to be cleared after strong enable, got stored=%v enrolled=%v", fakeStore.stored, fakeStore.enrolled)
	}

	if err := manager.EnableKeychain(ctx, "master-pass"); err != nil {
		t.Fatalf("EnableKeychain failed: %v", err)
	}
	status, err = manager.Status(ctx)
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if !status.KeychainEnabled || status.KeychainRequirePresence || status.KeychainMode != KeychainModePlatform {
		t.Fatalf("expected default enable to disable presence requirement: %+v", status)
	}
	if len(fakeStore.stored) != 1 || len(fakeStore.enrolled) != 1 {
		t.Fatalf("expected platform store enrollment, got stored=%v enrolled=%v", fakeStore.stored, fakeStore.enrolled)
	}
	if len(fakeStrongStore.stored) != 0 || len(fakeStrongStore.enrolled) != 0 {
		t.Fatalf("expected strong store to be cleared after platform enable, got stored=%v enrolled=%v", fakeStrongStore.stored, fakeStrongStore.enrolled)
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
	available     bool
	kind          string
	stored        map[string][]byte
	enrolled      map[string]bool
	isEnrolledErr error
	loadIntents   []vaultAccessIntent
}

func (f *fakeUnlockStore) Kind() string {
	if f.kind != "" {
		return f.kind
	}
	return "fake-keychain"
}

func (f *fakeUnlockStore) Available(ctx context.Context) (bool, string) {
	if f.available {
		return true, "fake"
	}
	return false, "fake unavailable"
}

func (f *fakeUnlockStore) IsEnrolled(ctx context.Context, vaultID string) (bool, error) {
	if f.isEnrolledErr != nil {
		return false, f.isEnrolledErr
	}
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

func installFakeVaultBackends(storeBackend UnlockMaterialStore, strongBackend UnlockMaterialStore, presence PresenceAuthorizer) func() {
	prevStore := newUnlockMaterialStore
	prevStrongStore := newStrongPresenceMaterialStore
	prevPresence := newPresenceAuthorizer
	newUnlockMaterialStore = func(paths config.Paths) UnlockMaterialStore { return storeBackend }
	newStrongPresenceMaterialStore = func(paths config.Paths) UnlockMaterialStore { return strongBackend }
	newPresenceAuthorizer = func(paths config.Paths) PresenceAuthorizer { return presence }
	return func() {
		newUnlockMaterialStore = prevStore
		newStrongPresenceMaterialStore = prevStrongStore
		newPresenceAuthorizer = prevPresence
	}
}
