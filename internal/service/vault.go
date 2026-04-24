package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/google/uuid"

	"github.com/nermius/nermius/internal/config"
	"github.com/nermius/nermius/internal/secret"
	"github.com/nermius/nermius/internal/store"
)

const (
	metaKDF           = "vault.kdf"
	metaWrappedKey    = "vault.wrapped_key"
	metaVaultID       = "vault.id"
	metaSchemaVersion = "vault.schema_version"
)

type PasswordPrompter func(label string) (string, error)

type VaultManager struct {
	Paths config.Paths
}

func NewVaultManager(paths config.Paths) *VaultManager {
	return &VaultManager{Paths: paths}
}

func (m *VaultManager) Open(ctx context.Context) (*store.Store, error) {
	if err := config.EnsureLayout(m.Paths); err != nil {
		return nil, err
	}
	db, err := store.Open(m.Paths.VaultPath)
	if err != nil {
		return nil, err
	}
	if err := db.Migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func (m *VaultManager) Init(ctx context.Context, password string) error {
	db, err := m.Open(ctx)
	if err != nil {
		return err
	}
	defer db.Close()
	initialized, err := db.IsInitialized(ctx)
	if err != nil {
		return err
	}
	if initialized {
		return errors.New("vault is already initialized")
	}
	kdf := secret.DefaultKDFParams()
	kek := secret.DeriveKEK(password, kdf)
	vaultKey, err := secret.GenerateVaultKey()
	if err != nil {
		return err
	}
	defer zeroBytes(vaultKey)
	wrapped, err := secret.WrapVaultKey(kek, vaultKey)
	if err != nil {
		return err
	}
	kdfEncoded, err := secret.EncodeJSONBase64(kdf)
	if err != nil {
		return err
	}
	wrappedEncoded, err := secret.EncodeJSONBase64(wrapped)
	if err != nil {
		return err
	}
	for key, value := range map[string]string{
		metaKDF:           kdfEncoded,
		metaWrappedKey:    wrappedEncoded,
		metaVaultID:       uuid.NewString(),
		metaSchemaVersion: store.CurrentSchemaVersion,
	} {
		if err := db.SetMeta(ctx, key, value); err != nil {
			return err
		}
	}
	_ = config.RemoveIfExists(m.Paths.SessionPath)
	return nil
}

func (m *VaultManager) ChangePassword(ctx context.Context, oldPassword, newPassword string) error {
	db, err := m.Open(ctx)
	if err != nil {
		return err
	}
	defer db.Close()
	vaultKey, err := m.unwrapVaultKey(ctx, db, oldPassword)
	if err != nil {
		return err
	}
	defer zeroBytes(vaultKey)
	kdf := secret.DefaultKDFParams()
	kek := secret.DeriveKEK(newPassword, kdf)
	wrapped, err := secret.WrapVaultKey(kek, vaultKey)
	if err != nil {
		return err
	}
	kdfEncoded, err := secret.EncodeJSONBase64(kdf)
	if err != nil {
		return err
	}
	wrappedEncoded, err := secret.EncodeJSONBase64(wrapped)
	if err != nil {
		return err
	}
	if err := db.SetMeta(ctx, metaKDF, kdfEncoded); err != nil {
		return err
	}
	if err := db.SetMeta(ctx, metaWrappedKey, wrappedEncoded); err != nil {
		return err
	}
	status, err := m.Status(ctx)
	if err != nil {
		return err
	}
	if status.KeychainEnabled && status.BackendKind == "unavailable" {
		return errors.New("keychain enrollment is enabled but the current backend is unavailable")
	}
	return nil
}

func (m *VaultManager) Status(ctx context.Context) (VaultStatus, error) {
	db, err := m.Open(ctx)
	if err != nil {
		return VaultStatus{}, err
	}
	defer db.Close()
	initialized, err := db.IsInitialized(ctx)
	if err != nil {
		return VaultStatus{}, err
	}
	storeBackend := newUnlockMaterialStore(m.Paths)
	presence := newPresenceAuthorizer(m.Paths)
	presenceAvailable, _ := presence.Available(ctx)
	status := VaultStatus{
		Initialized:         initialized,
		BackendKind:         storeBackend.Kind(),
		PresenceBackendKind: presence.Kind(),
		UserPresenceCapable: presenceAvailable && presence.UserPresence(),
	}
	if !initialized {
		return status, nil
	}
	schemaVersion, err := m.schemaVersion(ctx, db)
	if err != nil {
		return VaultStatus{}, err
	}
	status.SchemaVersion = schemaVersion
	vaultID, err := m.vaultID(ctx, db)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return VaultStatus{}, err
	}
	status.CurrentVaultID = vaultID
	available, _ := storeBackend.Available(ctx)
	if available && vaultID != "" {
		enabled, err := storeBackend.IsEnrolled(ctx, vaultID)
		if err != nil {
			return VaultStatus{}, err
		}
		status.KeychainEnabled = enabled
		if enabled {
			status.UnlockMaterialSource = storeBackend.Kind()
		}
	}
	return status, nil
}

func (m *VaultManager) EnableKeychain(ctx context.Context, password string) error {
	db, err := m.Open(ctx)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := m.EnsureCurrentSchema(ctx, db); err != nil {
		return err
	}
	vaultID, err := m.vaultID(ctx, db)
	if err != nil {
		return err
	}
	storeBackend := newUnlockMaterialStore(m.Paths)
	available, message := storeBackend.Available(ctx)
	if !available {
		if message == "" {
			message = "system keychain backend unavailable"
		}
		return errors.New(message)
	}
	vaultKey, err := m.unwrapVaultKey(ctx, db, password)
	if err != nil {
		return err
	}
	defer zeroBytes(vaultKey)
	return storeBackend.Store(ctx, vaultID, vaultKey)
}

func (m *VaultManager) DisableKeychain(ctx context.Context) error {
	db, err := m.Open(ctx)
	if err != nil {
		return err
	}
	defer db.Close()
	vaultID, err := m.vaultID(ctx, db)
	if err != nil {
		return err
	}
	storeBackend := newUnlockMaterialStore(m.Paths)
	available, message := storeBackend.Available(ctx)
	if !available {
		if message == "" {
			message = "system keychain backend unavailable"
		}
		return errors.New(message)
	}
	return storeBackend.Delete(ctx, vaultID)
}

func (m *VaultManager) ResolveMasterKey(ctx context.Context, prompt PasswordPrompter) ([]byte, *store.Store, error) {
	db, err := m.Open(ctx)
	if err != nil {
		return nil, nil, err
	}
	key, err := m.resolveKeyWithStore(ctx, db, prompt, vaultAccessRead)
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	return key, db, nil
}

func (m *VaultManager) ResolveWriteKey(ctx context.Context, db *store.Store, prompt PasswordPrompter) ([]byte, error) {
	return m.resolveKeyWithStore(ctx, db, prompt, vaultAccessWrite)
}

func (m *VaultManager) EnsureCurrentSchema(ctx context.Context, db *store.Store) error {
	version, err := m.schemaVersion(ctx, db)
	if err != nil {
		return err
	}
	if version != store.CurrentSchemaVersion {
		return fmt.Errorf("vault schema %s requires `nermius vault migrate`", version)
	}
	return nil
}

func (m *VaultManager) MigrateVault(ctx context.Context, prompt PasswordPrompter) error {
	db, err := m.Open(ctx)
	if err != nil {
		return err
	}
	defer db.Close()
	initialized, err := db.IsInitialized(ctx)
	if err != nil {
		return err
	}
	if !initialized {
		return errors.New("vault is not initialized")
	}
	version, err := m.schemaVersion(ctx, db)
	if err != nil {
		return err
	}
	if version == store.CurrentSchemaVersion {
		return nil
	}
	vaultKey, err := m.resolvePasswordPromptOnly(ctx, db, prompt)
	if err != nil {
		return err
	}
	defer zeroBytes(vaultKey)
	if err := backupFile(m.Paths.VaultPath, m.Paths.VaultPath+".bak.pre-schema-v2"); err != nil {
		return err
	}
	legacyDocs, err := db.ListLegacyDocuments(ctx)
	if err != nil {
		return err
	}
	legacySecrets, err := db.ListLegacySecrets(ctx)
	if err != nil {
		return err
	}
	for _, rec := range legacyDocs {
		encrypted, err := sealPayloadWithKey(vaultKey, rec.ID, vaultRecordPayload{
			Class:     store.RecordClassDocument,
			Kind:      rec.Kind,
			Label:     rec.Label,
			Body:      rec.Body,
			CreatedAt: rec.CreatedAt,
			UpdatedAt: rec.UpdatedAt,
		})
		if err != nil {
			return err
		}
		if err := db.PutRecord(ctx, encrypted); err != nil {
			return err
		}
	}
	for _, rec := range legacySecrets {
		payload, err := secret.OpenEnvelope(vaultKey, secret.EnvelopeSecret{
			WrappedKeyNonce:      rec.WrappedKeyNonce,
			WrappedKeyCiphertext: rec.WrappedKeyCiphertext,
			PayloadNonce:         rec.PayloadNonce,
			PayloadCiphertext:    rec.PayloadCiphertext,
		})
		if err != nil {
			return err
		}
		encrypted, err := sealPayloadWithKey(vaultKey, rec.ID, vaultRecordPayload{
			Class:     store.RecordClassSecret,
			Kind:      rec.Kind,
			Body:      payload,
			CreatedAt: rec.CreatedAt,
			UpdatedAt: rec.UpdatedAt,
		})
		zeroBytes(payload)
		if err != nil {
			return err
		}
		if err := db.PutRecord(ctx, encrypted); err != nil {
			return err
		}
	}
	vaultID, err := m.vaultID(ctx, db)
	if errors.Is(err, sql.ErrNoRows) || vaultID == "" {
		vaultID = uuid.NewString()
		if err := db.SetMeta(ctx, metaVaultID, vaultID); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := db.SetMeta(ctx, metaSchemaVersion, store.CurrentSchemaVersion); err != nil {
		return err
	}
	if err := db.ClearLegacyData(ctx); err != nil {
		return err
	}
	return db.Vacuum(ctx)
}

func (m *VaultManager) resolveKeyWithStore(ctx context.Context, db *store.Store, prompt PasswordPrompter, intent vaultAccessIntent) ([]byte, error) {
	if key, err := m.resolveFromKeychain(ctx, db, intent); err == nil {
		return key, nil
	}
	if raw, ok := os.LookupEnv("NERMIUS_MASTER_PASSWORD"); ok && raw != "" {
		return m.unwrapVaultKey(ctx, db, raw)
	}
	return m.resolvePasswordPromptOnly(ctx, db, prompt)
}

func (m *VaultManager) resolvePasswordPromptOnly(ctx context.Context, db *store.Store, prompt PasswordPrompter) ([]byte, error) {
	if prompt == nil {
		return nil, errors.New("vault is locked; set NERMIUS_MASTER_PASSWORD or provide the master password")
	}
	password, err := prompt("Master password")
	if err != nil {
		return nil, err
	}
	return m.unwrapVaultKey(ctx, db, password)
}

func (m *VaultManager) resolveFromKeychain(ctx context.Context, db *store.Store, intent vaultAccessIntent) ([]byte, error) {
	version, err := m.schemaVersion(ctx, db)
	if err != nil {
		return nil, err
	}
	if version != store.CurrentSchemaVersion {
		return nil, fmt.Errorf("vault schema %s does not support keychain enrollment", version)
	}
	vaultID, err := m.vaultID(ctx, db)
	if err != nil {
		return nil, err
	}
	storeBackend := newUnlockMaterialStore(m.Paths)
	available, message := storeBackend.Available(ctx)
	if !available {
		if message == "" {
			message = "system keychain backend unavailable"
		}
		return nil, errors.New(message)
	}
	enrolled, err := storeBackend.IsEnrolled(ctx, vaultID)
	if err != nil {
		return nil, err
	}
	if !enrolled {
		return nil, errors.New("vault is not enrolled in the system keychain")
	}
	presence := newPresenceAuthorizer(m.Paths)
	if err := presence.Require(ctx, vaultID, intent); err != nil {
		return nil, err
	}
	return storeBackend.Load(ctx, vaultID, intent)
}

func (m *VaultManager) schemaVersion(ctx context.Context, db *store.Store) (string, error) {
	value, err := db.GetMeta(ctx, metaSchemaVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return "1", nil
	}
	return value, err
}

func (m *VaultManager) vaultID(ctx context.Context, db *store.Store) (string, error) {
	return db.GetMeta(ctx, metaVaultID)
}

func (m *VaultManager) unwrapVaultKey(ctx context.Context, db *store.Store, password string) ([]byte, error) {
	var kdf secret.KDFParams
	kdfEncoded, err := db.GetMeta(ctx, metaKDF)
	if err != nil {
		return nil, err
	}
	if err := secret.DecodeJSONBase64(kdfEncoded, &kdf); err != nil {
		return nil, err
	}
	var wrapped secret.WrappedVaultKey
	wrappedEncoded, err := db.GetMeta(ctx, metaWrappedKey)
	if err != nil {
		return nil, err
	}
	if err := secret.DecodeJSONBase64(wrappedEncoded, &wrapped); err != nil {
		return nil, err
	}
	kek := secret.DeriveKEK(password, kdf)
	return secret.UnwrapVaultKey(kek, wrapped)
}

func backupFile(src, dst string) error {
	input, err := os.Open(src)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer output.Close()
	if _, err := io.Copy(output, input); err != nil {
		return err
	}
	return output.Close()
}
