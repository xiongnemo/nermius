package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"

	"github.com/nermius/nermius/internal/config"
	"github.com/nermius/nermius/internal/secret"
	"github.com/nermius/nermius/internal/store"
)

const (
	metaKDF                     = "vault.kdf"
	metaWrappedKey              = "vault.wrapped_key"
	metaVaultID                 = "vault.id"
	metaSchemaVersion           = "vault.schema_version"
	metaKeychainMode            = "vault.keychain_mode"
	metaKeychainRequirePresence = "vault.keychain_require_presence"
)

type PasswordPrompter func(label string) (string, error)

type VaultManager struct {
	Paths config.Paths
}

func NewVaultManager(paths config.Paths) *VaultManager {
	return &VaultManager{Paths: paths}
}

func (m *VaultManager) Open(ctx context.Context) (*store.Store, error) {
	if err := m.rejectLegacyDefaultVault(); err != nil {
		return nil, err
	}
	return m.openAt(ctx, m.Paths.VaultPath)
}

func (m *VaultManager) openAt(ctx context.Context, path string) (*store.Store, error) {
	if err := config.EnsureLayout(m.Paths); err != nil {
		return nil, err
	}
	db, err := store.Open(path)
	if err != nil {
		return nil, err
	}
	if err := db.Migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func (m *VaultManager) rejectLegacyDefaultVault() error {
	if m.Paths.VaultOverride || m.Paths.LegacyVaultPath == "" || samePath(m.Paths.VaultPath, m.Paths.LegacyVaultPath) {
		return nil
	}
	current, err := pathExists(m.Paths.VaultPath)
	if err != nil {
		return err
	}
	legacy, err := pathExists(m.Paths.LegacyVaultPath)
	if err != nil {
		return err
	}
	if !legacy {
		return nil
	}
	if current {
		return fmt.Errorf("both the current vault %q and legacy vault %q exist; choose one with --vault or run `nermius vault migrate` after resolving the duplicate", m.Paths.VaultPath, m.Paths.LegacyVaultPath)
	}
	return fmt.Errorf("vault found at legacy location %q; run `nermius vault migrate` to move it to %q", m.Paths.LegacyVaultPath, m.Paths.VaultPath)
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
	mode, err := m.keychainMode(ctx, db)
	if err != nil {
		return VaultStatus{}, err
	}
	storeBackend := m.unlockStoreForMode(mode)
	storeAvailable, _ := storeBackend.Available(ctx)
	presence := newPresenceAuthorizer(m.Paths)
	presenceAvailable, _ := presence.Available(ctx)
	presenceKind := presence.Kind()
	userPresenceCapable := presenceAvailable && presence.UserPresence()
	if mode == KeychainModeStrongPresence && storeAvailable {
		presenceKind = storeBackend.Kind()
		userPresenceCapable = true
	}
	status := VaultStatus{
		Initialized:         initialized,
		KeychainMode:        mode,
		BackendKind:         storeBackend.Kind(),
		PresenceBackendKind: presenceKind,
		UserPresenceCapable: userPresenceCapable,
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
	if storeAvailable && vaultID != "" {
		enabled, err := storeBackend.IsEnrolled(ctx, vaultID)
		if err != nil {
			return VaultStatus{}, err
		}
		status.KeychainEnabled = enabled
		if enabled {
			status.UnlockMaterialSource = storeBackend.Kind()
			requirePresence, err := m.keychainRequirePresence(ctx, db)
			if err != nil {
				return VaultStatus{}, err
			}
			status.KeychainRequirePresence = requirePresence || mode == KeychainModeStrongPresence
		}
	}
	return status, nil
}

func (m *VaultManager) EnableKeychain(ctx context.Context, password string) error {
	return m.EnableKeychainWithOptions(ctx, password, EnableKeychainOptions{})
}

func (m *VaultManager) EnableKeychainWithOptions(ctx context.Context, password string, opts EnableKeychainOptions) error {
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
	mode := KeychainModePlatform
	if opts.RequirePresence {
		mode = KeychainModeStrongPresence
	}
	storeBackend := m.unlockStoreForMode(mode)
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
	if mode == KeychainModePlatform {
		if err := m.removeOtherKeychainEnrollment(ctx, vaultID, mode); err != nil {
			return err
		}
	}
	if err := storeBackend.Store(ctx, vaultID, vaultKey); err != nil {
		return err
	}
	if mode == KeychainModeStrongPresence {
		if err := m.removeOtherKeychainEnrollment(ctx, vaultID, mode); err != nil {
			return err
		}
	}
	if err := m.setKeychainMode(ctx, db, mode); err != nil {
		return err
	}
	return m.setKeychainRequirePresence(ctx, db, opts.RequirePresence)
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
	return m.clearKeychainEnrollment(ctx, db, vaultID)
}

func (m *VaultManager) clearKeychainEnrollment(ctx context.Context, db *store.Store, vaultID string) error {
	if err := newUnlockMaterialStore(m.Paths).Delete(ctx, vaultID); err != nil {
		return err
	}
	if err := newStrongPresenceMaterialStore(m.Paths).Delete(ctx, vaultID); err != nil {
		return err
	}
	if err := m.setKeychainRequirePresence(ctx, db, false); err != nil {
		return err
	}
	return m.setKeychainMode(ctx, db, KeychainModePlatform)
}

func (m *VaultManager) ResolveMasterKey(ctx context.Context, prompt PasswordPrompter) ([]byte, *store.Store, error) {
	resolution, err := m.ResolveMasterKeyDetailed(ctx, prompt)
	if err != nil {
		return nil, nil, err
	}
	return resolution.Key, resolution.DB, nil
}

func (m *VaultManager) ResolveMasterKeyDetailed(ctx context.Context, prompt PasswordPrompter) (MasterKeyResolution, error) {
	db, err := m.Open(ctx)
	if err != nil {
		return MasterKeyResolution{}, err
	}
	key, details, err := m.resolveKeyWithStore(ctx, db, prompt, vaultAccessRead)
	if err != nil {
		_ = db.Close()
		return MasterKeyResolution{}, err
	}
	return MasterKeyResolution{
		Key:                key,
		DB:                 db,
		Source:             details.source,
		KeychainMode:       details.keychainMode,
		KeychainError:      details.keychainError,
		KeychainConfigured: details.keychainConfigured,
	}, nil
}

func (m *VaultManager) ResolveWriteKey(ctx context.Context, db *store.Store, prompt PasswordPrompter) ([]byte, error) {
	key, _, err := m.resolveKeyWithStore(ctx, db, prompt, vaultAccessWrite)
	return key, err
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
	source, relocated, err := m.migrationSource()
	if err != nil {
		return err
	}
	if relocated {
		if err := m.prepareLegacyRelocation(source); err != nil {
			_ = os.Remove(m.Paths.VaultPath)
			return err
		}
	}
	if err := m.migrateVaultAt(ctx, prompt, m.Paths.VaultPath); err != nil {
		if relocated {
			_ = os.Remove(m.Paths.VaultPath)
		}
		return err
	}
	if relocated {
		if err := m.finishLegacyRelocation(source); err != nil {
			return err
		}
	}
	return nil
}

func (m *VaultManager) migrateVaultAt(ctx context.Context, prompt PasswordPrompter, path string) error {
	db, err := m.openAt(ctx, path)
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

func (m *VaultManager) migrationSource() (string, bool, error) {
	if m.Paths.VaultOverride || m.Paths.LegacyVaultPath == "" || samePath(m.Paths.VaultPath, m.Paths.LegacyVaultPath) {
		return m.Paths.VaultPath, false, nil
	}
	current, err := pathExists(m.Paths.VaultPath)
	if err != nil {
		return "", false, err
	}
	legacy, err := pathExists(m.Paths.LegacyVaultPath)
	if err != nil {
		return "", false, err
	}
	if current && legacy {
		return "", false, fmt.Errorf("both the current vault %q and legacy vault %q exist; choose one with --vault or remove the duplicate before migrating", m.Paths.VaultPath, m.Paths.LegacyVaultPath)
	}
	if legacy {
		return m.Paths.LegacyVaultPath, true, nil
	}
	return m.Paths.VaultPath, false, nil
}

func (m *VaultManager) prepareLegacyRelocation(source string) error {
	if err := copyFile(source, m.Paths.VaultPath); err != nil {
		return fmt.Errorf("copy legacy vault to %q: %w", m.Paths.VaultPath, err)
	}
	if err := copyOptionalFile(m.Paths.LegacySessionPath, m.Paths.SessionPath); err != nil {
		return fmt.Errorf("copy legacy session state: %w", err)
	}
	if err := copyOptionalTree(legacyKeychainPath(m.Paths), filepath.Join(m.Paths.CacheDir, "keychain")); err != nil {
		return fmt.Errorf("copy legacy keychain state: %w", err)
	}
	return nil
}

func (m *VaultManager) finishLegacyRelocation(source string) error {
	paths := []string{
		m.Paths.LegacySessionPath,
		legacyKeychainPath(m.Paths),
		source,
	}
	for _, path := range paths {
		if err := checkArchiveIfExists(path); err != nil {
			return err
		}
	}
	for _, path := range paths {
		if err := archiveIfExists(path); err != nil {
			return err
		}
	}
	return nil
}

func legacyKeychainPath(paths config.Paths) string {
	if strings.TrimSpace(paths.LegacyCacheDir) == "" {
		return ""
	}
	return filepath.Join(paths.LegacyCacheDir, "keychain")
}

func pathExists(path string) (bool, error) {
	if strings.TrimSpace(path) == "" {
		return false, nil
	}
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func samePath(left, right string) bool {
	if left == "" || right == "" {
		return left == right
	}
	leftAbs, leftErr := filepath.Abs(left)
	rightAbs, rightErr := filepath.Abs(right)
	if leftErr != nil || rightErr != nil {
		return filepath.Clean(left) == filepath.Clean(right)
	}
	return filepath.Clean(leftAbs) == filepath.Clean(rightAbs)
}

type keyResolutionDetails struct {
	source             string
	keychainMode       string
	keychainConfigured bool
	keychainError      error
}

func (m *VaultManager) resolveKeyWithStore(ctx context.Context, db *store.Store, prompt PasswordPrompter, intent vaultAccessIntent) ([]byte, keyResolutionDetails, error) {
	details := keyResolutionDetails{}
	keychainMode, keychainConfigured, err := m.keychainConfigured(ctx, db)
	details.keychainMode = keychainMode
	details.keychainConfigured = keychainConfigured
	if err != nil {
		details.keychainConfigured = true
		details.keychainError = err
	}
	if key, err := m.resolveFromKeychain(ctx, db, intent); err == nil {
		details.source = MasterKeySourceKeychain
		return key, details, nil
	} else if details.keychainError == nil {
		details.keychainError = err
	}
	if raw, ok := os.LookupEnv("NERMIUS_MASTER_PASSWORD"); ok && raw != "" {
		key, err := m.unwrapVaultKey(ctx, db, raw)
		if err != nil {
			return nil, details, err
		}
		details.source = MasterKeySourceEnv
		return key, details, nil
	}
	key, err := m.resolvePasswordPromptOnly(ctx, db, prompt)
	if err != nil {
		return nil, details, err
	}
	details.source = MasterKeySourcePassword
	return key, details, nil
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
	mode, err := m.keychainMode(ctx, db)
	if err != nil {
		return nil, err
	}
	storeBackend := m.unlockStoreForMode(mode)
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
	requirePresence, err := m.keychainRequirePresence(ctx, db)
	if err != nil {
		return nil, err
	}
	if requirePresence && mode != KeychainModeStrongPresence {
		presence := newPresenceAuthorizer(m.Paths)
		if err := presence.Require(ctx, vaultID, intent); err != nil {
			return nil, err
		}
	}
	return storeBackend.Load(ctx, vaultID, intent)
}

func (m *VaultManager) unlockStoreForMode(mode string) UnlockMaterialStore {
	if mode == KeychainModeStrongPresence {
		return newStrongPresenceMaterialStore(m.Paths)
	}
	return newUnlockMaterialStore(m.Paths)
}

func (m *VaultManager) removeOtherKeychainEnrollment(ctx context.Context, vaultID, mode string) error {
	if mode == KeychainModeStrongPresence {
		return newUnlockMaterialStore(m.Paths).Delete(ctx, vaultID)
	}
	return newStrongPresenceMaterialStore(m.Paths).Delete(ctx, vaultID)
}

func (m *VaultManager) keychainMode(ctx context.Context, db *store.Store) (string, error) {
	value, err := db.GetMeta(ctx, metaKeychainMode)
	if errors.Is(err, sql.ErrNoRows) {
		return KeychainModePlatform, nil
	}
	if err != nil {
		return "", err
	}
	switch value {
	case KeychainModePlatform, KeychainModeStrongPresence:
		return value, nil
	case "":
		return KeychainModePlatform, nil
	default:
		return "", fmt.Errorf("unsupported keychain mode %q", value)
	}
}

func (m *VaultManager) setKeychainMode(ctx context.Context, db *store.Store, mode string) error {
	if mode == "" {
		mode = KeychainModePlatform
	}
	return db.SetMeta(ctx, metaKeychainMode, mode)
}

func (m *VaultManager) keychainConfigured(ctx context.Context, db *store.Store) (string, bool, error) {
	mode, err := m.keychainMode(ctx, db)
	if err != nil {
		return "", false, err
	}
	if mode == KeychainModeStrongPresence {
		return mode, true, nil
	}
	vaultID, err := m.vaultID(ctx, db)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return mode, false, nil
		}
		return "", false, err
	}
	storeBackend := m.unlockStoreForMode(mode)
	available, _ := storeBackend.Available(ctx)
	if !available {
		return mode, false, nil
	}
	enrolled, err := storeBackend.IsEnrolled(ctx, vaultID)
	if err != nil {
		return "", false, err
	}
	return mode, enrolled, nil
}

func (m *VaultManager) keychainRequirePresence(ctx context.Context, db *store.Store) (bool, error) {
	value, err := db.GetMeta(ctx, metaKeychainRequirePresence)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return value == "true", nil
}

func (m *VaultManager) setKeychainRequirePresence(ctx context.Context, db *store.Store, enabled bool) error {
	value := "false"
	if enabled {
		value = "true"
	}
	return db.SetMeta(ctx, metaKeychainRequirePresence, value)
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
	return copyFile(src, dst)
}

func copyFile(src, dst string) error {
	input, err := os.Open(src)
	if err != nil {
		return err
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	output, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		return err
	}
	if err := output.Chmod(0o600); err != nil {
		_ = output.Close()
		return err
	}
	return output.Close()
}

func copyOptionalFile(src, dst string) error {
	if strings.TrimSpace(src) == "" {
		return nil
	}
	info, err := os.Stat(src)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("expected file, found directory %q", src)
	}
	if exists, err := pathExists(dst); err != nil {
		return err
	} else if exists {
		return nil
	}
	return copyFile(src, dst)
}

func copyOptionalTree(src, dst string) error {
	if strings.TrimSpace(src) == "" {
		return nil
	}
	info, err := os.Stat(src)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("expected directory, found file %q", src)
	}
	return filepath.WalkDir(src, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		return copyOptionalFile(path, target)
	})
}

func archiveIfExists(path string) error {
	if err := checkArchiveIfExists(path); err != nil {
		return err
	}
	if strings.TrimSpace(path) == "" {
		return nil
	}
	exists, err := pathExists(path)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if err := os.Rename(path, path+".bak.pre-location"); err != nil {
		return fmt.Errorf("archive legacy path %q: %w", path, err)
	}
	return nil
}

func checkArchiveIfExists(path string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	exists, err := pathExists(path)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	dst := path + ".bak.pre-location"
	if dstExists, err := pathExists(dst); err != nil {
		return err
	} else if dstExists {
		return fmt.Errorf("cannot archive legacy path %q because %q already exists", path, dst)
	}
	return nil
}
