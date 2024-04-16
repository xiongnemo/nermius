package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/nermius/nermius/internal/config"
	"github.com/nermius/nermius/internal/secret"
	"github.com/nermius/nermius/internal/store"
)

const (
	metaKDF        = "vault.kdf"
	metaWrappedKey = "vault.wrapped_key"
)

type PasswordPrompter func(label string) (string, error)

type VaultManager struct {
	Paths config.Paths
}

type SessionState struct {
	VaultKey  string    `json:"vault_key"`
	ExpiresAt time.Time `json:"expires_at"`
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
	return m.writeSession(vaultKey, 8*time.Hour)
}

func (m *VaultManager) Unlock(ctx context.Context, password string, ttl time.Duration) error {
	db, err := m.Open(ctx)
	if err != nil {
		return err
	}
	defer db.Close()
	vaultKey, err := m.unwrapVaultKey(ctx, db, password)
	if err != nil {
		return err
	}
	return m.writeSession(vaultKey, ttl)
}

func (m *VaultManager) Lock() error {
	return config.RemoveIfExists(m.Paths.SessionPath)
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
	return m.writeSession(vaultKey, 8*time.Hour)
}

func (m *VaultManager) ResolveMasterKey(ctx context.Context, prompt PasswordPrompter) ([]byte, *store.Store, error) {
	db, err := m.Open(ctx)
	if err != nil {
		return nil, nil, err
	}
	key, err := m.resolveMasterKeyWithStore(ctx, db, prompt)
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	return key, db, nil
}

func (m *VaultManager) resolveMasterKeyWithStore(ctx context.Context, db *store.Store, prompt PasswordPrompter) ([]byte, error) {
	if raw, ok := os.LookupEnv("NERMIUS_MASTER_PASSWORD"); ok && raw != "" {
		return m.unwrapVaultKey(ctx, db, raw)
	}
	if key, err := m.readSession(); err == nil {
		return key, nil
	}
	if prompt == nil {
		return nil, errors.New("vault is locked; run `nermius vault unlock` or set NERMIUS_MASTER_PASSWORD")
	}
	password, err := prompt("Master password")
	if err != nil {
		return nil, err
	}
	return m.unwrapVaultKey(ctx, db, password)
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

func (m *VaultManager) writeSession(vaultKey []byte, ttl time.Duration) error {
	if err := config.EnsureLayout(m.Paths); err != nil {
		return err
	}
	state := SessionState{
		VaultKey:  base64.StdEncoding.EncodeToString(vaultKey),
		ExpiresAt: time.Now().Add(ttl).UTC(),
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return config.EnsurePrivateFile(m.Paths.SessionPath, raw)
}

func (m *VaultManager) readSession() ([]byte, error) {
	raw, err := os.ReadFile(m.Paths.SessionPath)
	if err != nil {
		return nil, err
	}
	var state SessionState
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, err
	}
	if time.Now().UTC().After(state.ExpiresAt) {
		_ = config.RemoveIfExists(m.Paths.SessionPath)
		return nil, fmt.Errorf("session expired")
	}
	return base64.StdEncoding.DecodeString(state.VaultKey)
}
