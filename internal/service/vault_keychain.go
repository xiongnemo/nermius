package service

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/nermius/nermius/internal/config"
)

type vaultAccessIntent string

const (
	vaultAccessRead  vaultAccessIntent = "read"
	vaultAccessWrite vaultAccessIntent = "write"
)

const (
	KeychainModePlatform       = "platform"
	KeychainModeStrongPresence = "windows-cng-presence"
)

type UnlockMaterialStore interface {
	Kind() string
	Available(context.Context) (bool, string)
	IsEnrolled(context.Context, string) (bool, error)
	Store(context.Context, string, []byte) error
	Load(context.Context, string, vaultAccessIntent) ([]byte, error)
	Delete(context.Context, string) error
}

type PresenceAuthorizer interface {
	Kind() string
	Available(context.Context) (bool, string)
	UserPresence() bool
	Require(context.Context, string, vaultAccessIntent) error
}

type VaultStatus struct {
	Initialized             bool   `json:"initialized"`
	KeychainEnabled         bool   `json:"keychain_enabled"`
	KeychainMode            string `json:"keychain_mode,omitempty"`
	KeychainRequirePresence bool   `json:"keychain_require_presence"`
	BackendKind             string `json:"backend_kind,omitempty"`
	PresenceBackendKind     string `json:"presence_backend,omitempty"`
	UserPresenceCapable     bool   `json:"user_presence_capable"`
	CurrentVaultID          string `json:"vault_id,omitempty"`
	SchemaVersion           string `json:"schema_version,omitempty"`
	UnlockMaterialSource    string `json:"unlock_material_source,omitempty"`
}

type EnableKeychainOptions struct {
	RequirePresence bool
}

var (
	newUnlockMaterialStore         = defaultUnlockMaterialStore
	newStrongPresenceMaterialStore = defaultStrongPresenceMaterialStore
	newPresenceAuthorizer          = defaultPresenceAuthorizer
)

func unlockMaterialBlobPath(paths config.Paths, vaultID string) string {
	return filepath.Join(paths.CacheDir, "keychain", fmt.Sprintf("%s.bin", vaultID))
}
