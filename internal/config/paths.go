package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const (
	AppName            = "nermius"
	DefaultDataDirName = ".nermius"
	DefaultVaultName   = "vault.db"
	DefaultSessionName = "session.json"
)

type Paths struct {
	ConfigDir      string
	CacheDir       string
	VaultPath      string
	SessionPath    string
	KnownHostsPath string

	// Legacy paths are populated only for the default-path layout. They let
	// vault migration find data written by older releases without making
	// ordinary commands silently open or create a different vault.
	LegacyConfigDir   string
	LegacyCacheDir    string
	LegacyVaultPath   string
	LegacySessionPath string
	VaultOverride     bool
}

func ResolvePaths(vaultOverride string) (Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, err
	}
	appConfig := filepath.Join(home, DefaultDataDirName)
	appCache := filepath.Join(appConfig, "cache")
	vaultPath := filepath.Join(appConfig, DefaultVaultName)
	override := strings.TrimSpace(vaultOverride) != ""
	if override {
		vaultPath = ExpandUser(vaultOverride)
	}
	legacyConfig, legacyCache := legacyDirs()
	legacyVaultPath := ""
	legacySessionPath := ""
	if legacyConfig != "" {
		legacyVaultPath = filepath.Join(legacyConfig, DefaultVaultName)
	}
	if legacyCache != "" {
		legacySessionPath = filepath.Join(legacyCache, DefaultSessionName)
	}
	knownHostsPath := filepath.Join(home, ".ssh", "known_hosts")
	return Paths{
		ConfigDir:         appConfig,
		CacheDir:          appCache,
		VaultPath:         vaultPath,
		SessionPath:       filepath.Join(appCache, DefaultSessionName),
		KnownHostsPath:    knownHostsPath,
		LegacyConfigDir:   legacyConfig,
		LegacyCacheDir:    legacyCache,
		LegacyVaultPath:   legacyVaultPath,
		LegacySessionPath: legacySessionPath,
		VaultOverride:     override,
	}, nil
}

func legacyDirs() (string, string) {
	configBase, _ := os.UserConfigDir()
	cacheBase, _ := os.UserCacheDir()
	legacyConfig := ""
	legacyCache := ""
	if strings.TrimSpace(configBase) != "" {
		legacyConfig = filepath.Join(configBase, AppName)
	}
	if strings.TrimSpace(cacheBase) != "" {
		legacyCache = filepath.Join(cacheBase, AppName)
	}
	return legacyConfig, legacyCache
}

func EnsureLayout(paths Paths) error {
	for _, dir := range []string{
		filepath.Dir(paths.VaultPath),
		filepath.Dir(paths.SessionPath),
	} {
		if dir == "" || dir == "." {
			continue
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func ExpandUser(path string) string {
	if path == "" || path[0] != '~' {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if path == "~" {
		return home
	}
	if len(path) > 1 && (path[1] == '/' || path[1] == '\\') {
		return filepath.Join(home, path[2:])
	}
	return path
}

func EnsurePrivateFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	return nil
}

func RemoveIfExists(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
