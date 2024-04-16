package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	AppName            = "nermius"
	DefaultVaultName   = "vault.db"
	DefaultSessionName = "session.json"
)

type Paths struct {
	ConfigDir      string
	CacheDir       string
	VaultPath      string
	SessionPath    string
	KnownHostsPath string
}

func ResolvePaths(vaultOverride string) (Paths, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return Paths{}, err
	}
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return Paths{}, err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, err
	}
	appConfig := filepath.Join(configDir, AppName)
	appCache := filepath.Join(cacheDir, AppName)
	vaultPath := filepath.Join(appConfig, DefaultVaultName)
	if strings.TrimSpace(vaultOverride) != "" {
		vaultPath = ExpandUser(vaultOverride)
	}
	knownHostsPath := filepath.Join(home, ".ssh", "known_hosts")
	if runtime.GOOS == "windows" {
		knownHostsPath = filepath.Join(home, ".ssh", "known_hosts")
	}
	return Paths{
		ConfigDir:      appConfig,
		CacheDir:       appCache,
		VaultPath:      vaultPath,
		SessionPath:    filepath.Join(appCache, DefaultSessionName),
		KnownHostsPath: knownHostsPath,
	}, nil
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
