package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolvePathsUsesHomeDataRoot(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir failed: %v", err)
	}
	paths, err := ResolvePaths("")
	if err != nil {
		t.Fatalf("ResolvePaths failed: %v", err)
	}
	wantRoot := filepath.Join(home, DefaultDataDirName)
	if paths.ConfigDir != wantRoot {
		t.Fatalf("ConfigDir = %q, want %q", paths.ConfigDir, wantRoot)
	}
	if paths.CacheDir != filepath.Join(wantRoot, "cache") {
		t.Fatalf("CacheDir = %q, want cache below %q", paths.CacheDir, wantRoot)
	}
	if paths.VaultPath != filepath.Join(wantRoot, DefaultVaultName) {
		t.Fatalf("VaultPath = %q, want vault below %q", paths.VaultPath, wantRoot)
	}
	if paths.SessionPath != filepath.Join(paths.CacheDir, DefaultSessionName) {
		t.Fatalf("SessionPath = %q, want session below cache", paths.SessionPath)
	}
	if paths.KnownHostsPath != filepath.Join(home, ".ssh", "known_hosts") {
		t.Fatalf("KnownHostsPath = %q, want OpenSSH path below home", paths.KnownHostsPath)
	}
	if paths.VaultOverride {
		t.Fatal("default paths unexpectedly marked as an override")
	}
}

func TestResolvePathsExpandsVaultOverride(t *testing.T) {
	paths, err := ResolvePaths("~/custom/vault.db")
	if err != nil {
		t.Fatalf("ResolvePaths failed: %v", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir failed: %v", err)
	}
	if paths.VaultPath != filepath.Join(home, "custom", "vault.db") {
		t.Fatalf("VaultPath = %q, want expanded override", paths.VaultPath)
	}
	if !paths.VaultOverride {
		t.Fatal("explicit vault path was not marked as an override")
	}
}
