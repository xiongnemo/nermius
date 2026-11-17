package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testEnv(goos, home string, vars map[string]string) Env {
	return Env{GOOS: goos, Home: home, Getenv: func(name string) string { return vars[name] }}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
}

func TestDirsHonourOnlyAbsoluteXDGVariables(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			home := t.TempDir()
			unset := testEnv(goos, home, nil).Dirs()
			want := Dirs{
				Config: filepath.Join(home, ".config", "nermius"),
				Data:   filepath.Join(home, ".local", "share", "nermius"),
				State:  filepath.Join(home, ".local", "state", "nermius"),
				Cache:  filepath.Join(home, ".cache", "nermius"),
			}
			if unset != want {
				t.Fatalf("unset XDG: got %+v, want %+v", unset, want)
			}

			base := t.TempDir()
			set := testEnv(goos, home, map[string]string{
				"XDG_CONFIG_HOME": filepath.Join(base, "c"),
				"XDG_DATA_HOME":   filepath.Join(base, "d"),
				"XDG_STATE_HOME":  filepath.Join(base, "s"),
				"XDG_CACHE_HOME":  filepath.Join(base, "k"),
			}).Dirs()
			wantSet := Dirs{
				Config: filepath.Join(base, "c", "nermius"),
				Data:   filepath.Join(base, "d", "nermius"),
				State:  filepath.Join(base, "s", "nermius"),
				Cache:  filepath.Join(base, "k", "nermius"),
			}
			if set != wantSet {
				t.Fatalf("absolute XDG: got %+v, want %+v", set, wantSet)
			}

			relative := testEnv(goos, home, map[string]string{
				"XDG_CONFIG_HOME": "relative/c",
				"XDG_DATA_HOME":   "relative/d",
				"XDG_STATE_HOME":  ".",
				"XDG_CACHE_HOME":  "k",
			}).Dirs()
			if relative != want {
				t.Fatalf("relative XDG must be ignored: got %+v, want %+v", relative, want)
			}
		})
	}
}

func TestResolveVaultLegacyNewBothNeither(t *testing.T) {
	type layout struct {
		name       string
		goos       string
		vars       func(home string) map[string]string
		legacyPath func(home string) string
	}
	layouts := []layout{
		{"home dot dir", "linux", func(string) map[string]string { return nil }, func(home string) string {
			return filepath.Join(home, ".nermius", "vault.db")
		}},
		{"windows appdata", "windows", func(home string) map[string]string {
			return map[string]string{"APPDATA": filepath.Join(home, "AppData", "Roaming"), "LOCALAPPDATA": filepath.Join(home, "AppData", "Local")}
		}, func(home string) string {
			return filepath.Join(home, "AppData", "Roaming", "nermius", "vault.db")
		}},
		{"macos application support", "darwin", func(string) map[string]string { return nil }, func(home string) string {
			return filepath.Join(home, "Library", "Application Support", "nermius", "vault.db")
		}},
		{"linux user config dir", "linux", func(string) map[string]string { return nil }, func(home string) string {
			return filepath.Join(home, ".config", "nermius", "vault.db")
		}},
	}
	for _, l := range layouts {
		for _, state := range []string{"legacy only", "new only", "both", "neither"} {
			t.Run(l.name+"/"+state, func(t *testing.T) {
				home := t.TempDir()
				env := testEnv(l.goos, home, l.vars(home))
				newPath := filepath.Join(home, ".local", "share", "nermius", "vault.db")
				legacyPath := l.legacyPath(home)
				if state == "legacy only" || state == "both" {
					writeTestFile(t, legacyPath, "legacy")
				}
				if state == "new only" || state == "both" {
					writeTestFile(t, newPath, "new")
				}
				paths := ResolvePathsIn(env, "")
				want := newPath
				if state == "legacy only" {
					want = legacyPath
				}
				if paths.VaultPath != want {
					t.Fatalf("VaultPath = %q, want %q", paths.VaultPath, want)
				}
				if state == "legacy only" {
					if len(paths.Legacy) != 1 || paths.Legacy[0].Path != legacyPath || paths.Legacy[0].NewPath != newPath {
						t.Fatalf("Legacy = %+v, want one entry for %q", paths.Legacy, legacyPath)
					}
				} else if len(paths.Legacy) != 0 {
					t.Fatalf("Legacy = %+v, want none", paths.Legacy)
				}
			})
		}
	}
}

func TestResolveRelativeXDGConfigHomeHasNoLegacyOSDir(t *testing.T) {
	home := t.TempDir()
	// Older releases failed outright with a relative XDG_CONFIG_HOME, so a
	// vault under it is not theirs.
	writeTestFile(t, filepath.Join(home, "relative", "nermius", "vault.db"), "x")
	paths := ResolvePathsIn(testEnv("linux", home, map[string]string{"XDG_CONFIG_HOME": "relative"}), "")
	if want := filepath.Join(home, ".local", "share", "nermius", "vault.db"); paths.VaultPath != want {
		t.Fatalf("VaultPath = %q, want %q", paths.VaultPath, want)
	}
}

func TestResolveUsesAbsoluteXDGConfigHomeForLegacyOSDir(t *testing.T) {
	home := t.TempDir()
	configHome := filepath.Join(t.TempDir(), "cfg")
	legacy := filepath.Join(configHome, "nermius", "vault.db")
	writeTestFile(t, legacy, "x")
	paths := ResolvePathsIn(testEnv("linux", home, map[string]string{"XDG_CONFIG_HOME": configHome}), "")
	if paths.VaultPath != legacy {
		t.Fatalf("VaultPath = %q, want %q", paths.VaultPath, legacy)
	}
}

func TestResolveItemsIndependently(t *testing.T) {
	home := t.TempDir()
	vars := map[string]string{"APPDATA": filepath.Join(home, "Roaming"), "LOCALAPPDATA": filepath.Join(home, "Local")}
	env := testEnv("windows", home, vars)
	newVault := filepath.Join(home, ".local", "share", "nermius", "vault.db")
	legacyKeychain := filepath.Join(home, "Local", "nermius", "keychain")
	writeTestFile(t, newVault, "vault")
	writeTestFile(t, filepath.Join(legacyKeychain, "id.bin"), "blob")

	paths := ResolvePathsIn(env, "")
	if paths.VaultPath != newVault {
		t.Fatalf("VaultPath = %q, want %q", paths.VaultPath, newVault)
	}
	if paths.KeychainDir != legacyKeychain {
		t.Fatalf("KeychainDir = %q, want %q", paths.KeychainDir, legacyKeychain)
	}
	if len(paths.Legacy) != 1 || paths.Legacy[0].Item != "keychain enrollment" {
		t.Fatalf("Legacy = %+v, want only the keychain", paths.Legacy)
	}
}

func TestEmptyNewLocationsDoNotHideLegacy(t *testing.T) {
	home := t.TempDir()
	env := testEnv("linux", home, nil)
	legacyVault := filepath.Join(home, ".nermius", "vault.db")
	legacyKeychain := filepath.Join(home, ".nermius", "cache", "keychain")
	writeTestFile(t, legacyVault, "vault")
	writeTestFile(t, filepath.Join(legacyKeychain, "id.bin"), "blob")
	// A newer run may have created empty directories or an empty file.
	writeTestFile(t, filepath.Join(home, ".local", "share", "nermius", "vault.db"), "")
	if err := os.MkdirAll(filepath.Join(home, ".local", "share", "nermius", "keychain"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".cache", "nermius"), 0o700); err != nil {
		t.Fatal(err)
	}

	paths := ResolvePathsIn(env, "")
	if paths.VaultPath != legacyVault {
		t.Fatalf("VaultPath = %q, want %q", paths.VaultPath, legacyVault)
	}
	if paths.KeychainDir != legacyKeychain {
		t.Fatalf("KeychainDir = %q, want %q", paths.KeychainDir, legacyKeychain)
	}
}

func TestVaultOverrideWins(t *testing.T) {
	home := t.TempDir()
	writeTestFile(t, filepath.Join(home, ".nermius", "vault.db"), "legacy")
	paths := ResolvePathsIn(testEnv("linux", home, nil), "~/custom/vault.db")
	if paths.VaultPath != filepath.Join(home, "custom", "vault.db") {
		t.Fatalf("VaultPath = %q, want the expanded override", paths.VaultPath)
	}
	if !paths.VaultOverride {
		t.Fatal("explicit vault path was not marked as an override")
	}
	for _, use := range paths.Legacy {
		if use.Item == "vault" {
			t.Fatalf("an override must not report the old vault: %+v", use)
		}
	}
}

func TestFreshInstallUsesNewLocationsAndCreatesNothing(t *testing.T) {
	home := t.TempDir()
	paths := ResolvePathsIn(testEnv("windows", home, map[string]string{
		"APPDATA":      filepath.Join(home, "Roaming"),
		"LOCALAPPDATA": filepath.Join(home, "Local"),
	}), "")
	if want := filepath.Join(home, ".local", "share", "nermius", "vault.db"); paths.VaultPath != want {
		t.Fatalf("VaultPath = %q, want %q", paths.VaultPath, want)
	}
	if want := filepath.Join(home, ".local", "share", "nermius", "keychain"); paths.KeychainDir != want {
		t.Fatalf("KeychainDir = %q, want %q", paths.KeychainDir, want)
	}
	if paths.KnownHostsPath != filepath.Join(home, ".ssh", "known_hosts") {
		t.Fatalf("KnownHostsPath = %q, want OpenSSH's file", paths.KnownHostsPath)
	}
	if len(paths.Legacy) != 0 {
		t.Fatalf("Legacy = %+v, want none", paths.Legacy)
	}
	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("resolving paths created %d entries in the home directory", len(entries))
	}
}

func TestResolvePathsReadsTheProcessEnvironment(t *testing.T) {
	home := t.TempDir()
	data := t.TempDir()
	for _, name := range []string{"HOME", "USERPROFILE"} {
		t.Setenv(name, home)
	}
	t.Setenv("APPDATA", filepath.Join(home, "Roaming"))
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "Local"))
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("XDG_DATA_HOME", data)
	paths, err := ResolvePaths("")
	if err != nil {
		t.Fatalf("ResolvePaths failed: %v", err)
	}
	if want := filepath.Join(data, "nermius", "vault.db"); paths.VaultPath != want {
		t.Fatalf("VaultPath = %q, want %q", paths.VaultPath, want)
	}
}

func TestLegacyNoticeNamesBothLocations(t *testing.T) {
	notice := LegacyUse{Item: "vault", Path: "/old/vault.db", NewPath: "/new/vault.db"}.Notice()
	for _, part := range []string{"nermius: ", "vault", "/old/vault.db", `"nermius migrate"`, "/new/vault.db"} {
		if !strings.Contains(notice, part) {
			t.Fatalf("notice %q lacks %q", notice, part)
		}
	}
	if strings.Contains(notice, "\n") {
		t.Fatalf("notice must be one line: %q", notice)
	}
}
