package config

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// windowsLayout is an environment shaped like Windows, with every location
// inside a temporary home.
func windowsLayout(t *testing.T) (Env, string) {
	t.Helper()
	home := t.TempDir()
	return testEnv("windows", home, map[string]string{
		"APPDATA":      filepath.Join(home, "AppData", "Roaming"),
		"LOCALAPPDATA": filepath.Join(home, "AppData", "Local"),
	}), home
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) failed: %v", path, err)
	}
	return string(raw)
}

func assertMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("%s should not exist (err=%v)", path, err)
	}
}

func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		// Directory times are left out: NTFS refreshes them lazily, and any
		// entry added or removed shows up as a different set of paths anyway.
		value := info.Mode().String()
		if entry.Type().IsRegular() {
			value += " " + info.ModTime().String() + " " + readTestFile(t, path)
		}
		out[path] = value
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot failed: %v", err)
	}
	return out
}

func execute(t *testing.T, plan MigrationPlan) (MigrationResult, string) {
	t.Helper()
	var out bytes.Buffer
	result := plan.Execute(&out)
	return result, out.String()
}

func TestMigrateDryRunTouchesNothing(t *testing.T) {
	env, home := windowsLayout(t)
	writeTestFile(t, filepath.Join(home, "AppData", "Roaming", "nermius", "vault.db"), "vault")
	writeTestFile(t, filepath.Join(home, "AppData", "Local", "nermius", "keychain", "id.bin"), "blob")
	writeTestFile(t, filepath.Join(home, "AppData", "Local", "nermius", "session.json"), "key")
	writeTestFile(t, filepath.Join(home, ".nermius", "notes.txt"), "mine")
	before := snapshot(t, home)

	plan := PlanMigration(env)
	var lines []string
	for _, action := range plan.Actions {
		lines = append(lines, DescribePlanned(action))
	}
	text := strings.Join(lines, "\n")

	if after := snapshot(t, home); len(after) != len(before) {
		t.Fatalf("planning changed the tree: %d entries before, %d after", len(before), len(after))
	} else {
		for path, value := range before {
			if after[path] != value {
				t.Fatalf("planning changed %s", path)
			}
		}
	}
	for _, want := range []string{
		"move     vault: " + filepath.Join(home, "AppData", "Roaming", "nermius", "vault.db") + " -> " + filepath.Join(home, ".local", "share", "nermius", "vault.db"),
		"move     keychain enrollment: ",
		"delete   unlock session from an old release " + filepath.Join(home, "AppData", "Local", "nermius", "session.json"),
		"skip     " + filepath.Join(home, ".nermius", "notes.txt") + ": not a file nermius wrote",
		"rmdir    " + filepath.Join(home, "AppData", "Local", "nermius"),
		"rmdir    " + filepath.Join(home, "AppData", "Roaming", "nermius"),
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("plan lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "rmdir    "+filepath.Join(home, ".nermius")+":") {
		t.Fatalf("a directory holding an unknown file must be kept:\n%s", text)
	}
}

func TestMigrateMovesEverythingAndCleansUp(t *testing.T) {
	env, home := windowsLayout(t)
	roaming := filepath.Join(home, "AppData", "Roaming")
	local := filepath.Join(home, "AppData", "Local")
	data := filepath.Join(home, ".local", "share", "nermius")
	writeTestFile(t, filepath.Join(roaming, "nermius", "vault.db"), "vault")
	writeTestFile(t, filepath.Join(roaming, "nermius", "vault.db.bak.pre-schema-v2"), "backup")
	writeTestFile(t, filepath.Join(local, "nermius", "keychain", "id.bin"), "blob")
	writeTestFile(t, filepath.Join(local, "nermius", "keychain", "id.cng.bin"), "strong")
	writeTestFile(t, filepath.Join(local, "nermius", "session.json"), "key")
	writeTestFile(t, filepath.Join(roaming, "Other", "keep.txt"), "not ours")
	old := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := os.Chtimes(filepath.Join(roaming, "nermius", "vault.db"), old, old); err != nil {
		t.Fatal(err)
	}

	result, out := execute(t, PlanMigration(env))
	if result.Conflicts != 0 || result.Failures != 0 {
		t.Fatalf("result = %+v\n%s", result, out)
	}
	if got := readTestFile(t, filepath.Join(data, "vault.db")); got != "vault" {
		t.Fatalf("vault content = %q", got)
	}
	info, err := os.Stat(filepath.Join(data, "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(old) {
		t.Fatalf("vault mtime = %v, want %v", info.ModTime(), old)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("vault mode = %v, want 0600", info.Mode().Perm())
	}
	if got := readTestFile(t, filepath.Join(data, "vault.db.bak.pre-schema-v2")); got != "backup" {
		t.Fatalf("backup content = %q", got)
	}
	if got := readTestFile(t, filepath.Join(data, "keychain", "id.bin")); got != "blob" {
		t.Fatalf("keychain content = %q", got)
	}
	if got := readTestFile(t, filepath.Join(data, "keychain", "id.cng.bin")); got != "strong" {
		t.Fatalf("strong keychain content = %q", got)
	}
	if runtime.GOOS != "windows" {
		dirInfo, err := os.Stat(data)
		if err != nil {
			t.Fatal(err)
		}
		if dirInfo.Mode().Perm() != 0o700 {
			t.Fatalf("data dir mode = %v, want 0700", dirInfo.Mode().Perm())
		}
	}
	assertMissing(t, filepath.Join(roaming, "nermius"))
	assertMissing(t, filepath.Join(local, "nermius"))
	// Parents the tool does not own stay, and so does another app's data.
	if got := readTestFile(t, filepath.Join(roaming, "Other", "keep.txt")); got != "not ours" {
		t.Fatalf("another application's file changed: %q", got)
	}
	if _, err := os.Stat(local); err != nil {
		t.Fatalf("%%LOCALAPPDATA%% itself must stay: %v", err)
	}
	if !strings.Contains(out, "deleted unlock session from an old release") {
		t.Fatalf("session deletion not reported:\n%s", out)
	}
}

func TestMigrateMergesIntoExistingDirectory(t *testing.T) {
	env, home := windowsLayout(t)
	data := filepath.Join(home, ".local", "share", "nermius")
	writeTestFile(t, filepath.Join(data, "keychain", "current.bin"), "current")
	writeTestFile(t, filepath.Join(home, ".nermius", "cache", "keychain", "old.bin"), "old")

	result, out := execute(t, PlanMigration(env))
	if result.Conflicts != 0 || result.Failures != 0 {
		t.Fatalf("result = %+v\n%s", result, out)
	}
	if got := readTestFile(t, filepath.Join(data, "keychain", "current.bin")); got != "current" {
		t.Fatalf("existing file changed: %q", got)
	}
	if got := readTestFile(t, filepath.Join(data, "keychain", "old.bin")); got != "old" {
		t.Fatalf("merged file = %q", got)
	}
	assertMissing(t, filepath.Join(home, ".nermius"))
}

func TestMigrateConflictKeepsBothAndCarriesOn(t *testing.T) {
	env, home := windowsLayout(t)
	data := filepath.Join(home, ".local", "share", "nermius")
	legacyVault := filepath.Join(home, ".nermius", "vault.db")
	writeTestFile(t, filepath.Join(data, "vault.db"), "new vault")
	writeTestFile(t, legacyVault, "old vault")
	writeTestFile(t, filepath.Join(home, ".nermius", "cache", "keychain", "id.bin"), "blob")

	plan := PlanMigration(env)
	if plan.Conflicts() != 1 {
		t.Fatalf("Conflicts() = %d, want 1", plan.Conflicts())
	}
	result, out := execute(t, plan)
	if result.Conflicts != 1 || result.Failures != 0 {
		t.Fatalf("result = %+v\n%s", result, out)
	}
	if got := readTestFile(t, filepath.Join(data, "vault.db")); got != "new vault" {
		t.Fatalf("new vault overwritten: %q", got)
	}
	if got := readTestFile(t, legacyVault); got != "old vault" {
		t.Fatalf("old vault changed: %q", got)
	}
	if got := readTestFile(t, filepath.Join(data, "keychain", "id.bin")); got != "blob" {
		t.Fatalf("the rest was not migrated: %q", got)
	}
	if _, err := os.Stat(filepath.Join(home, ".nermius")); err != nil {
		t.Fatalf("the directory holding the conflicting copy must stay: %v", err)
	}
	if !strings.Contains(out, "conflict: vault "+legacyVault) {
		t.Fatalf("conflict not reported:\n%s", out)
	}
}

func TestMigrateRemovesIdenticalLegacyCopy(t *testing.T) {
	env, home := windowsLayout(t)
	data := filepath.Join(home, ".local", "share", "nermius")
	writeTestFile(t, filepath.Join(data, "vault.db"), "same")
	writeTestFile(t, filepath.Join(home, "AppData", "Roaming", "nermius", "vault.db"), "same")

	result, out := execute(t, PlanMigration(env))
	if result.Conflicts != 0 || result.Failures != 0 {
		t.Fatalf("result = %+v\n%s", result, out)
	}
	assertMissing(t, filepath.Join(home, "AppData", "Roaming", "nermius"))
	if got := readTestFile(t, filepath.Join(data, "vault.db")); got != "same" {
		t.Fatalf("vault = %q", got)
	}
}

func TestMigrateNewestLegacyCopyWins(t *testing.T) {
	env, home := windowsLayout(t)
	data := filepath.Join(home, ".local", "share", "nermius")
	older := filepath.Join(home, "AppData", "Roaming", "nermius", "vault.db")
	writeTestFile(t, filepath.Join(home, ".nermius", "vault.db"), "v0.0.33")
	writeTestFile(t, older, "v0.0.32")

	plan := PlanMigration(env)
	result, out := execute(t, plan)
	if result.Conflicts != 1 {
		t.Fatalf("result = %+v, want the older copy reported as a conflict\n%s", result, out)
	}
	if got := readTestFile(t, filepath.Join(data, "vault.db")); got != "v0.0.33" {
		t.Fatalf("vault = %q, want the newest copy", got)
	}
	if got := readTestFile(t, older); got != "v0.0.32" {
		t.Fatalf("older copy changed: %q", got)
	}
}

func TestMigrateSecondRunFindsNothing(t *testing.T) {
	env, home := windowsLayout(t)
	writeTestFile(t, filepath.Join(home, ".nermius", "vault.db"), "vault")
	writeTestFile(t, filepath.Join(home, ".nermius", "cache", "keychain", "id.bin"), "blob")
	writeTestFile(t, filepath.Join(home, ".nermius", "cache", "session.json"), "key")
	if result, out := execute(t, PlanMigration(env)); result.Conflicts != 0 || result.Failures != 0 {
		t.Fatalf("first run: %+v\n%s", result, out)
	}
	second := PlanMigration(env)
	if second.Pending() || len(second.Actions) != 0 {
		t.Fatalf("second run planned %+v", second.Actions)
	}
}

func TestMigrateOnLinuxKeepsTheCurrentConfigAndCacheDirs(t *testing.T) {
	home := t.TempDir()
	env := testEnv("linux", home, nil)
	config := filepath.Join(home, ".config", "nermius")
	cache := filepath.Join(home, ".cache", "nermius")
	// os.UserConfigDir()/nermius is the new config dir on Linux.
	writeTestFile(t, filepath.Join(config, "vault.db"), "vault")
	writeTestFile(t, filepath.Join(config, "future-setting.toml"), "x")
	writeTestFile(t, filepath.Join(cache, "session.json"), "key")

	plan := PlanMigration(env)
	for _, action := range plan.Actions {
		if action.Kind == ActionSkip {
			t.Fatalf("files in a current XDG directory must not be reported: %+v", action)
		}
	}
	result, out := execute(t, plan)
	if result.Conflicts != 0 || result.Failures != 0 {
		t.Fatalf("result = %+v\n%s", result, out)
	}
	if got := readTestFile(t, filepath.Join(home, ".local", "share", "nermius", "vault.db")); got != "vault" {
		t.Fatalf("vault = %q", got)
	}
	if got := readTestFile(t, filepath.Join(config, "future-setting.toml")); got != "x" {
		t.Fatalf("config file changed: %q", got)
	}
	assertMissing(t, filepath.Join(cache, "session.json"))
	if _, err := os.Stat(cache); err != nil {
		t.Fatalf("the current cache dir must not be removed: %v", err)
	}
}

func TestMigrateNeverTreatsCurrentDirsAsLegacy(t *testing.T) {
	home := t.TempDir()
	// XDG_DATA_HOME inside the old ~/.nermius must not make migrate move the
	// new data directory into itself or remove it.
	env := testEnv("linux", home, map[string]string{"XDG_DATA_HOME": filepath.Join(home, ".nermius")})
	writeTestFile(t, filepath.Join(home, ".nermius", "vault.db"), "vault")
	writeTestFile(t, filepath.Join(home, ".nermius", "nermius", "keychain", "id.bin"), "blob")

	result, out := execute(t, PlanMigration(env))
	if result.Conflicts != 0 || result.Failures != 0 {
		t.Fatalf("result = %+v\n%s", result, out)
	}
	if got := readTestFile(t, filepath.Join(home, ".nermius", "nermius", "vault.db")); got != "vault" {
		t.Fatalf("vault = %q", got)
	}
	if got := readTestFile(t, filepath.Join(home, ".nermius", "nermius", "keychain", "id.bin")); got != "blob" {
		t.Fatalf("keychain = %q", got)
	}
}

func TestMoveFileNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	writeTestFile(t, src, "source")
	writeTestFile(t, dst, "destination")
	if err := moveFile(src, dst); err == nil {
		t.Fatal("moveFile overwrote an existing destination")
	}
	if got := readTestFile(t, dst); got != "destination" {
		t.Fatalf("destination = %q", got)
	}
	if got := readTestFile(t, src); got != "source" {
		t.Fatalf("source = %q", got)
	}
}

func TestCopyVerifiedPreservesContentModeAndTime(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	writeTestFile(t, src, strings.Repeat("vault bytes ", 10000))
	if err := os.Chmod(src, 0o640); err != nil {
		t.Fatal(err)
	}
	stamp := time.Date(2024, 4, 16, 23, 20, 27, 0, time.UTC)
	if err := os.Chtimes(src, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if err := copyVerified(src, dst); err != nil {
		t.Fatalf("copyVerified failed: %v", err)
	}
	if readTestFile(t, dst) != readTestFile(t, src) {
		t.Fatal("content differs")
	}
	srcInfo, _ := os.Stat(src)
	dstInfo, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if dstInfo.Mode().Perm() != srcInfo.Mode().Perm() {
		t.Fatalf("mode = %v, want %v", dstInfo.Mode().Perm(), srcInfo.Mode().Perm())
	}
	if !dstInfo.ModTime().Equal(stamp) {
		t.Fatalf("mtime = %v, want %v", dstInfo.ModTime(), stamp)
	}
	if err := copyVerified(src, dst); err == nil {
		t.Fatal("copyVerified overwrote an existing file")
	}
}
