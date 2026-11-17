package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nermius/nermius/internal/config"
)

func testCLIEnv(home string) config.Env {
	return config.Env{GOOS: "linux", Home: home, Getenv: func(string) string { return "" }}
}

func TestRunMigrateNothingToDo(t *testing.T) {
	var out bytes.Buffer
	if err := runMigrate(&out, testCLIEnv(t.TempDir()), "", false); err != nil {
		t.Fatalf("runMigrate failed: %v", err)
	}
	if !strings.Contains(out.String(), "Nothing to migrate.") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestRunMigrateDryRunThenRun(t *testing.T) {
	home := t.TempDir()
	legacy := filepath.Join(home, ".nermius", "vault.db")
	writeCLITestFile(t, legacy, "vault")

	var dry bytes.Buffer
	if err := runMigrate(&dry, testCLIEnv(home), "", true); err != nil {
		t.Fatalf("dry run failed: %v", err)
	}
	if !strings.Contains(dry.String(), "Dry run: nothing will be changed.") || !strings.Contains(dry.String(), "move     vault: "+legacy) {
		t.Fatalf("dry run output = %q", dry.String())
	}
	if _, err := os.Stat(legacy); err != nil {
		t.Fatalf("dry run moved the vault: %v", err)
	}

	var run bytes.Buffer
	if err := runMigrate(&run, testCLIEnv(home), "", false); err != nil {
		t.Fatalf("run failed: %v\n%s", err, run.String())
	}
	if !strings.Contains(run.String(), "moved vault: "+legacy) || !strings.Contains(run.String(), "Migration complete.") {
		t.Fatalf("run output = %q", run.String())
	}

	var again bytes.Buffer
	if err := runMigrate(&again, testCLIEnv(home), "", false); err != nil {
		t.Fatalf("second run failed: %v", err)
	}
	if !strings.Contains(again.String(), "Nothing to migrate.") {
		t.Fatalf("second run output = %q", again.String())
	}
}

func TestRunMigrateConflictFails(t *testing.T) {
	home := t.TempDir()
	writeCLITestFile(t, filepath.Join(home, ".nermius", "vault.db"), "old")
	writeCLITestFile(t, filepath.Join(home, ".local", "share", "nermius", "vault.db"), "new")
	var out bytes.Buffer
	err := runMigrate(&out, testCLIEnv(home), "", false)
	if err == nil || !strings.Contains(err.Error(), "1 conflict(s)") {
		t.Fatalf("err = %v, want a conflict error\n%s", err, out.String())
	}
}

func TestRunMigrateTellsWhereAnOverriddenVaultWent(t *testing.T) {
	home := t.TempDir()
	legacy := filepath.Join(home, ".nermius", "vault.db")
	writeCLITestFile(t, legacy, "vault")
	var out bytes.Buffer
	if err := runMigrate(&out, testCLIEnv(home), legacy, false); err != nil {
		t.Fatalf("runMigrate failed: %v", err)
	}
	want := "Note: --vault points at " + legacy + ", which migrate moves to " + filepath.Join(home, ".local", "share", "nermius", "vault.db")
	if !strings.Contains(out.String(), want) {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}
}

func TestMigrateCompletion(t *testing.T) {
	root := newRootCommand(&runtime{})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"__complete", "mig"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(__complete mig) returned error: %v", err)
	}
	if !strings.Contains(out.String(), "migrate") {
		t.Fatalf("completion output = %q, want migrate", out.String())
	}
}
