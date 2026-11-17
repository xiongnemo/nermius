package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// isolateHome points every variable that decides nermius' file locations at a
// temporary directory, so a test never sees the real home.
func isolateHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "AppData", "Local"))
	for _, name := range []string{"XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR"} {
		t.Setenv(name, "")
	}
	return home
}

func writeCLITestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyNoticePrintedOncePerRunOnStderr(t *testing.T) {
	home := isolateHome(t)
	writeCLITestFile(t, filepath.Join(home, ".nermius", "vault.db"), "vault")
	var stderr bytes.Buffer
	rt := &runtime{stderr: &stderr}
	for i := 0; i < 3; i++ {
		paths, err := rt.paths()
		if err != nil {
			t.Fatalf("paths failed: %v", err)
		}
		if paths.VaultPath != filepath.Join(home, ".nermius", "vault.db") {
			t.Fatalf("VaultPath = %q", paths.VaultPath)
		}
	}
	lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], `run "nermius migrate"`) {
		t.Fatalf("stderr = %q, want exactly one migrate notice", stderr.String())
	}
}

func TestLegacyNoticeSilentWithoutOldFiles(t *testing.T) {
	isolateHome(t)
	var stderr bytes.Buffer
	rt := &runtime{stderr: &stderr}
	if _, err := rt.paths(); err != nil {
		t.Fatal(err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want nothing", stderr.String())
	}
}
