package cli

import (
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
)

func TestFileSignatureMatches(t *testing.T) {
	dir := t.TempDir()
	left := filepath.Join(dir, "left.bin")
	right := filepath.Join(dir, "right.bin")
	other := filepath.Join(dir, "other.bin")
	if err := os.WriteFile(left, []byte("same"), 0o600); err != nil {
		t.Fatalf("WriteFile left failed: %v", err)
	}
	if err := os.WriteFile(right, []byte("same"), 0o600); err != nil {
		t.Fatalf("WriteFile right failed: %v", err)
	}
	if err := os.WriteFile(other, []byte("different"), 0o600); err != nil {
		t.Fatalf("WriteFile other failed: %v", err)
	}

	leftSig, err := readFileSignature(left)
	if err != nil {
		t.Fatalf("readFileSignature left failed: %v", err)
	}
	rightSig, err := readFileSignature(right)
	if err != nil {
		t.Fatalf("readFileSignature right failed: %v", err)
	}
	otherSig, err := readFileSignature(other)
	if err != nil {
		t.Fatalf("readFileSignature other failed: %v", err)
	}

	if !leftSig.matches(rightSig) {
		t.Fatal("expected identical files to match")
	}
	if leftSig.matches(otherSig) {
		t.Fatal("expected different files not to match")
	}
}

func TestDetectShellFromEnv(t *testing.T) {
	bash := detectShellFromEnv("linux", func(key string) string {
		if key == "SHELL" {
			return "/bin/bash"
		}
		return ""
	})
	if bash != shellBash {
		t.Fatalf("expected bash, got %s", bash)
	}

	powerShell := detectShellFromEnv("windows", func(key string) string {
		if key == "PSModulePath" {
			return "C:\\Users\\nemo\\Documents\\WindowsPowerShell\\Modules"
		}
		return ""
	})
	if powerShell != shellPowerShell {
		t.Fatalf("expected powershell, got %s", powerShell)
	}
}

func TestFindExecutableInPath(t *testing.T) {
	dir := t.TempDir()
	name := "nermius"
	pathExt := ""
	goos := goruntime.GOOS
	fileName := name
	if goos == "windows" {
		fileName = name + ".exe"
		pathExt = ".EXE"
	}
	fullPath := filepath.Join(dir, fileName)
	if err := os.WriteFile(fullPath, []byte("binary"), 0o755); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	found, ok := findExecutableInPath(goos, name, dir, pathExt)
	if !ok {
		t.Fatal("expected executable to be found in PATH")
	}
	if !samePath(found, fullPath) {
		t.Fatalf("expected %s, got %s", fullPath, found)
	}
}

func TestInstallCommandNames(t *testing.T) {
	names := installCommandNames("nermius.exe")
	if len(names) != 2 {
		t.Fatalf("expected 2 names, got %v", names)
	}
	if names[0] != "nermius" || names[1] != "nermius.exe" {
		t.Fatalf("unexpected command names: %v", names)
	}
}

func TestPathContainsDir(t *testing.T) {
	dir := t.TempDir()
	pathEnv := strings.Join([]string{filepath.Join(dir, "other"), dir}, string(os.PathListSeparator))
	if !pathContainsDir(dir, pathEnv) {
		t.Fatal("expected target directory to be detected in PATH")
	}
}
