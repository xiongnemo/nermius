package buildinfo

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCurrentFormatsVersionString(t *testing.T) {
	originalBase := baseVersion
	originalBranch := gitBranch
	originalCommit := gitCommit
	originalDirty := gitDirty
	originalBuildTime := buildTime
	defer func() {
		baseVersion = originalBase
		gitBranch = originalBranch
		gitCommit = originalCommit
		gitDirty = originalDirty
		buildTime = originalBuildTime
	}()

	baseVersion = BaseVersion
	gitBranch = "feature/version-help"
	gitCommit = "0123456789abcdef"
	gitDirty = "true"
	buildTime = "2026-04-23T16:00:00Z"

	info := Current()
	if info.Version != "v0.0.1-feature-version-help-0123456789ab-dirty" {
		t.Fatalf("unexpected version string: %q", info.Version)
	}
	if info.BuildTime != "2026-04-23T16:00:00Z" {
		t.Fatalf("unexpected build time: %q", info.BuildTime)
	}
}

func TestSanitizeBranchFallback(t *testing.T) {
	if got := sanitizeBranch("feature/foo bar"); got != "feature-foo-bar" {
		t.Fatalf("sanitizeBranch() = %q", got)
	}
	if got := sanitizeBranch("///"); got != "unknown" {
		t.Fatalf("sanitizeBranch(only separators) = %q", got)
	}
}

func TestBranchFromGitPathDirectory(t *testing.T) {
	root := t.TempDir()
	gitDir := filepath.Join(root, ".git")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/dev/test\n"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if got := branchFromGitPath(gitDir, root); got != "dev/test" {
		t.Fatalf("branchFromGitPath(dir) = %q", got)
	}
}

func TestBranchFromGitPathFile(t *testing.T) {
	root := t.TempDir()
	actualGitDir := filepath.Join(root, "metadata")
	if err := os.MkdirAll(actualGitDir, 0o755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(actualGitDir, "HEAD"), []byte("ref: refs/heads/feature/version\n"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".git"), []byte("gitdir: metadata\n"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if got := branchFromGitPath(filepath.Join(root, ".git"), root); got != "feature/version" {
		t.Fatalf("branchFromGitPath(file) = %q", got)
	}
}
