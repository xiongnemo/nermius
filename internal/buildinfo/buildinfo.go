package buildinfo

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"unicode"
)

const BaseVersion = "v0.0.1"

var (
	baseVersion = BaseVersion
	gitBranch   string
	gitCommit   string
	gitDirty    string
	buildTime   string
)

type Info struct {
	BaseVersion string
	Version     string
	Branch      string
	Commit      string
	BuildTime   string
	Dirty       bool
}

func Current() Info {
	settings := map[string]string{}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			settings[setting.Key] = setting.Value
		}
	}

	base := firstNonEmpty(baseVersion, BaseVersion)
	branch := sanitizeBranch(firstNonEmpty(gitBranch, settings["vcs.branch"], discoverGitBranch(), "unknown"))
	commit := shortenCommit(firstNonEmpty(gitCommit, settings["vcs.revision"], "unknown"))
	dirty := parseDirty(firstNonEmpty(gitDirty, settings["vcs.modified"]))
	build := firstNonEmpty(buildTime, settings["vcs.time"], "unknown")

	return Info{
		BaseVersion: base,
		Version:     formatVersion(base, branch, commit, dirty),
		Branch:      branch,
		Commit:      commit,
		BuildTime:   build,
		Dirty:       dirty,
	}
}

func formatVersion(base, branch, commit string, dirty bool) string {
	version := firstNonEmpty(base, BaseVersion) + "-" + firstNonEmpty(branch, "unknown") + "-" + firstNonEmpty(commit, "unknown")
	if dirty {
		version += "-dirty"
	}
	return version
}

func shortenCommit(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 12 {
		return value[:12]
	}
	if value == "" {
		return "unknown"
	}
	return value
}

func sanitizeBranch(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	var b strings.Builder
	prevDash := false
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
			prevDash = false
			continue
		}
		if !prevDash {
			b.WriteByte('-')
			prevDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "unknown"
	}
	return out
}

func parseDirty(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "dirty":
		return true
	default:
		return false
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func discoverGitBranch() string {
	dirs := []string{}
	if cwd, err := os.Getwd(); err == nil {
		dirs = append(dirs, cwd)
	}
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	for _, dir := range dirs {
		if branch := findGitBranch(dir); branch != "" {
			return branch
		}
	}
	return ""
}

func findGitBranch(start string) string {
	current := start
	for {
		gitPath := filepath.Join(current, ".git")
		if branch := branchFromGitPath(gitPath, current); branch != "" {
			return branch
		}
		parent := filepath.Dir(current)
		if parent == current {
			return ""
		}
		current = parent
	}
}

func branchFromGitPath(gitPath, root string) string {
	info, err := os.Stat(gitPath)
	if err != nil {
		return ""
	}
	if info.IsDir() {
		return branchFromHead(filepath.Join(gitPath, "HEAD"))
	}
	raw, err := os.ReadFile(gitPath)
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(line, "gitdir: ") {
		return ""
	}
	gitDir := strings.TrimSpace(strings.TrimPrefix(line, "gitdir: "))
	if !filepath.IsAbs(gitDir) {
		gitDir = filepath.Join(root, gitDir)
	}
	return branchFromHead(filepath.Join(gitDir, "HEAD"))
}

func branchFromHead(headPath string) string {
	raw, err := os.ReadFile(headPath)
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(string(raw))
	if line == "" {
		return ""
	}
	if !strings.HasPrefix(line, "ref: ") {
		return "detached"
	}
	ref := strings.TrimSpace(strings.TrimPrefix(line, "ref: "))
	const headsPrefix = "refs/heads/"
	if strings.HasPrefix(ref, headsPrefix) {
		return strings.TrimPrefix(ref, headsPrefix)
	}
	return ref
}
