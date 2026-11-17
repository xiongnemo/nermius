package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	AppName          = "nermius"
	DefaultVaultName = "vault.db"
	KeychainDirName  = "keychain"
)

// Env is the part of the process environment that decides where nermius keeps
// its files. Tests build one by hand so they never look at the real home.
type Env struct {
	GOOS   string
	Home   string
	Getenv func(string) string
}

// CurrentEnv describes the running process.
func CurrentEnv() (Env, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Env{}, err
	}
	return Env{GOOS: runtime.GOOS, Home: home, Getenv: os.Getenv}, nil
}

func (e Env) getenv(name string) string {
	if e.Getenv == nil {
		return ""
	}
	return e.Getenv(name)
}

// Dirs are nermius' XDG base directories. The same layout is used on Linux,
// macOS and Windows.
type Dirs struct {
	Config string
	Data   string
	State  string
	Cache  string
}

func (e Env) Dirs() Dirs {
	return Dirs{
		Config: e.xdgDir("XDG_CONFIG_HOME", ".config"),
		Data:   e.xdgDir("XDG_DATA_HOME", ".local", "share"),
		State:  e.xdgDir("XDG_STATE_HOME", ".local", "state"),
		Cache:  e.xdgDir("XDG_CACHE_HOME", ".cache"),
	}
}

// xdgDir honours an XDG variable only when it holds an absolute path; the XDG
// spec says relative values are invalid and must be ignored.
func (e Env) xdgDir(variable string, fallback ...string) string {
	if value := e.getenv(variable); value != "" && filepath.IsAbs(value) {
		return filepath.Join(value, AppName)
	}
	return filepath.Join(append(append([]string{e.Home}, fallback...), AppName)...)
}

func (d Dirs) all() []string {
	return []string{d.Config, d.Data, d.State, d.Cache}
}

// legacyRoots are the nermius-owned directories released versions wrote to.
type legacyRoots struct {
	// Home is ~/.nermius, used by v0.0.33-dev: vault.db at its top and the
	// keychain blobs below Home/cache.
	Home      string
	HomeCache string
	// OSConfig and OSCache are what os.UserConfigDir and os.UserCacheDir
	// produced for every release before v0.0.33-dev.
	OSConfig string
	OSCache  string
}

func (e Env) legacyRoots() legacyRoots {
	roots := legacyRoots{
		Home:      filepath.Join(e.Home, ".nermius"),
		HomeCache: filepath.Join(e.Home, ".nermius", "cache"),
	}
	if base := e.osConfigBase(); base != "" {
		roots.OSConfig = filepath.Join(base, AppName)
	}
	if base := e.osCacheBase(); base != "" {
		roots.OSCache = filepath.Join(base, AppName)
	}
	return roots
}

// osConfigBase mirrors os.UserConfigDir for e, so the legacy location is the
// one an older release computed in the same environment.
func (e Env) osConfigBase() string {
	switch e.GOOS {
	case "windows":
		return e.getenv("APPDATA")
	case "darwin", "ios":
		return filepath.Join(e.Home, "Library", "Application Support")
	default:
		return e.unixBase("XDG_CONFIG_HOME", ".config")
	}
}

// osCacheBase mirrors os.UserCacheDir for e.
func (e Env) osCacheBase() string {
	switch e.GOOS {
	case "windows":
		return e.getenv("LOCALAPPDATA")
	case "darwin", "ios":
		return filepath.Join(e.Home, "Library", "Caches")
	default:
		return e.unixBase("XDG_CACHE_HOME", ".cache")
	}
}

func (e Env) unixBase(variable, fallback string) string {
	value := e.getenv(variable)
	if value == "" {
		return filepath.Join(e.Home, fallback)
	}
	if !filepath.IsAbs(value) {
		// os.User*Dir failed here, and so did older releases: nothing was written.
		return ""
	}
	return value
}

func (r legacyRoots) vaultCandidates() []string {
	return joinEach([]string{r.Home, r.OSConfig}, DefaultVaultName)
}

func (r legacyRoots) keychainCandidates() []string {
	return joinEach([]string{r.HomeCache, r.OSCache}, KeychainDirName)
}

func joinEach(dirs []string, name string) []string {
	out := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		if dir != "" {
			out = append(out, filepath.Join(dir, name))
		}
	}
	return out
}

type Paths struct {
	DataDir        string
	VaultPath      string
	KeychainDir    string
	KnownHostsPath string
	VaultOverride  bool

	// Legacy lists the items that were found only at a location an older
	// release used, and are being used from there.
	Legacy []LegacyUse
}

// LegacyUse records one item resolved to an old location.
type LegacyUse struct {
	Item    string
	Path    string
	NewPath string
}

// Notice is the one-line hint printed to stderr when a legacy location is used.
func (u LegacyUse) Notice() string {
	return fmt.Sprintf("%s: using the %s from the old location %s; run \"%s migrate\" to move it to %s", AppName, u.Item, u.Path, AppName, u.NewPath)
}

func ResolvePaths(vaultOverride string) (Paths, error) {
	env, err := CurrentEnv()
	if err != nil {
		return Paths{}, err
	}
	return ResolvePathsIn(env, vaultOverride), nil
}

// ResolvePathsIn resolves every item independently: an explicit override
// wins, then the item at its XDG location, then the item at a location an
// older release used, and otherwise the XDG location, created on first write.
func ResolvePathsIn(env Env, vaultOverride string) Paths {
	dirs := env.Dirs()
	legacy := env.legacyRoots()
	paths := Paths{
		DataDir:        dirs.Data,
		KnownHostsPath: filepath.Join(env.Home, ".ssh", "known_hosts"),
	}
	if strings.TrimSpace(vaultOverride) != "" {
		paths.VaultPath = expandUserIn(env.Home, vaultOverride)
		paths.VaultOverride = true
	} else {
		paths.VaultPath = paths.resolve("vault", filepath.Join(dirs.Data, DefaultVaultName), legacy.vaultCandidates(), vaultExists)
	}
	paths.KeychainDir = paths.resolve("keychain enrollment", filepath.Join(dirs.Data, KeychainDirName), legacy.keychainCandidates(), dirHasFiles)
	return paths
}

func (p *Paths) resolve(item, current string, legacy []string, exists func(string) bool) string {
	if exists(current) {
		return current
	}
	for _, old := range legacy {
		if samePath(old, current) {
			continue
		}
		if exists(old) {
			p.Legacy = append(p.Legacy, LegacyUse{Item: item, Path: old, NewPath: current})
			return old
		}
	}
	return current
}

// vaultExists reports whether path holds a vault. An empty file is not one:
// a newer run must never hide an older vault behind an empty placeholder.
func vaultExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Size() > 0
}

// dirHasFiles reports whether path is a directory holding at least one file.
func dirHasFiles(path string) bool {
	entries, err := os.ReadDir(path)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			return true
		}
	}
	return false
}

func samePath(left, right string) bool {
	if left == "" || right == "" {
		return false
	}
	left, right = filepath.Clean(left), filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func EnsureLayout(paths Paths) error {
	dir := filepath.Dir(paths.VaultPath)
	if dir == "" || dir == "." {
		return nil
	}
	return os.MkdirAll(dir, 0o700)
}

func ExpandUser(path string) string {
	if path == "" || path[0] != '~' {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return expandUserIn(home, path)
}

func expandUserIn(home, path string) string {
	if path == "" || path[0] != '~' {
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
