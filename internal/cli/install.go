package cli

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/nermius/nermius/internal/config"
)

type shellKind string

const (
	shellUnknown    shellKind = "unknown"
	shellBash       shellKind = "bash"
	shellZsh        shellKind = "zsh"
	shellFish       shellKind = "fish"
	shellNu         shellKind = "nu"
	shellPowerShell shellKind = "powershell"
	shellCmd        shellKind = "cmd"
)

type fileSignature struct {
	Size   int64
	SHA256 string
	SHA512 string
}

func (s fileSignature) matches(other fileSignature) bool {
	return s.Size == other.Size && s.SHA256 == other.SHA256 && s.SHA512 == other.SHA512
}

func (r *runtime) newInstallCmd() *cobra.Command {
	var installDir string
	var assumeYes bool
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install this executable into a user bin directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInstall(cmd, installDir, assumeYes)
		},
	}
	cmd.Flags().StringVar(&installDir, "dir", "~/.local/bin", "Destination directory for the installed executable")
	cmd.Flags().BoolVarP(&assumeYes, "yes", "y", false, "Assume yes for directory creation and overwrite prompts")
	return cmd
}

func runInstall(cmd *cobra.Command, rawInstallDir string, assumeYes bool) error {
	sourcePath, err := currentExecutablePath()
	if err != nil {
		return err
	}
	binaryName := filepath.Base(sourcePath)
	targetDir := rawInstallDir
	if strings.TrimSpace(targetDir) == "" {
		targetDir = "~/.local/bin"
	}
	targetDir = normalizePath(targetDir)
	targetPath := filepath.Join(targetDir, binaryName)

	stdout := cmd.OutOrStdout()
	fmt.Fprintf(stdout, "Source executable: %s\n", sourcePath)
	fmt.Fprintf(stdout, "Install target: %s\n", targetPath)

	pathEnv := os.Getenv("PATH")
	inPath := pathContainsDir(targetDir, pathEnv)
	if inPath {
		fmt.Fprintf(stdout, "PATH: %s is already in PATH.\n", targetDir)
	} else {
		fmt.Fprintf(stdout, "PATH: %s is not currently in PATH.\n", targetDir)
	}

	proceed, err := ensureInstallDir(stdout, targetDir, assumeYes)
	if err != nil {
		return err
	}
	if !proceed {
		return nil
	}

	copied, proceed, err := installBinary(stdout, sourcePath, targetPath, assumeYes)
	if err != nil {
		return err
	}
	if !proceed {
		return nil
	}
	if copied {
		fmt.Fprintf(stdout, "Installed %s to %s.\n", binaryName, targetPath)
	} else {
		fmt.Fprintf(stdout, "Installed file already matches %s.\n", sourcePath)
	}

	reportCommandAvailability(stdout, targetPath, binaryName, targetDir, pathEnv, inPath)
	return nil
}

func ensureInstallDir(stdout io.Writer, targetDir string, assumeYes bool) (bool, error) {
	info, err := os.Stat(targetDir)
	if err == nil {
		if !info.IsDir() {
			return false, fmt.Errorf("%s exists but is not a directory", targetDir)
		}
		return true, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	approved, err := confirmInstallAction(
		assumeYes,
		fmt.Sprintf("Install directory %s does not exist. Create it", targetDir),
	)
	if err != nil {
		return false, err
	}
	if !approved {
		fmt.Fprintln(stdout, "Installation cancelled; target directory was not created.")
		return false, nil
	}
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return false, err
	}
	fmt.Fprintf(stdout, "Created %s.\n", targetDir)
	return true, nil
}

func installBinary(stdout io.Writer, sourcePath, targetPath string, assumeYes bool) (bool, bool, error) {
	if samePath(sourcePath, targetPath) {
		return false, true, nil
	}
	_, err := os.Stat(targetPath)
	if errors.Is(err, os.ErrNotExist) {
		return true, true, copyExecutable(sourcePath, targetPath)
	}
	if err != nil {
		return false, false, err
	}

	sourceSig, err := readFileSignature(sourcePath)
	if err != nil {
		return false, false, err
	}
	targetSig, err := readFileSignature(targetPath)
	if err != nil {
		return false, false, err
	}
	if sourceSig.matches(targetSig) {
		return false, true, nil
	}

	approved, err := confirmInstallAction(
		assumeYes,
		fmt.Sprintf(
			"Existing install at %s differs from the current executable.\nCurrent: size=%d sha256=%s\nInstalled: size=%d sha256=%s\nOverwrite it",
			targetPath,
			sourceSig.Size,
			sourceSig.SHA256,
			targetSig.Size,
			targetSig.SHA256,
		),
	)
	if err != nil {
		return false, false, err
	}
	if !approved {
		fmt.Fprintln(stdout, "Installation cancelled; existing executable was left untouched.")
		return false, false, nil
	}
	return true, true, copyExecutable(sourcePath, targetPath)
}

func confirmInstallAction(assumeYes bool, label string) (bool, error) {
	if assumeYes {
		return true, nil
	}
	return promptConfirm(label)
}

func reportCommandAvailability(stdout io.Writer, targetPath, binaryName, targetDir, pathEnv string, inPath bool) {
	shell := detectShell()
	fmt.Fprintf(stdout, "Detected shell: %s\n", shell)

	for _, commandName := range installCommandNames(binaryName) {
		resolvedPath, ok := findExecutableInPath(goruntime.GOOS, commandName, pathEnv, os.Getenv("PATHEXT"))
		if !ok {
			continue
		}
		if samePath(resolvedPath, targetPath) {
			fmt.Fprintf(stdout, "You can invoke it directly as `%s`.\n", commandName)
			return
		}
		fmt.Fprintf(stdout, "Command `%s` currently resolves to %s, not %s.\n", commandName, resolvedPath, targetPath)
		fmt.Fprintln(stdout, "Another executable is earlier in PATH.")
		if inPath {
			fmt.Fprintf(stdout, "Move %s earlier in PATH or invoke %s explicitly.\n", targetDir, targetPath)
		} else {
			printPathHint(stdout, shell, targetDir)
		}
		return
	}

	fmt.Fprintf(stdout, "The installed executable is not currently reachable as `%s` from PATH.\n", installCommandNames(binaryName)[0])
	if inPath {
		fmt.Fprintln(stdout, "The directory is already in PATH. Start a new shell and try again.")
		return
	}
	printPathHint(stdout, shell, targetDir)
}

func currentExecutablePath() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	return filepath.Abs(path)
}

func copyExecutable(sourcePath, targetPath string) error {
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()

	info, err := source.Stat()
	if err != nil {
		return err
	}
	mode := info.Mode()
	if mode.Perm() == 0 {
		mode = 0o755
	}

	temp, err := os.CreateTemp(filepath.Dir(targetPath), filepath.Base(targetPath)+".*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer func() {
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}()

	if _, err := io.Copy(temp, source); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tempPath, mode); err != nil && goruntime.GOOS != "windows" {
		return err
	}
	if err := os.Remove(targetPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(tempPath, targetPath)
}

func readFileSignature(path string) (fileSignature, error) {
	file, err := os.Open(path)
	if err != nil {
		return fileSignature{}, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return fileSignature{}, err
	}

	hash256 := sha256.New()
	hash512 := sha512.New()
	if _, err := io.Copy(io.MultiWriter(hash256, hash512), file); err != nil {
		return fileSignature{}, err
	}
	return fileSignature{
		Size:   info.Size(),
		SHA256: hex.EncodeToString(hash256.Sum(nil)),
		SHA512: hex.EncodeToString(hash512.Sum(nil)),
	}, nil
}

func pathContainsDir(targetDir, pathEnv string) bool {
	target := normalizePath(targetDir)
	if target == "" {
		return false
	}
	for _, entry := range filepath.SplitList(pathEnv) {
		if samePath(target, entry) {
			return true
		}
	}
	return false
}

func installCommandNames(binaryName string) []string {
	names := []string{}
	appendUnique := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		for _, existing := range names {
			if strings.EqualFold(existing, value) {
				return
			}
		}
		names = append(names, value)
	}
	appendUnique(strings.TrimSuffix(binaryName, filepath.Ext(binaryName)))
	appendUnique(binaryName)
	return names
}

func findExecutableInPath(goos, commandName, pathEnv, pathExt string) (string, bool) {
	candidates := executableCandidates(goos, commandName, pathExt)
	for _, dir := range filepath.SplitList(pathEnv) {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		for _, candidate := range candidates {
			fullPath := filepath.Join(dir, candidate)
			info, err := os.Stat(fullPath)
			if err == nil && !info.IsDir() {
				return normalizePath(fullPath), true
			}
		}
	}
	return "", false
}

func executableCandidates(goos, commandName, pathExt string) []string {
	if goos != "windows" || filepath.Ext(commandName) != "" {
		return []string{commandName}
	}
	exts := strings.Split(pathExt, ";")
	if len(exts) == 0 || strings.TrimSpace(pathExt) == "" {
		exts = []string{".COM", ".EXE", ".BAT", ".CMD"}
	}
	out := make([]string, 0, len(exts)+1)
	out = append(out, commandName)
	for _, ext := range exts {
		ext = strings.TrimSpace(ext)
		if ext == "" {
			continue
		}
		out = append(out, commandName+strings.ToLower(ext))
		out = append(out, commandName+strings.ToUpper(ext))
	}
	return out
}

func detectShell() shellKind {
	return detectShellFromEnv(goruntime.GOOS, os.Getenv)
}

func detectShellFromEnv(goos string, getenv func(string) string) shellKind {
	switch {
	case strings.TrimSpace(getenv("NU_VERSION")) != "":
		return shellNu
	case strings.TrimSpace(getenv("FISH_VERSION")) != "":
		return shellFish
	}
	if shell := strings.ToLower(filepath.Base(getenv("SHELL"))); shell != "" {
		switch {
		case strings.Contains(shell, "pwsh"), strings.Contains(shell, "powershell"):
			return shellPowerShell
		case strings.Contains(shell, "zsh"):
			return shellZsh
		case strings.Contains(shell, "bash"):
			return shellBash
		case strings.Contains(shell, "fish"):
			return shellFish
		case strings.Contains(shell, "nu"):
			return shellNu
		}
	}
	if goos == "windows" {
		if shell := strings.ToLower(filepath.Base(getenv("COMSPEC"))); strings.Contains(shell, "pwsh") || strings.Contains(shell, "powershell") {
			return shellPowerShell
		}
		if strings.TrimSpace(getenv("PSModulePath")) != "" || strings.TrimSpace(getenv("POWERSHELL_DISTRIBUTION_CHANNEL")) != "" {
			return shellPowerShell
		}
		return shellCmd
	}
	return shellUnknown
}

func printPathHint(stdout io.Writer, shell shellKind, targetDir string) {
	hint := pathSetupHint(shell, targetDir)
	if hint == "" {
		fmt.Fprintf(stdout, "Add %s to PATH in your shell startup config, then start a new shell.\n", targetDir)
		return
	}
	fmt.Fprintln(stdout, "Add the install directory to PATH, then start a new shell:")
	fmt.Fprintln(stdout, hint)
}

func pathSetupHint(shell shellKind, targetDir string) string {
	displayPath := displayInstallPath(targetDir)
	switch shell {
	case shellPowerShell:
		return fmt.Sprintf(
			"  $env:Path += \";%s\"\n  [Environment]::SetEnvironmentVariable(\"Path\", [Environment]::GetEnvironmentVariable(\"Path\", \"User\") + \";%s\", \"User\")",
			targetDir,
			targetDir,
		)
	case shellCmd:
		return fmt.Sprintf("  set PATH=%%PATH%%;%s", targetDir)
	case shellFish:
		return fmt.Sprintf("  fish_add_path %s", displayPath)
	case shellZsh:
		return fmt.Sprintf("  echo 'export PATH=\"%s:$PATH\"' >> ~/.zshrc", displayPath)
	case shellBash:
		return fmt.Sprintf("  echo 'export PATH=\"%s:$PATH\"' >> ~/.bashrc", displayPath)
	case shellNu:
		return fmt.Sprintf("  $env.PATH = ($env.PATH | prepend '%s')", displayPath)
	default:
		return ""
	}
}

func displayInstallPath(path string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	normalizedHome := normalizePath(home)
	normalizedPath := normalizePath(path)
	if normalizedHome == "" || normalizedPath == "" {
		return path
	}
	if samePath(normalizedPath, normalizedHome) {
		return "~"
	}
	prefix := normalizedHome + string(os.PathSeparator)
	matchesPrefix := strings.HasPrefix(normalizedPath, prefix)
	if goruntime.GOOS == "windows" {
		matchesPrefix = strings.HasPrefix(strings.ToLower(normalizedPath), strings.ToLower(prefix))
	}
	if !matchesPrefix {
		return path
	}
	return "~" + string(os.PathSeparator) + strings.TrimPrefix(normalizedPath, prefix)
}

func normalizePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	path = config.ExpandUser(path)
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	if absolute, err := filepath.Abs(path); err == nil {
		path = absolute
	}
	return filepath.Clean(path)
}

func samePath(left, right string) bool {
	left = normalizePath(left)
	right = normalizePath(right)
	if left == "" || right == "" {
		return false
	}
	if goruntime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}
