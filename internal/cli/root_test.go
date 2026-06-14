package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nermius/nermius/internal/config"
	"github.com/nermius/nermius/internal/domain"
	"github.com/nermius/nermius/internal/service"
)

func TestParseCLIForwardLocal(t *testing.T) {
	forward, err := parseCLIForward(domain.ForwardLocal, "8080:db.internal:5432")
	if err != nil {
		t.Fatalf("parseCLIForward returned error: %v", err)
	}
	if forward.ListenHost != "127.0.0.1" || forward.ListenPort != 8080 {
		t.Fatalf("unexpected local forward listen side: %+v", forward)
	}
	if forward.TargetHost != "db.internal" || forward.TargetPort != 5432 {
		t.Fatalf("unexpected local forward target side: %+v", forward)
	}
}

func TestParseCLIForwardDynamic(t *testing.T) {
	forward, err := parseCLIForward(domain.ForwardDynamic, "9050")
	if err != nil {
		t.Fatalf("parseCLIForward returned error: %v", err)
	}
	if forward.ListenHost != "127.0.0.1" || forward.ListenPort != 9050 {
		t.Fatalf("unexpected dynamic forward: %+v", forward)
	}
}

func TestJoinExecCommand(t *testing.T) {
	command := joinExecCommand([]string{"bash", "-lc", "echo hello"})
	if command != "bash -lc echo hello" {
		t.Fatalf("unexpected command join result: %q", command)
	}
}

func TestParseKnownHostsBackend(t *testing.T) {
	backend, err := parseKnownHostsBackend("vault+file")
	if err != nil {
		t.Fatalf("parseKnownHostsBackend returned error: %v", err)
	}
	if backend != domain.KnownHostsBackendVaultFile {
		t.Fatalf("expected vault+file backend, got %q", backend)
	}
}

func TestBuildKnownHostsConfig(t *testing.T) {
	cfg, err := buildKnownHostsConfig("strict", "vault", "~/.ssh/known_hosts")
	if err != nil {
		t.Fatalf("buildKnownHostsConfig returned error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected known hosts config")
	}
	if cfg.Policy != domain.KnownHostsStrict || cfg.Backend != domain.KnownHostsBackendVault || cfg.Path != "~/.ssh/known_hosts" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestRootHelpIncludesBuildMetadata(t *testing.T) {
	var out bytes.Buffer
	root := newRootCommand(&runtime{})
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	help := out.String()
	if !bytes.Contains([]byte(help), []byte("Version:")) {
		t.Fatalf("expected help to include version metadata, got:\n%s", help)
	}
	if !bytes.Contains([]byte(help), []byte("Build Time:")) {
		t.Fatalf("expected help to include build time metadata, got:\n%s", help)
	}
	if !bytes.Contains([]byte(help), []byte("version")) {
		t.Fatalf("expected help to list version subcommand, got:\n%s", help)
	}
}

func TestVersionCommandPrintsVersionString(t *testing.T) {
	var out bytes.Buffer
	root := newRootCommand(&runtime{})
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(version) returned error: %v", err)
	}
	if len(bytes.TrimSpace(out.Bytes())) == 0 {
		t.Fatal("expected version command output")
	}
}

func TestHostAddHelpIncludesDirectAuthFlags(t *testing.T) {
	var out bytes.Buffer
	root := newRootCommand(&runtime{})
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"host", "add", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(host add --help) returned error: %v", err)
	}
	help := out.String()
	if !bytes.Contains([]byte(help), []byte("--key")) {
		t.Fatalf("expected host add help to include --key, got:\n%s", help)
	}
	if !bytes.Contains([]byte(help), []byte("--password")) {
		t.Fatalf("expected host add help to include --password, got:\n%s", help)
	}
}

func TestResolveSpecsToIDsSupportsKeyNameAndShortID(t *testing.T) {
	catalog, cleanup := newCLITestCatalog(t)
	defer cleanup()

	key := &domain.Key{
		Name:               "deploy",
		Kind:               domain.KeyKindPrivateKey,
		PrivateKeySecretID: "secret-id",
	}
	if err := catalog.SaveKey(context.Background(), key); err != nil {
		t.Fatalf("SaveKey failed: %v", err)
	}

	ids, err := resolveSpecsToIDs(context.Background(), catalog, domain.KindKey, []string{"deploy", key.ID[:8], key.ID})
	if err != nil {
		t.Fatalf("resolveSpecsToIDs returned error: %v", err)
	}
	if len(ids) != 3 || ids[0] != key.ID || ids[1] != key.ID || ids[2] != key.ID {
		t.Fatalf("unexpected resolved ids: %v", ids)
	}
}

func TestCompletionSuggestsHostDirectKeyFlag(t *testing.T) {
	var out bytes.Buffer
	root := newRootCommand(&runtime{})
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"__complete", "host", "add", "--k"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(__complete host add --k) returned error: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("--key")) {
		t.Fatalf("expected completion to suggest --key, got:\n%s", out.String())
	}
}

func TestCompletionSuggestsWorkspaceCommand(t *testing.T) {
	var out bytes.Buffer
	root := newRootCommand(&runtime{})
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"__complete", "wor"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(__complete wor) returned error: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("workspace")) {
		t.Fatalf("expected completion to suggest workspace, got:\n%s", out.String())
	}
}

func TestVaultHelpShowsKeychainAndMigrateInsteadOfUnlockLock(t *testing.T) {
	var out bytes.Buffer
	root := newRootCommand(&runtime{})
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"vault", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(vault --help) returned error: %v", err)
	}
	help := out.String()
	if !bytes.Contains([]byte(help), []byte("keychain")) {
		t.Fatalf("expected vault help to include keychain, got:\n%s", help)
	}
	if !bytes.Contains([]byte(help), []byte("migrate")) {
		t.Fatalf("expected vault help to include migrate, got:\n%s", help)
	}
	if bytes.Contains([]byte(help), []byte("\n  unlock")) || bytes.Contains([]byte(help), []byte("\n  lock")) {
		t.Fatalf("expected vault help to omit unlock/lock, got:\n%s", help)
	}
}

func TestCompletionSuggestsVaultKeychainSubcommand(t *testing.T) {
	var out bytes.Buffer
	root := newRootCommand(&runtime{})
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"__complete", "vault", "k"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(__complete vault k) returned error: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("keychain")) {
		t.Fatalf("expected completion to suggest keychain, got:\n%s", out.String())
	}
}

func TestVaultKeychainEnableHelpIncludesRequirePresence(t *testing.T) {
	var out bytes.Buffer
	root := newRootCommand(&runtime{})
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"vault", "keychain", "enable", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(vault keychain enable --help) returned error: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("--require-presence")) {
		t.Fatalf("expected help to include --require-presence, got:\n%s", out.String())
	}
}

func TestCompletionSuggestsVaultKeychainRequirePresenceFlag(t *testing.T) {
	var out bytes.Buffer
	root := newRootCommand(&runtime{})
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"__complete", "vault", "keychain", "enable", "--require-p"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(__complete vault keychain enable --require-p) returned error: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("--require-presence")) {
		t.Fatalf("expected completion to suggest --require-presence, got:\n%s", out.String())
	}
}

func TestShouldOfferKeychainFallbackCleanupOnlyAfterPasswordFallback(t *testing.T) {
	if !shouldOfferKeychainFallbackCleanup(service.MasterKeyResolution{
		Source:             service.MasterKeySourcePassword,
		KeychainConfigured: true,
		KeychainError:      errors.New("keychain failed"),
	}) {
		t.Fatal("expected cleanup offer after password fallback from configured keychain failure")
	}
	for name, resolution := range map[string]service.MasterKeyResolution{
		"keychain-source": {
			Source:             service.MasterKeySourceKeychain,
			KeychainConfigured: true,
			KeychainError:      errors.New("ignored"),
		},
		"env-source": {
			Source:             service.MasterKeySourceEnv,
			KeychainConfigured: true,
			KeychainError:      errors.New("ignored"),
		},
		"not-configured": {
			Source:             service.MasterKeySourcePassword,
			KeychainConfigured: false,
			KeychainError:      errors.New("ignored"),
		},
		"no-keychain-error": {
			Source:             service.MasterKeySourcePassword,
			KeychainConfigured: true,
		},
	} {
		if shouldOfferKeychainFallbackCleanup(resolution) {
			t.Fatalf("expected no cleanup offer for %s", name)
		}
	}
}

func TestForwardHelpIncludesStartSubcommand(t *testing.T) {
	var out bytes.Buffer
	root := newRootCommand(&runtime{})
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"forward", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(forward --help) returned error: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("start")) {
		t.Fatalf("expected forward help to include start, got:\n%s", out.String())
	}
}

func TestCompletionSuggestsForwardStartSubcommand(t *testing.T) {
	var out bytes.Buffer
	root := newRootCommand(&runtime{})
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"__complete", "forward", "st"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(__complete forward st) returned error: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("start")) {
		t.Fatalf("expected completion to suggest start, got:\n%s", out.String())
	}
}

func TestTermiusHelpIncludesExportAndImport(t *testing.T) {
	var out bytes.Buffer
	root := newRootCommand(&runtime{})
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"termius", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(termius --help) returned error: %v", err)
	}
	help := out.String()
	if !bytes.Contains([]byte(help), []byte("export")) || !bytes.Contains([]byte(help), []byte("import")) {
		t.Fatalf("expected termius help to include export and import, got:\n%s", help)
	}
	if !bytes.Contains([]byte(help), []byte("Linux and macOS")) {
		t.Fatalf("expected termius help to mention unsupported Linux and macOS local export, got:\n%s", help)
	}
}

func TestCompletionSuggestsTermiusExportSubcommand(t *testing.T) {
	var out bytes.Buffer
	root := newRootCommand(&runtime{})
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"__complete", "termius", "ex"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(__complete termius ex) returned error: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("export")) {
		t.Fatalf("expected completion to suggest export, got:\n%s", out.String())
	}
}

func TestBackendTermixHelpIncludesAddListShow(t *testing.T) {
	var out bytes.Buffer
	root := newRootCommand(&runtime{})
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"backend", "termix", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(backend termix --help) returned error: %v", err)
	}
	help := out.String()
	for _, want := range []string{"add", "list", "show"} {
		if !bytes.Contains([]byte(help), []byte(want)) {
			t.Fatalf("expected backend termix help to include %q, got:\n%s", want, help)
		}
	}
}

func TestCompletionSuggestsBackendTermixSubcommand(t *testing.T) {
	var out bytes.Buffer
	root := newRootCommand(&runtime{})
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"__complete", "backend", "te"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(__complete backend te) returned error: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("termix")) {
		t.Fatalf("expected completion to suggest termix, got:\n%s", out.String())
	}
}

func TestRootHelpIncludesSFTPCommand(t *testing.T) {
	var out bytes.Buffer
	root := newRootCommand(&runtime{})
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(--help) returned error: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("sftp")) {
		t.Fatalf("expected help to include sftp, got:\n%s", out.String())
	}
}

func TestSFTPHelpIncludesTransferCommands(t *testing.T) {
	var out bytes.Buffer
	root := newRootCommand(&runtime{})
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"sftp", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(sftp --help) returned error: %v", err)
	}
	help := out.String()
	for _, want := range []string{"ls", "get", "put", "mkdir", "rm", "rename"} {
		if !bytes.Contains([]byte(help), []byte(want)) {
			t.Fatalf("expected sftp help to include %q, got:\n%s", want, help)
		}
	}
}

func TestCompletionSuggestsSFTPSubcommand(t *testing.T) {
	var out bytes.Buffer
	root := newRootCommand(&runtime{})
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"__complete", "sftp", "g"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(__complete sftp g) returned error: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("get")) {
		t.Fatalf("expected completion to suggest get, got:\n%s", out.String())
	}
}

func TestCompletionSuggestsSFTPForceFlag(t *testing.T) {
	var out bytes.Buffer
	root := newRootCommand(&runtime{})
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"__complete", "sftp", "get", "host:/tmp/file", "local", "--f"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(__complete sftp get --f) returned error: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("--force")) {
		t.Fatalf("expected completion to suggest --force, got:\n%s", out.String())
	}
}

func TestLocalDownloadPreviewDetectsDirectoryTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "app.log")
	destination, exists, err := localDownloadPreview("/var/log/app.log", dir)
	if err != nil {
		t.Fatalf("localDownloadPreview returned error: %v", err)
	}
	if destination != target || exists {
		t.Fatalf("preview = %q exists=%v, want %q false", destination, exists, target)
	}
	if err := os.WriteFile(target, []byte("old"), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	destination, exists, err = localDownloadPreview("/var/log/app.log", dir)
	if err != nil {
		t.Fatalf("localDownloadPreview existing returned error: %v", err)
	}
	if destination != target || !exists {
		t.Fatalf("preview = %q exists=%v, want %q true", destination, exists, target)
	}
}

func TestBackendTermixAddCanCreateProfileWithoutValidation(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "vault.db")
	manager := service.NewVaultManager(config.Paths{
		ConfigDir:      dir,
		CacheDir:       dir,
		VaultPath:      vaultPath,
		SessionPath:    filepath.Join(dir, "session.json"),
		KnownHostsPath: filepath.Join(dir, "known_hosts"),
	})
	if err := manager.Init(context.Background(), "test-password"); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	var out bytes.Buffer
	root := newRootCommand(&runtime{vaultPath: vaultPath})
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{
		"--vault", vaultPath,
		"backend", "termix", "add", "lab",
		"--url", "http://localhost:8080/",
		"--token", "tmx_secret",
		"--profile", "termix-lab",
		"--create-profile",
		"--no-validate",
	})
	t.Setenv("NERMIUS_MASTER_PASSWORD", "test-password")
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(backend termix add) returned error: %v\n%s", err, out.String())
	}

	masterKey, db, err := manager.ResolveMasterKey(context.Background(), func(string) (string, error) {
		return "test-password", nil
	})
	if err != nil {
		t.Fatalf("ResolveMasterKey failed: %v", err)
	}
	defer db.Close()
	catalog := service.NewCatalog(db, masterKey)
	backends, err := catalog.ListBackends(context.Background())
	if err != nil {
		t.Fatalf("ListBackends failed: %v", err)
	}
	if len(backends) != 1 {
		t.Fatalf("expected one backend, got %#v", backends)
	}
	if backends[0].URL != "http://localhost:8080" || backends[0].TokenSecretID == "" || backends[0].TargetProfileRef == "" {
		t.Fatalf("unexpected backend: %#v", backends[0])
	}
	if _, err := catalog.GetProfile(context.Background(), backends[0].TargetProfileRef); err != nil {
		t.Fatalf("expected created profile to exist: %v", err)
	}
}

func newCLITestCatalog(t *testing.T) (*service.Catalog, func()) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.db")
	manager := service.NewVaultManager(config.Paths{
		ConfigDir:      filepath.Dir(path),
		CacheDir:       filepath.Dir(path),
		VaultPath:      path,
		SessionPath:    filepath.Join(filepath.Dir(path), "session.json"),
		KnownHostsPath: filepath.Join(filepath.Dir(path), "known_hosts"),
	})
	db, err := manager.Open(context.Background())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	return service.NewCatalog(db, []byte("01234567890123456789012345678901")), func() {
		_ = db.Close()
	}
}
