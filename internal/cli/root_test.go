package cli

import (
	"bytes"
	"context"
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
