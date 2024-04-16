package cli

import (
	"testing"

	"github.com/nermius/nermius/internal/domain"
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
