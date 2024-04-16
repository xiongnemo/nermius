package service

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/nermius/nermius/internal/domain"
)

func TestListAndDeleteKnownHostsEntriesAcrossSources(t *testing.T) {
	ctx := context.Background()
	catalog, cleanup := newTestCatalog(t)
	defer cleanup()

	pub := mustPublicKey(t)
	filePath := filepath.Join(t.TempDir(), "known_hosts")

	if err := catalog.SaveKnownHost(ctx, &domain.KnownHost{
		Hosts:     []string{"vault.example"},
		Algorithm: pub.Type(),
		PublicKey: string(ssh.MarshalAuthorizedKey(pub)),
	}); err != nil {
		t.Fatalf("SaveKnownHost failed: %v", err)
	}
	if err := appendKnownHost(filePath, "file.example:22", &net.TCPAddr{IP: net.ParseIP("192.0.2.21"), Port: 22}, pub); err != nil {
		t.Fatalf("appendKnownHost failed: %v", err)
	}

	items, err := ListKnownHostsEntries(ctx, catalog, filePath, "all")
	if err != nil {
		t.Fatalf("ListKnownHostsEntries failed: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 known host entries, got %d", len(items))
	}

	deleted, err := DeleteKnownHostsEntries(ctx, catalog, filePath, "vault.example", "vault")
	if err != nil {
		t.Fatalf("DeleteKnownHostsEntries(vault) failed: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected 1 vault entry deleted, got %d", deleted)
	}

	deleted, err = DeleteKnownHostsEntries(ctx, catalog, filePath, "file.example", "file")
	if err != nil {
		t.Fatalf("DeleteKnownHostsEntries(file) failed: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected 1 file entry deleted, got %d", deleted)
	}

	items, err = ListKnownHostsEntries(ctx, catalog, filePath, "all")
	if err != nil {
		t.Fatalf("ListKnownHostsEntries after delete failed: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected no known host entries after delete, got %d", len(items))
	}
}
