package tui

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/gdamore/tcell/v2"

	"github.com/nermius/nermius/internal/config"
	"github.com/nermius/nermius/internal/domain"
	"github.com/nermius/nermius/internal/service"
	"github.com/nermius/nermius/internal/store"
)

func TestHandleKeyEnterOnNonHostOpensDetailModal(t *testing.T) {
	app, cleanup := newTestAppWithCatalog(t)
	defer cleanup()

	group := &domain.Group{Name: "ops"}
	if err := app.catalog.SaveGroup(context.Background(), group); err != nil {
		t.Fatalf("SaveGroup failed: %v", err)
	}
	app.tabs = []domain.DocumentKind{domain.KindGroup}
	app.records[domain.KindGroup] = []store.DocumentSummary{{
		ID:    group.ID,
		Kind:  string(domain.KindGroup),
		Label: group.Label(),
	}}

	done, err := app.handleKey(context.Background(), tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone))
	if err != nil {
		t.Fatalf("handleKey returned error: %v", err)
	}
	if done {
		t.Fatal("handleKey unexpectedly requested exit")
	}
	top := app.topModal()
	if top == nil || top.kind != modalKindDetail || top.detail == nil {
		t.Fatal("expected Enter on non-host tab to open a detail modal")
	}
	if top.detail.kind != domain.KindGroup || top.detail.id != group.ID {
		t.Fatalf("unexpected detail target: kind=%v id=%q", top.detail.kind, top.detail.id)
	}
}

func TestOpenDeleteConfirmBlocksReferencedObject(t *testing.T) {
	app, cleanup := newTestAppWithCatalog(t)
	defer cleanup()

	group := &domain.Group{Name: "ops"}
	if err := app.catalog.SaveGroup(context.Background(), group); err != nil {
		t.Fatalf("SaveGroup failed: %v", err)
	}
	host := &domain.Host{
		Title:    "prod",
		Hostname: "prod.example.com",
		GroupIDs: []string{group.ID},
	}
	if err := app.catalog.SaveHost(context.Background(), host); err != nil {
		t.Fatalf("SaveHost failed: %v", err)
	}

	app.tabs = []domain.DocumentKind{domain.KindGroup}
	app.records[domain.KindGroup] = []store.DocumentSummary{{
		ID:    group.ID,
		Kind:  string(domain.KindGroup),
		Label: group.Label(),
	}}

	if err := app.openDeleteConfirm(context.Background()); err != nil {
		t.Fatalf("openDeleteConfirm returned error: %v", err)
	}
	top := app.topModal()
	if top == nil || top.kind != modalKindDetail || top.detail == nil {
		t.Fatal("expected delete of referenced object to open a blocking detail modal")
	}
	if top.detail.title != "Delete blocked" {
		t.Fatalf("unexpected modal title %q", top.detail.title)
	}
	if len(top.detail.lines) == 0 {
		t.Fatal("expected delete blocked modal to describe references")
	}
}

func newTestAppWithCatalog(t *testing.T) (*App, func()) {
	t.Helper()
	paths := testPaths(t)
	manager := service.NewVaultManager(paths)
	db, err := manager.Open(context.Background())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	app := &App{
		catalog:  service.NewCatalog(db, []byte("01234567890123456789012345678901")),
		paths:    paths,
		tabs:     []domain.DocumentKind{domain.KindHost, domain.KindGroup, domain.KindProfile, domain.KindIdentity, domain.KindKey, domain.KindForward, domain.KindKnownHost},
		records:  map[domain.DocumentKind][]store.DocumentSummary{},
		filters:  map[domain.DocumentKind]string{},
		modals:   nil,
		sessions: nil,
	}
	return app, func() {
		_ = db.Close()
	}
}

func testPaths(t *testing.T) config.Paths {
	t.Helper()
	dir := t.TempDir()
	return config.Paths{
		ConfigDir:      dir,
		CacheDir:       dir,
		VaultPath:      filepath.Join(dir, "vault.db"),
		SessionPath:    filepath.Join(dir, "session.json"),
		KnownHostsPath: filepath.Join(dir, "known_hosts"),
	}
}
