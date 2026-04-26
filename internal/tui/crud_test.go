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

func TestPromptConfirmModalUsesTUIScreenEvents(t *testing.T) {
	app, cleanup := newTestAppWithCatalog(t)
	defer cleanup()
	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatalf("screen init failed: %v", err)
	}
	defer screen.Fini()
	app.screen = screen
	app.events = make(chan tcell.Event, 4)
	app.events <- tcell.NewEventKey(tcell.KeyRune, 'y', tcell.ModNone)

	approved, err := app.promptConfirmModal(context.Background(), "Trust this host and add it to vault?")
	if err != nil {
		t.Fatalf("promptConfirmModal returned error: %v", err)
	}
	if !approved {
		t.Fatal("expected prompt to be approved")
	}
	if app.hasModal() {
		t.Fatal("expected prompt modal to close")
	}
}

func TestPromptTextModalUsesTUIScreenEvents(t *testing.T) {
	app, cleanup := newTestAppWithCatalog(t)
	defer cleanup()
	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatalf("screen init failed: %v", err)
	}
	defer screen.Fini()
	app.screen = screen
	app.events = make(chan tcell.Event, 4)
	app.events <- tcell.NewEventKey(tcell.KeyRune, 'n', tcell.ModNone)
	app.events <- tcell.NewEventKey(tcell.KeyRune, 'e', tcell.ModNone)
	app.events <- tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone)

	value, err := app.promptTextModal(context.Background(), "Username", false)
	if err != nil {
		t.Fatalf("promptTextModal returned error: %v", err)
	}
	if value != "ne" {
		t.Fatalf("expected input %q, got %q", "ne", value)
	}
	if app.hasModal() {
		t.Fatal("expected prompt modal to close")
	}
}

func TestNewForwardFormDefaultsToLocalWithTargetFields(t *testing.T) {
	app, cleanup := newTestAppWithCatalog(t)
	defer cleanup()

	form, err := app.buildForwardForm(context.Background(), "", true)
	if err != nil {
		t.Fatalf("buildForwardForm returned error: %v", err)
	}
	typeField := formFieldByKey(form, "type")
	if typeField == nil || typeField.value != string(domain.ForwardLocal) {
		t.Fatalf("expected new forward type to default to local, got %#v", typeField)
	}
	listenHost := formFieldByKey(form, "listen_host")
	if listenHost == nil || listenHost.value != "127.0.0.1" {
		t.Fatalf("expected listen host default 127.0.0.1, got %#v", listenHost)
	}
	targetHost := formFieldByKey(form, "target_host")
	if targetHost == nil || targetHost.visible == nil || !targetHost.visible(form) {
		t.Fatal("expected target host to be visible for default local forward")
	}
	hostRef := formFieldByKey(form, "host_ref")
	if hostRef == nil || hostRef.kind != fieldKindSingleRef || hostRef.refKind != domain.KindHost || !hostRef.required {
		t.Fatalf("expected required host picker field, got %#v", hostRef)
	}
}

func TestForwardRecordLabelIncludesRuntimeState(t *testing.T) {
	app := &App{
		runningForwards: map[string]*service.RunningForward{
			"forward-running": {},
		},
		forwardErrors: map[string]string{
			"forward-error": "listen failed",
		},
	}
	if got := app.displayRecordLabel(domain.KindForward, store.DocumentSummary{ID: "forward-running", Label: "db"}); got != "[running] db" {
		t.Fatalf("running label = %q", got)
	}
	if got := app.displayRecordLabel(domain.KindForward, store.DocumentSummary{ID: "forward-error", Label: "api"}); got != "[error] api" {
		t.Fatalf("error label = %q", got)
	}
	if got := app.displayRecordLabel(domain.KindForward, store.DocumentSummary{ID: "forward-stopped", Label: "socks"}); got != "[stopped] socks" {
		t.Fatalf("stopped label = %q", got)
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
