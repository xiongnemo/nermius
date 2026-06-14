package tui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"

	"github.com/nermius/nermius/internal/domain"
	"github.com/nermius/nermius/internal/service"
	"github.com/nermius/nermius/internal/store"
)

func TestSFTPTabIndexAndFooter(t *testing.T) {
	app := &App{tabs: []domain.DocumentKind{domain.KindHost, domain.KindIdentity}}
	app.setActiveTab(app.sftpTabIndex())
	if !app.inSFTPTab() {
		t.Fatal("expected active SFTP tab")
	}
	if got := app.footerText(); !strings.Contains(got, "HOST") {
		t.Fatalf("empty SFTP footer = %q, want host hint", got)
	}
}

func TestSFTPTogglePaneAndCursorClamp(t *testing.T) {
	app := &App{
		tabs: []domain.DocumentKind{domain.KindHost},
		sftp: &sftpBrowserState{
			activePane: sftpPaneRight,
			panes: [sftpPaneCount]sftpPaneState{
				sftpPaneRight: {kind: sftpPaneRemote, entries: makeSFTPTestEntries("b", "a")},
			},
		},
	}
	done, err := app.handleSFTPKey(nil, tcell.NewEventKey(tcell.KeyTAB, 0, tcell.ModNone))
	if done || err != nil {
		t.Fatalf("handleSFTPKey tab = done %v err %v", done, err)
	}
	if app.sftp.activePane != sftpPaneLeft {
		t.Fatalf("active pane = %v, want left", app.sftp.activePane)
	}
	app.sftp.activePane = sftpPaneRight
	done, err = app.handleSFTPKey(nil, tcell.NewEventKey(tcell.KeyDown, 0, tcell.ModNone))
	if done || err != nil {
		t.Fatalf("handleSFTPKey down = done %v err %v", done, err)
	}
	if app.sftp.panes[sftpPaneRight].cursor != 1 {
		t.Fatalf("remote cursor = %d, want 1", app.sftp.panes[sftpPaneRight].cursor)
	}
	app.moveSFTPCursor(100)
	if app.sftp.panes[sftpPaneRight].cursor != 1 {
		t.Fatalf("remote cursor after clamp = %d, want 1", app.sftp.panes[sftpPaneRight].cursor)
	}
}

func TestSFTPCursorWrapsAroundEntries(t *testing.T) {
	app := &App{
		sftp: &sftpBrowserState{
			activePane: sftpPaneRight,
			panes: [sftpPaneCount]sftpPaneState{
				sftpPaneRight: {kind: sftpPaneRemote, entries: makeSFTPTestEntries("a", "b", "c")},
			},
		},
	}
	app.moveSFTPCursor(-1)
	if app.sftp.panes[sftpPaneRight].cursor != 2 {
		t.Fatalf("cursor after moving above top = %d, want 2", app.sftp.panes[sftpPaneRight].cursor)
	}
	app.moveSFTPCursor(1)
	if app.sftp.panes[sftpPaneRight].cursor != 0 {
		t.Fatalf("cursor after moving below bottom = %d, want 0", app.sftp.panes[sftpPaneRight].cursor)
	}
	app.moveSFTPCursor(4)
	if app.sftp.panes[sftpPaneRight].cursor != 1 {
		t.Fatalf("cursor after page delta = %d, want 1", app.sftp.panes[sftpPaneRight].cursor)
	}
}

func TestSFTPPaneScrollFollowsCursor(t *testing.T) {
	pane := &sftpPaneState{
		kind:    sftpPaneRemote,
		entries: makeSFTPTestEntries("00", "01", "02", "03", "04", "05", "06", "07", "08", "09"),
		cursor:  8,
	}
	ensureSFTPCursorVisible(pane, 4)
	if pane.scroll != 5 {
		t.Fatalf("scroll = %d, want 5", pane.scroll)
	}
	pane.cursor = 2
	ensureSFTPCursorVisible(pane, 4)
	if pane.scroll != 2 {
		t.Fatalf("scroll after moving above viewport = %d, want 2", pane.scroll)
	}
	pane.cursor = 99
	pane.scroll = 99
	pane.entries = makeSFTPTestEntries("only")
	ensureSFTPCursorVisible(pane, 4)
	if pane.cursor != 0 || pane.scroll != 0 {
		t.Fatalf("short list cursor/scroll = %d/%d, want 0/0", pane.cursor, pane.scroll)
	}
	pane = &sftpPaneState{
		kind:    sftpPaneRemote,
		entries: makeSFTPTestEntries("00", "01", "02", "03"),
		cursor:  2,
		scroll:  1,
	}
	ensureSFTPCursorVisible(pane, 0)
	if pane.cursor != 2 || pane.scroll != 1 {
		t.Fatalf("zero rows cursor/scroll = %d/%d, want 2/1", pane.cursor, pane.scroll)
	}
}

func TestFindSFTPEntrySearchesFromNextEntryAndWraps(t *testing.T) {
	pane := &sftpPaneState{
		kind:    sftpPaneRemote,
		entries: makeSFTPTestEntries("alpha.log", "beta.txt", "gamma.log"),
		cursor:  2,
	}
	index, ok := findSFTPEntry(pane, "LOG")
	if !ok || index != 0 {
		t.Fatalf("find log = %d/%v, want 0/true", index, ok)
	}
	pane.cursor = index
	index, ok = findSFTPEntry(pane, "log")
	if !ok || index != 2 {
		t.Fatalf("find next log = %d/%v, want 2/true", index, ok)
	}
	if _, ok := findSFTPEntry(pane, "missing"); ok {
		t.Fatal("expected missing search to fail")
	}
}

func TestSFTPSlashOpensSearchPrompt(t *testing.T) {
	app := &App{
		sftp: &sftpBrowserState{
			activePane: sftpPaneRight,
			panes: [sftpPaneCount]sftpPaneState{
				sftpPaneRight: {kind: sftpPaneRemote, entries: makeSFTPTestEntries("alpha", "beta")},
			},
		},
	}
	done, err := app.handleSFTPKey(context.Background(), tcell.NewEventKey(tcell.KeyRune, '/', tcell.ModNone))
	if done || err != nil {
		t.Fatalf("handleSFTPKey slash = done %v err %v", done, err)
	}
	if !app.hasModal() {
		t.Fatal("expected search prompt modal")
	}
	top := app.topModal()
	if top == nil || top.kind != modalKindTextInput || top.textInput == nil || top.textInput.title != "Search SFTP entry" {
		t.Fatalf("top modal = %+v, want search text input", top)
	}
	top.textInput.onSave(app, "beta")
	if app.sftp.panes[sftpPaneRight].cursor != 1 {
		t.Fatalf("cursor after search = %d, want 1", app.sftp.panes[sftpPaneRight].cursor)
	}
}

func TestRenderSFTPPaneUsesScrollOffset(t *testing.T) {
	screen := tcell.NewSimulationScreen("")
	if err := screen.Init(); err != nil {
		t.Fatalf("screen init failed: %v", err)
	}
	defer screen.Fini()
	screen.SetSize(80, 8)
	app := &App{
		screen: screen,
		sftp: &sftpBrowserState{
			activePane: sftpPaneRight,
			panes: [sftpPaneCount]sftpPaneState{
				sftpPaneRight: {
					kind:    sftpPaneRemote,
					entries: makeSFTPTestEntries("00", "01", "02", "03", "04", "05", "06", "07"),
					cursor:  6,
				},
			},
		},
	}
	app.renderSFTPPane(0, 40, 8, sftpPaneRight)
	if app.sftp.panes[sftpPaneRight].scroll != 2 {
		t.Fatalf("render scroll = %d, want 2", app.sftp.panes[sftpPaneRight].scroll)
	}
	if got := simulationScreenText(screen, 0, 2, 40); !strings.Contains(got, "02") {
		t.Fatalf("first visible row = %q, want entry 02", got)
	}
	if got := simulationScreenText(screen, 0, 6, 40); !strings.Contains(got, "06") {
		t.Fatalf("selected visible row = %q, want entry 06", got)
	}
}

func TestSFTPMouseClickUsesScrollOffset(t *testing.T) {
	screen := tcell.NewSimulationScreen("")
	if err := screen.Init(); err != nil {
		t.Fatalf("screen init failed: %v", err)
	}
	defer screen.Fini()
	screen.SetSize(80, 8)
	app := &App{
		screen: screen,
		sftp: &sftpBrowserState{
			activePane: sftpPaneLeft,
			panes: [sftpPaneCount]sftpPaneState{
				sftpPaneRight: {
					kind:    sftpPaneRemote,
					entries: makeSFTPTestEntries("00", "01", "02", "03", "04", "05", "06", "07"),
					scroll:  3,
				},
			},
		},
	}
	app.handleSFTPMouse(context.Background(), tcell.NewEventMouse(50, 4, tcell.Button1, tcell.ModNone), tcell.ButtonNone)
	if app.sftp.activePane != sftpPaneRight {
		t.Fatalf("active pane = %v, want right", app.sftp.activePane)
	}
	if app.sftp.panes[sftpPaneRight].cursor != 5 {
		t.Fatalf("cursor = %d, want 5", app.sftp.panes[sftpPaneRight].cursor)
	}
}

func TestSFTPLeftRightKeysNavigateTabs(t *testing.T) {
	app := &App{
		tabs: []domain.DocumentKind{domain.KindHost, domain.KindIdentity},
		sftp: &sftpBrowserState{},
	}
	app.setActiveTab(app.sftpTabIndex())
	done, err := app.handleSFTPKey(nil, tcell.NewEventKey(tcell.KeyLeft, 0, tcell.ModNone))
	if done || err != nil {
		t.Fatalf("handleSFTPKey left = done %v err %v", done, err)
	}
	if !app.inSessionTab() {
		t.Fatalf("active tab = %d, want workspace tab %d", app.activeTab, len(app.tabs))
	}
	done, err = app.handleSFTPKey(nil, tcell.NewEventKey(tcell.KeyRight, 0, tcell.ModNone))
	if done || err != nil {
		t.Fatalf("handleSFTPKey right = done %v err %v", done, err)
	}
	if !app.inSFTPTab() {
		t.Fatalf("active tab = %d, want sftp tab %d", app.activeTab, app.sftpTabIndex())
	}
}

func TestSFTPQuitConfirmsRemotePane(t *testing.T) {
	app := &App{
		tabs:      []domain.DocumentKind{domain.KindHost},
		activeTab: 2,
		sftp: &sftpBrowserState{
			activePane: sftpPaneRight,
			panes: [sftpPaneCount]sftpPaneState{
				sftpPaneRight: {kind: sftpPaneRemote, hostLabel: "prod"},
			},
		},
	}
	done, err := app.handleSFTPKey(context.Background(), tcell.NewEventKey(tcell.KeyRune, 'q', tcell.ModNone))
	if done || err != nil {
		t.Fatalf("handleSFTPKey q = done %v err %v", done, err)
	}
	if app.exitRequested {
		t.Fatal("expected remote SFTP pane to require quit confirmation")
	}
	if !app.hasModal() {
		t.Fatal("expected quit confirmation modal")
	}
}

func TestSFTPEmptyPaneCanBecomeLocal(t *testing.T) {
	app := &App{
		tabs: []domain.DocumentKind{domain.KindHost},
		sftp: &sftpBrowserState{activePane: sftpPaneLeft},
	}
	done, err := app.handleSFTPKey(context.Background(), tcell.NewEventKey(tcell.KeyRune, 'l', tcell.ModNone))
	if done || err != nil {
		t.Fatalf("handleSFTPKey l = done %v err %v", done, err)
	}
	if got := app.sftp.panes[sftpPaneLeft].kind; got != sftpPaneLocal {
		t.Fatalf("left pane kind = %q, want local", got)
	}
}

func TestAssignSelectedHostToSFTPPaneOpensConfirmForConfiguredPane(t *testing.T) {
	app := &App{
		tabs:      []domain.DocumentKind{domain.KindHost},
		activeTab: 0,
		cursor:    0,
		records: map[domain.DocumentKind][]store.DocumentSummary{
			domain.KindHost: {{ID: "host-1", Label: "prod"}},
		},
		sftp: &sftpBrowserState{
			panes: [sftpPaneCount]sftpPaneState{
				sftpPaneLeft: {kind: sftpPaneLocal, path: "."},
			},
		},
	}
	if err := app.assignSelectedHostToSFTPPane(context.Background(), sftpPaneLeft); err != nil {
		t.Fatalf("assignSelectedHostToSFTPPane returned error: %v", err)
	}
	if !app.hasModal() {
		t.Fatal("expected replacement confirmation modal")
	}
}

func TestHostBracketKeysAssignSFTPPane(t *testing.T) {
	app := &App{
		tabs:      []domain.DocumentKind{domain.KindHost},
		activeTab: 0,
		cursor:    0,
		records: map[domain.DocumentKind][]store.DocumentSummary{
			domain.KindHost: {{ID: "host-1", Label: "prod"}},
		},
		sftp: &sftpBrowserState{
			panes: [sftpPaneCount]sftpPaneState{
				sftpPaneLeft: {kind: sftpPaneLocal, path: "."},
			},
		},
	}
	done, err := app.handleKey(context.Background(), tcell.NewEventKey(tcell.KeyRune, '[', tcell.ModNone))
	if done || err != nil {
		t.Fatalf("handleKey [ = done %v err %v", done, err)
	}
	if !app.hasModal() {
		t.Fatal("expected replacement confirmation modal")
	}
}

func TestSFTPUploadDownloadRequireLocalRemotePair(t *testing.T) {
	app := &App{
		sftp: &sftpBrowserState{
			activePane: sftpPaneLeft,
			panes: [sftpPaneCount]sftpPaneState{
				sftpPaneLeft:  {kind: sftpPaneLocal, path: "."},
				sftpPaneRight: {kind: sftpPaneLocal, path: "."},
			},
		},
	}
	app.startSFTPUpload(context.Background())
	if !strings.Contains(app.status, "not supported") {
		t.Fatalf("upload status = %q, want unsupported message", app.status)
	}
	app.status = ""
	app.startSFTPDownload(context.Background())
	if !strings.Contains(app.status, "not supported") {
		t.Fatalf("download status = %q, want unsupported message", app.status)
	}
}

func TestReadLocalSFTPEntriesSortsDirectoriesFirst(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "z.txt"), []byte("z"), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "a-dir"), 0700); err != nil {
		t.Fatalf("Mkdir failed: %v", err)
	}
	entries, err := readLocalSFTPEntries(dir)
	if err != nil {
		t.Fatalf("readLocalSFTPEntries returned error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries len = %d, want 2", len(entries))
	}
	if !entries[0].IsDir || entries[0].Name != "a-dir" {
		t.Fatalf("first entry = %+v, want a-dir directory", entries[0])
	}
}

func makeSFTPTestEntries(names ...string) []service.SFTPEntry {
	entries := make([]service.SFTPEntry, 0, len(names))
	for _, name := range names {
		entries = append(entries, service.SFTPEntry{Name: name, Path: name})
	}
	return entries
}

func simulationScreenText(screen tcell.SimulationScreen, x, y, width int) string {
	var builder strings.Builder
	for col := 0; col < width; col++ {
		mainc, _, _, _ := screen.GetContent(x+col, y)
		builder.WriteRune(mainc)
	}
	return builder.String()
}
