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
		t.Fatalf("active tab = %d, want sessions tab %d", app.activeTab, len(app.tabs))
	}
	done, err = app.handleSFTPKey(nil, tcell.NewEventKey(tcell.KeyRight, 0, tcell.ModNone))
	if done || err != nil {
		t.Fatalf("handleSFTPKey right = done %v err %v", done, err)
	}
	if !app.inSFTPTab() {
		t.Fatalf("active tab = %d, want sftp tab %d", app.activeTab, app.sftpTabIndex())
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
