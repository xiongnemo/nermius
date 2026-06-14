package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"

	"github.com/nermius/nermius/internal/domain"
	"github.com/nermius/nermius/internal/service"
)

func TestSFTPTabIndexAndFooter(t *testing.T) {
	app := &App{tabs: []domain.DocumentKind{domain.KindHost, domain.KindIdentity}}
	app.setActiveTab(app.sftpTabIndex())
	if !app.inSFTPTab() {
		t.Fatal("expected active SFTP tab")
	}
	if got := app.footerText(); !strings.Contains(got, "Go to HOST") && !strings.Contains(got, "go to HOST") {
		t.Fatalf("empty SFTP footer = %q, want host hint", got)
	}
}

func TestSFTPTogglePaneAndCursorClamp(t *testing.T) {
	app := &App{
		tabs: []domain.DocumentKind{domain.KindHost},
		sftp: &sftpBrowserState{
			activePane:    sftpPaneRemote,
			remoteEntries: makeSFTPTestEntries("b", "a"),
		},
	}
	done, err := app.handleSFTPKey(nil, tcell.NewEventKey(tcell.KeyTAB, 0, tcell.ModNone))
	if done || err != nil {
		t.Fatalf("handleSFTPKey tab = done %v err %v", done, err)
	}
	if app.sftp.activePane != sftpPaneLocal {
		t.Fatalf("active pane = %v, want local", app.sftp.activePane)
	}
	app.sftp.activePane = sftpPaneRemote
	done, err = app.handleSFTPKey(nil, tcell.NewEventKey(tcell.KeyDown, 0, tcell.ModNone))
	if done || err != nil {
		t.Fatalf("handleSFTPKey down = done %v err %v", done, err)
	}
	if app.sftp.remoteCursor != 1 {
		t.Fatalf("remote cursor = %d, want 1", app.sftp.remoteCursor)
	}
	app.moveSFTPCursor(100)
	if app.sftp.remoteCursor != 1 {
		t.Fatalf("remote cursor after clamp = %d, want 1", app.sftp.remoteCursor)
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
