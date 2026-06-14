package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gdamore/tcell/v2"

	"github.com/nermius/nermius/internal/domain"
	"github.com/nermius/nermius/internal/service"
)

type sftpPane int

const (
	sftpPaneLocal sftpPane = iota
	sftpPaneRemote
)

type sftpBrowserState struct {
	hostID    string
	hostLabel string
	session   *service.SFTPSession

	localPath  string
	remotePath string

	localEntries  []service.SFTPEntry
	remoteEntries []service.SFTPEntry

	localCursor  int
	remoteCursor int
	activePane   sftpPane

	transfer *sftpTransferState
}

type sftpTransferState struct {
	message string
	done    chan sftpTransferResult
}

type sftpTransferResult struct {
	message string
	err     error
}

func newSFTPBrowserState(hostID, hostLabel string, session *service.SFTPSession) *sftpBrowserState {
	localPath, err := os.Getwd()
	if err != nil {
		localPath = "."
	}
	return &sftpBrowserState{
		hostID:     hostID,
		hostLabel:  hostLabel,
		session:    session,
		localPath:  localPath,
		remotePath: ".",
		activePane: sftpPaneRemote,
	}
}

func (a *App) openSelectedHostSFTP(ctx context.Context) error {
	record := a.selectedRecord()
	if record.ID == "" {
		return nil
	}
	return a.openHostSFTP(ctx, record.ID, record.Label)
}

func (a *App) openHostSFTP(ctx context.Context, id, label string) error {
	if id == "" {
		return nil
	}
	if strings.TrimSpace(label) == "" {
		if host, err := a.catalog.GetHost(ctx, id); err == nil && host != nil {
			label = host.Label()
		}
	}
	if strings.TrimSpace(label) == "" {
		label = id
	}
	session, err := a.connector.OpenSFTP(ctx, id, a.sessionPrompts(ctx))
	if err != nil {
		return err
	}
	if a.sftp != nil && a.sftp.session != nil {
		_ = a.sftp.session.Close()
	}
	a.sftp = newSFTPBrowserState(id, label, session)
	if err := a.refreshSFTP(ctx); err != nil {
		_ = session.Close()
		a.sftp = nil
		return err
	}
	a.status = fmt.Sprintf("Opened SFTP for %s.", label)
	a.setActiveTab(a.sftpTabIndex())
	return nil
}

func (a *App) closeSFTP() {
	if a.sftp == nil {
		return
	}
	if a.sftp.session != nil {
		_ = a.sftp.session.Close()
	}
	a.sftp.transfer = nil
	a.sftp = nil
	if a.inSFTPTab() {
		a.setActiveTab(0)
	}
}

func (a *App) refreshSFTP(ctx context.Context) error {
	if a.sftp == nil || a.sftp.session == nil {
		return nil
	}
	if err := a.refreshSFTPLocal(); err != nil {
		return err
	}
	entries, err := a.sftp.session.ReadDir(ctx, a.sftp.remotePath)
	if err != nil {
		return err
	}
	a.sftp.remoteEntries = entries
	a.sftp.localCursor = clampInt(a.sftp.localCursor, 0, max(0, len(a.sftp.localEntries)-1))
	a.sftp.remoteCursor = clampInt(a.sftp.remoteCursor, 0, max(0, len(a.sftp.remoteEntries)-1))
	return nil
}

func (a *App) refreshSFTPLocal() error {
	if a.sftp == nil {
		return nil
	}
	entries, err := readLocalSFTPEntries(a.sftp.localPath)
	if err != nil {
		return err
	}
	a.sftp.localEntries = entries
	a.sftp.localCursor = clampInt(a.sftp.localCursor, 0, max(0, len(entries)-1))
	return nil
}

func readLocalSFTPEntries(localPath string) ([]service.SFTPEntry, error) {
	items, err := os.ReadDir(localPath)
	if err != nil {
		return nil, err
	}
	entries := make([]service.SFTPEntry, 0, len(items))
	for _, item := range items {
		info, err := item.Info()
		if err != nil {
			continue
		}
		entries = append(entries, service.SFTPEntry{
			Name:    item.Name(),
			Path:    filepath.Join(localPath, item.Name()),
			IsDir:   item.IsDir(),
			Size:    info.Size(),
			Mode:    info.Mode().String(),
			ModTime: info.ModTime(),
		})
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].IsDir != entries[j].IsDir {
			return entries[i].IsDir
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	return entries, nil
}

func (a *App) handleSFTPKey(ctx context.Context, ev *tcell.EventKey) (bool, error) {
	if a.sftp == nil {
		switch ev.Key() {
		case tcell.KeyF2:
			a.setActiveTab(0)
		case tcell.KeyF10, tcell.KeyEscape:
			return true, nil
		default:
			if ev.Key() == tcell.KeyRune && ev.Rune() == 'q' {
				return true, nil
			}
		}
		return false, nil
	}
	switch ev.Key() {
	case tcell.KeyF10:
		return true, nil
	case tcell.KeyEscape, tcell.KeyF2:
		a.setActiveTab(0)
	case tcell.KeyTAB, tcell.KeyBacktab:
		a.toggleSFTPPane()
	case tcell.KeyUp:
		a.moveSFTPCursor(-1)
	case tcell.KeyDown:
		a.moveSFTPCursor(1)
	case tcell.KeyPgUp:
		a.moveSFTPCursor(-10)
	case tcell.KeyPgDn:
		a.moveSFTPCursor(10)
	case tcell.KeyEnter:
		if err := a.enterSFTPEntry(ctx); err != nil {
			a.status = err.Error()
		}
	case tcell.KeyBackspace, tcell.KeyBackspace2:
		if err := a.sftpParent(ctx); err != nil {
			a.status = err.Error()
		}
	case tcell.KeyDelete:
		a.openSFTPDeleteConfirm(ctx)
	default:
		if ev.Key() != tcell.KeyRune {
			return false, nil
		}
		switch ev.Rune() {
		case 'q':
			return true, nil
		case 'r':
			if err := a.refreshSFTP(ctx); err != nil {
				a.status = err.Error()
			}
		case 'g':
			a.openSFTPPathPrompt(ctx)
		case 'u':
			a.startSFTPUpload(ctx)
		case 'd':
			a.startSFTPDownload(ctx)
		case 'n':
			a.openSFTPMkdirPrompt(ctx)
		case 'x':
			a.openSFTPDeleteConfirm(ctx)
		case 'R':
			a.openSFTPRenamePrompt(ctx)
		case 'c':
			a.closeSFTP()
			a.status = "Closed SFTP connection."
		}
	}
	return false, nil
}

func (a *App) handleSFTPMouse(ctx context.Context, ev *tcell.EventMouse, prevButtons tcell.ButtonMask) {
	if a.sftp == nil {
		return
	}
	buttons := ev.Buttons()
	if buttons&tcell.WheelUp != 0 {
		a.moveSFTPCursor(-1)
		return
	}
	if buttons&tcell.WheelDown != 0 {
		a.moveSFTPCursor(1)
		return
	}
	if !pressedPrimary(buttons, prevButtons) {
		return
	}
	x, y := ev.Position()
	w, _ := a.screen.Size()
	if y < 2 {
		return
	}
	if x < w/2 {
		a.sftp.activePane = sftpPaneLocal
		a.sftp.localCursor = clampInt(y-2, 0, max(0, len(a.sftp.localEntries)-1))
	} else {
		a.sftp.activePane = sftpPaneRemote
		a.sftp.remoteCursor = clampInt(y-2, 0, max(0, len(a.sftp.remoteEntries)-1))
	}
}

func (a *App) toggleSFTPPane() {
	if a.sftp.activePane == sftpPaneLocal {
		a.sftp.activePane = sftpPaneRemote
		return
	}
	a.sftp.activePane = sftpPaneLocal
}

func (a *App) moveSFTPCursor(delta int) {
	if a.sftp == nil || delta == 0 {
		return
	}
	if a.sftp.activePane == sftpPaneLocal {
		a.sftp.localCursor = clampInt(a.sftp.localCursor+delta, 0, max(0, len(a.sftp.localEntries)-1))
		return
	}
	a.sftp.remoteCursor = clampInt(a.sftp.remoteCursor+delta, 0, max(0, len(a.sftp.remoteEntries)-1))
}

func (a *App) enterSFTPEntry(ctx context.Context) error {
	entry, ok := a.currentSFTPEntry()
	if !ok || !entry.IsDir {
		return nil
	}
	if a.sftp.activePane == sftpPaneLocal {
		a.sftp.localPath = entry.Path
		a.sftp.localCursor = 0
		return a.refreshSFTPLocal()
	}
	a.sftp.remotePath = entry.Path
	a.sftp.remoteCursor = 0
	return a.refreshSFTP(ctx)
}

func (a *App) sftpParent(ctx context.Context) error {
	if a.sftp.activePane == sftpPaneLocal {
		next := filepath.Dir(a.sftp.localPath)
		if next == a.sftp.localPath {
			return nil
		}
		a.sftp.localPath = next
		a.sftp.localCursor = 0
		return a.refreshSFTPLocal()
	}
	next := service.ParentSFTPRemotePath(a.sftp.remotePath)
	if next == a.sftp.remotePath {
		return nil
	}
	a.sftp.remotePath = next
	a.sftp.remoteCursor = 0
	return a.refreshSFTP(ctx)
}

func (a *App) openSFTPPathPrompt(ctx context.Context) {
	if a.sftp == nil {
		return
	}
	current := a.sftp.localPath
	title := "Local path"
	if a.sftp.activePane == sftpPaneRemote {
		current = a.sftp.remotePath
		title = "Remote path"
	}
	a.pushModal(modalState{
		kind: modalKindTextInput,
		textInput: newTextInputModal(title, current, false, false, func(app *App, input string) {
			input = strings.TrimSpace(input)
			if input == "" {
				return
			}
			if app.sftp.activePane == sftpPaneLocal {
				app.sftp.localPath = input
				if err := app.refreshSFTPLocal(); err != nil {
					app.status = err.Error()
				}
				return
			}
			app.sftp.remotePath = service.NormalizeSFTPRemotePath(input)
			app.sftp.remoteCursor = 0
			if err := app.refreshSFTP(ctx); err != nil {
				app.status = err.Error()
			}
		}),
	})
}

func (a *App) startSFTPUpload(ctx context.Context) {
	if a.sftp == nil || a.sftp.transfer != nil {
		return
	}
	entry, ok := a.localSFTPEntry()
	if !ok {
		a.status = "No local file selected."
		return
	}
	if entry.IsDir {
		a.status = "Directory upload is not supported yet."
		return
	}
	session := a.sftp.session
	destination := service.JoinSFTPRemotePath(a.sftp.remotePath, entry.Name)
	confirm := func() {
		a.runSFTPTransfer(ctx, "Uploading "+entry.Name, func(ctx context.Context) (string, error) {
			report, err := session.Upload(ctx, entry.Path, destination, true)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("Uploaded %s (%d bytes).", report.Destination, report.Bytes), nil
		})
	}
	if a.remoteSFTPEntryExists(destination) {
		a.pushModal(modalState{
			kind: modalKindConfirm,
			confirm: &confirmModal{
				title: "Overwrite Remote File",
				lines: wrapModalLines("Overwrite "+destination+"?", 68),
				onConfirm: func(context.Context, *App) error {
					confirm()
					return nil
				},
			},
		})
		return
	}
	confirm()
}

func (a *App) startSFTPDownload(ctx context.Context) {
	if a.sftp == nil || a.sftp.transfer != nil {
		return
	}
	entry, ok := a.remoteSFTPEntry()
	if !ok {
		a.status = "No remote file selected."
		return
	}
	if entry.IsDir {
		a.status = "Directory download is not supported yet."
		return
	}
	session := a.sftp.session
	destination := filepath.Join(a.sftp.localPath, entry.Name)
	confirm := func() {
		a.runSFTPTransfer(ctx, "Downloading "+entry.Name, func(ctx context.Context) (string, error) {
			report, err := session.Download(ctx, entry.Path, destination, true)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("Downloaded %s (%d bytes).", report.Destination, report.Bytes), nil
		})
	}
	if _, err := os.Stat(destination); err == nil {
		a.pushModal(modalState{
			kind: modalKindConfirm,
			confirm: &confirmModal{
				title: "Overwrite Local File",
				lines: wrapModalLines("Overwrite "+destination+"?", 68),
				onConfirm: func(context.Context, *App) error {
					confirm()
					return nil
				},
			},
		})
		return
	} else if err != nil && !os.IsNotExist(err) {
		a.status = err.Error()
		return
	}
	confirm()
}

func (a *App) runSFTPTransfer(ctx context.Context, message string, fn func(context.Context) (string, error)) {
	if a.sftp == nil || a.sftp.transfer != nil {
		return
	}
	done := make(chan sftpTransferResult, 1)
	a.sftp.transfer = &sftpTransferState{message: message, done: done}
	a.status = message + "..."
	go func() {
		msg, err := fn(ctx)
		done <- sftpTransferResult{message: msg, err: err}
	}()
}

func (a *App) collectSFTPUpdates(ctx context.Context) {
	if a.sftp == nil || a.sftp.transfer == nil {
		return
	}
	select {
	case result := <-a.sftp.transfer.done:
		a.sftp.transfer = nil
		if result.err != nil {
			a.status = result.err.Error()
			return
		}
		if result.message != "" {
			a.status = result.message
		}
		if err := a.refreshSFTP(ctx); err != nil {
			a.status = err.Error()
		}
	default:
		a.status = a.sftp.transfer.message + "..."
	}
}

func (a *App) openSFTPMkdirPrompt(ctx context.Context) {
	if a.sftp == nil {
		return
	}
	if a.sftp.activePane != sftpPaneRemote {
		a.status = "Remote pane must be active to create a directory."
		return
	}
	a.pushModal(modalState{
		kind: modalKindTextInput,
		textInput: newTextInputModal("Remote directory name", "", false, false, func(app *App, input string) {
			input = strings.TrimSpace(input)
			if input == "" {
				return
			}
			remotePath := service.JoinSFTPRemotePath(app.sftp.remotePath, input)
			if err := app.sftp.session.Mkdir(ctx, remotePath, false); err != nil {
				app.status = err.Error()
				return
			}
			app.status = "Created " + remotePath + "."
			if err := app.refreshSFTP(ctx); err != nil {
				app.status = err.Error()
			}
		}),
	})
}

func (a *App) openSFTPDeleteConfirm(ctx context.Context) {
	if a.sftp == nil {
		return
	}
	if a.sftp.activePane != sftpPaneRemote {
		a.status = "Remote pane must be active to delete."
		return
	}
	entry, ok := a.remoteSFTPEntry()
	if !ok {
		return
	}
	action := "Remove remote file "
	if entry.IsDir {
		action = "Recursively remove remote directory "
	}
	a.pushModal(modalState{
		kind: modalKindConfirm,
		confirm: &confirmModal{
			title: "Remove Remote Path",
			lines: wrapModalLines(action+entry.Path+"?", 68),
			onConfirm: func(context.Context, *App) error {
				if err := a.sftp.session.Remove(ctx, entry.Path, entry.IsDir); err != nil {
					a.status = err.Error()
					return nil
				}
				a.status = "Removed " + entry.Path + "."
				if err := a.refreshSFTP(ctx); err != nil {
					a.status = err.Error()
				}
				return nil
			},
		},
	})
}

func (a *App) openSFTPRenamePrompt(ctx context.Context) {
	if a.sftp == nil {
		return
	}
	if a.sftp.activePane != sftpPaneRemote {
		a.status = "Remote pane must be active to rename."
		return
	}
	entry, ok := a.remoteSFTPEntry()
	if !ok {
		return
	}
	a.pushModal(modalState{
		kind: modalKindTextInput,
		textInput: newTextInputModal("New remote path", entry.Path, false, false, func(app *App, input string) {
			input = strings.TrimSpace(input)
			if input == "" {
				return
			}
			newPath := service.NormalizeSFTPRemotePath(input)
			if err := app.sftp.session.Rename(ctx, entry.Path, newPath); err != nil {
				app.status = err.Error()
				return
			}
			app.status = "Renamed " + entry.Path + " to " + newPath + "."
			if err := app.refreshSFTP(ctx); err != nil {
				app.status = err.Error()
			}
		}),
	})
}

func (a *App) renderSFTP(w, h int) {
	if a.sftp == nil {
		drawText(a.screen, 0, 2, tcell.StyleDefault, "No SFTP connection. Go to HOST and press s.")
		return
	}
	mid := max(1, w/2)
	a.renderSFTPPane(0, mid, h, "LOCAL "+a.sftp.localPath, a.sftp.localEntries, a.sftp.localCursor, a.sftp.activePane == sftpPaneLocal)
	a.renderSFTPPane(mid, w-mid, h, "REMOTE "+a.sftp.hostLabel+":"+a.sftp.remotePath, a.sftp.remoteEntries, a.sftp.remoteCursor, a.sftp.activePane == sftpPaneRemote)
	if mid < w {
		style := tcell.StyleDefault.Foreground(tcell.ColorDarkSlateGray)
		for y := 1; y < h-1; y++ {
			a.screen.SetContent(mid-1, y, ' ', nil, style.Background(tcell.ColorDarkSlateGray))
		}
	}
}

func (a *App) renderSFTPPane(x, width, height int, title string, entries []service.SFTPEntry, cursor int, active bool) {
	if width <= 0 {
		return
	}
	titleStyle := tcell.StyleDefault.Foreground(tcell.ColorYellow)
	if active {
		titleStyle = titleStyle.Background(tcell.ColorDarkCyan).Foreground(tcell.ColorWhite)
		fillPartialRow(a.screen, x, 1, width, titleStyle)
	}
	drawText(a.screen, x, 1, titleStyle, truncate(title, width))
	rows := max(0, height-3)
	for i := 0; i < rows && i < len(entries); i++ {
		entry := entries[i]
		style := tcell.StyleDefault
		if active && i == cursor {
			style = style.Background(tcell.ColorDarkSlateGray)
			fillPartialRow(a.screen, x, 2+i, width, style)
		}
		drawText(a.screen, x, 2+i, style, truncate(formatSFTPEntry(entry, width), width))
	}
}

func formatSFTPEntry(entry service.SFTPEntry, width int) string {
	kind := "-"
	if entry.IsDir {
		kind = "d"
	}
	nameWidth := max(8, width-32)
	return fmt.Sprintf("%s %-*s %10d %s", kind, nameWidth, truncate(entry.Name, nameWidth), entry.Size, entry.ModTime.Format("2006-01-02 15:04"))
}

func fillPartialRow(screen tcell.Screen, x, y, width int, style tcell.Style) {
	for col := 0; col < width; col++ {
		screen.SetContent(x+col, y, ' ', nil, style)
	}
}

func (a *App) currentSFTPEntry() (service.SFTPEntry, bool) {
	if a.sftp == nil {
		return service.SFTPEntry{}, false
	}
	if a.sftp.activePane == sftpPaneLocal {
		return a.localSFTPEntry()
	}
	return a.remoteSFTPEntry()
}

func (a *App) localSFTPEntry() (service.SFTPEntry, bool) {
	if a.sftp == nil || a.sftp.localCursor < 0 || a.sftp.localCursor >= len(a.sftp.localEntries) {
		return service.SFTPEntry{}, false
	}
	return a.sftp.localEntries[a.sftp.localCursor], true
}

func (a *App) remoteSFTPEntry() (service.SFTPEntry, bool) {
	if a.sftp == nil || a.sftp.remoteCursor < 0 || a.sftp.remoteCursor >= len(a.sftp.remoteEntries) {
		return service.SFTPEntry{}, false
	}
	return a.sftp.remoteEntries[a.sftp.remoteCursor], true
}

func (a *App) remoteSFTPEntryExists(remotePath string) bool {
	if a.sftp == nil {
		return false
	}
	remotePath = service.NormalizeSFTPRemotePath(remotePath)
	for _, entry := range a.sftp.remoteEntries {
		if service.NormalizeSFTPRemotePath(entry.Path) == remotePath {
			return true
		}
	}
	return false
}

func (a *App) sftpTabIndex() int {
	return len(a.tabs) + 1
}

func (a *App) inSFTPTab() bool {
	return a.activeTab == a.sftpTabIndex()
}

func sftpTabKinds(tabs []domain.DocumentKind) []domain.DocumentKind {
	out := make([]domain.DocumentKind, 0, len(tabs)+2)
	out = append(out, tabs...)
	out = append(out, domain.DocumentKind("sessions"), domain.DocumentKind("sftp"))
	return out
}
