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

type sftpPaneIndex int

const (
	sftpPaneLeft sftpPaneIndex = iota
	sftpPaneRight
	sftpPaneCount
)

type sftpPaneKind string

const (
	sftpPaneEmpty  sftpPaneKind = "empty"
	sftpPaneLocal  sftpPaneKind = "local"
	sftpPaneRemote sftpPaneKind = "remote"
)

type sftpBrowserState struct {
	panes      [sftpPaneCount]sftpPaneState
	activePane sftpPaneIndex
	transfer   *sftpTransferState
}

type sftpPaneState struct {
	kind      sftpPaneKind
	hostID    string
	hostLabel string
	session   *service.SFTPSession
	path      string
	entries   []service.SFTPEntry
	cursor    int
	scroll    int
}

type sftpTransferState struct {
	message string
	done    chan sftpTransferResult
}

type sftpTransferResult struct {
	message string
	err     error
}

func newSFTPBrowserState() *sftpBrowserState {
	return &sftpBrowserState{activePane: sftpPaneRight}
}

func (p *sftpPaneState) configured() bool {
	return p != nil && p.kind != "" && p.kind != sftpPaneEmpty
}

func (p *sftpPaneState) label(side sftpPaneIndex) string {
	sideLabel := "LEFT"
	if side == sftpPaneRight {
		sideLabel = "RIGHT"
	}
	switch p.kind {
	case sftpPaneLocal:
		return sideLabel + " LOCAL " + p.path
	case sftpPaneRemote:
		return sideLabel + " REMOTE " + p.hostLabel + ":" + p.path
	default:
		return sideLabel + " EMPTY"
	}
}

func (a *App) ensureSFTPBrowser() {
	if a.sftp == nil {
		a.sftp = newSFTPBrowserState()
	}
}

func (a *App) openSelectedHostSFTP(ctx context.Context) error {
	record := a.selectedRecord()
	if record.ID == "" {
		return nil
	}
	if a.sftp != nil && (a.sftp.panes[sftpPaneLeft].configured() || a.sftp.panes[sftpPaneRight].configured()) {
		a.pushModal(modalState{
			kind: modalKindConfirm,
			confirm: &confirmModal{
				title: "Replace SFTP Panes",
				lines: wrapModalLines("Replace current SFTP panes with Local on the left and "+record.Label+" on the right?", 68),
				onConfirm: func(ctx context.Context, app *App) error {
					return app.openHostSFTP(ctx, record.ID, record.Label)
				},
			},
		})
		return nil
	}
	return a.openHostSFTP(ctx, record.ID, record.Label)
}

func (a *App) openHostSFTP(ctx context.Context, id, label string) error {
	if id == "" {
		return nil
	}
	a.closeSFTPPanesNow()
	a.sftp = newSFTPBrowserState()
	if err := a.setSFTPPaneLocal(ctx, sftpPaneLeft); err != nil {
		a.closeSFTP()
		return err
	}
	if err := a.setSFTPPaneRemote(ctx, sftpPaneRight, id, label); err != nil {
		a.closeSFTP()
		return err
	}
	a.sftp.activePane = sftpPaneRight
	a.status = fmt.Sprintf("Opened SFTP for %s.", a.sftp.panes[sftpPaneRight].hostLabel)
	a.setActiveTab(a.sftpTabIndex())
	return nil
}

func (a *App) assignSelectedHostToSFTPPane(ctx context.Context, pane sftpPaneIndex) error {
	record := a.selectedRecord()
	if record.ID == "" {
		return nil
	}
	a.ensureSFTPBrowser()
	if a.sftp.panes[pane].configured() {
		a.pushModal(modalState{
			kind: modalKindConfirm,
			confirm: &confirmModal{
				title: "Replace SFTP Pane",
				lines: wrapModalLines(fmt.Sprintf("Replace %s SFTP pane with %s?", sftpPaneName(pane), record.Label), 68),
				onConfirm: func(ctx context.Context, app *App) error {
					return app.assignHostToSFTPPane(ctx, pane, record.ID, record.Label)
				},
			},
		})
		return nil
	}
	return a.assignHostToSFTPPane(ctx, pane, record.ID, record.Label)
}

func (a *App) assignHostToSFTPPane(ctx context.Context, pane sftpPaneIndex, id, label string) error {
	a.ensureSFTPBrowser()
	if err := a.setSFTPPaneRemote(ctx, pane, id, label); err != nil {
		return err
	}
	a.sftp.activePane = pane
	a.status = fmt.Sprintf("Set %s SFTP pane to %s.", sftpPaneName(pane), a.sftp.panes[pane].hostLabel)
	a.setActiveTab(a.sftpTabIndex())
	return nil
}

func (a *App) setSFTPPaneLocal(ctx context.Context, pane sftpPaneIndex) error {
	a.ensureSFTPBrowser()
	localPath, err := os.Getwd()
	if err != nil {
		localPath = "."
	}
	a.closeSFTPPaneNow(pane)
	a.sftp.panes[pane] = sftpPaneState{kind: sftpPaneLocal, path: localPath}
	return a.refreshSFTPPane(ctx, pane)
}

func (a *App) setSFTPPaneRemote(ctx context.Context, pane sftpPaneIndex, id, label string) error {
	a.ensureSFTPBrowser()
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
	a.closeSFTPPaneNow(pane)
	a.sftp.panes[pane] = sftpPaneState{
		kind:      sftpPaneRemote,
		hostID:    id,
		hostLabel: label,
		session:   session,
		path:      ".",
	}
	if err := a.refreshSFTPPane(ctx, pane); err != nil {
		a.closeSFTPPaneNow(pane)
		return err
	}
	return nil
}

func (a *App) closeSFTP() {
	a.closeSFTPNow()
}

func (a *App) closeSFTPNow() {
	if a.sftp == nil {
		return
	}
	a.closeSFTPPanesNow()
	a.sftp.transfer = nil
	a.sftp = nil
	if a.inSFTPTab() {
		a.setActiveTab(0)
	}
}

func (a *App) closeSFTPPanes() {
	a.closeSFTPPanesNow()
}

func (a *App) closeSFTPPanesNow() {
	if a.sftp == nil {
		return
	}
	for pane := sftpPaneLeft; pane < sftpPaneCount; pane++ {
		a.closeSFTPPaneNow(pane)
	}
}

func (a *App) closeSFTPPane(pane sftpPaneIndex) {
	if a.sftp != nil && pane >= 0 && pane < sftpPaneCount && a.sftp.panes[pane].kind == sftpPaneRemote {
		a.pushModal(modalState{
			kind: modalKindConfirm,
			confirm: &confirmModal{
				title: "Close SFTP Pane",
				lines: wrapModalLines(fmt.Sprintf("Close %s remote SFTP pane?", sftpPaneName(pane)), 68),
				onConfirm: func(context.Context, *App) error {
					a.closeSFTPPaneNow(pane)
					return nil
				},
			},
		})
		return
	}
	a.closeSFTPPaneNow(pane)
}

func (a *App) closeSFTPPaneNow(pane sftpPaneIndex) {
	if a.sftp == nil || pane < 0 || pane >= sftpPaneCount {
		return
	}
	if a.sftp.panes[pane].session != nil {
		_ = a.sftp.panes[pane].session.Close()
	}
	a.sftp.panes[pane] = sftpPaneState{}
}

func (a *App) requestCloseSFTP() {
	if !a.hasRemoteSFTPPane() {
		a.closeSFTPNow()
		a.status = "Closed SFTP connection."
		return
	}
	a.pushModal(modalState{
		kind: modalKindConfirm,
		confirm: &confirmModal{
			title: "Close SFTP",
			lines: wrapModalLines("Close remote SFTP panes?", 68),
			onConfirm: func(context.Context, *App) error {
				a.closeSFTPNow()
				a.status = "Closed SFTP connection."
				return nil
			},
		},
	})
}

func (a *App) hasRemoteSFTPPane() bool {
	return a.sftp != nil && (a.sftp.panes[sftpPaneLeft].kind == sftpPaneRemote || a.sftp.panes[sftpPaneRight].kind == sftpPaneRemote)
}

func (a *App) refreshSFTP(ctx context.Context) error {
	if a.sftp == nil {
		return nil
	}
	for pane := sftpPaneLeft; pane < sftpPaneCount; pane++ {
		if err := a.refreshSFTPPane(ctx, pane); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) refreshSFTPPane(ctx context.Context, pane sftpPaneIndex) error {
	if a.sftp == nil || pane < 0 || pane >= sftpPaneCount {
		return nil
	}
	state := &a.sftp.panes[pane]
	switch state.kind {
	case sftpPaneLocal:
		entries, err := readLocalSFTPEntries(state.path)
		if err != nil {
			return err
		}
		state.entries = entries
	case sftpPaneRemote:
		if state.session == nil {
			return nil
		}
		entries, err := state.session.ReadDir(ctx, state.path)
		if err != nil {
			return fmt.Errorf("%s", sftpErrorStatus(err))
		}
		state.entries = entries
	default:
		state.entries = nil
		state.cursor = 0
		state.scroll = 0
		return nil
	}
	state.cursor = clampInt(state.cursor, 0, max(0, len(state.entries)-1))
	state.scroll = clampInt(state.scroll, 0, max(0, len(state.entries)-1))
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
		case tcell.KeyLeft:
			a.moveActiveTab(-1)
		case tcell.KeyRight:
			a.moveActiveTab(1)
		case tcell.KeyF2:
			a.setActiveTab(0)
		case tcell.KeyF10, tcell.KeyEscape:
			a.requestQuit()
		default:
			if ev.Key() == tcell.KeyRune && ev.Rune() == 'q' {
				a.requestQuit()
			}
		}
		return false, nil
	}
	switch ev.Key() {
	case tcell.KeyF10:
		a.requestQuit()
	case tcell.KeyLeft:
		a.moveActiveTab(-1)
	case tcell.KeyRight:
		a.moveActiveTab(1)
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
			a.requestQuit()
		case 'r':
			if err := a.refreshSFTP(ctx); err != nil {
				a.status = err.Error()
			}
		case 'g':
			a.openSFTPPathPrompt(ctx)
		case '/':
			a.openSFTPSearchPrompt()
		case 'l':
			a.setActiveSFTPPaneLocal(ctx)
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
			a.requestCloseSFTP()
		}
	}
	return false, nil
}

func (a *App) handleSFTPMouse(ctx context.Context, ev *tcell.EventMouse, prevButtons tcell.ButtonMask) {
	_ = ctx
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
		a.sftp.activePane = sftpPaneLeft
		pane := &a.sftp.panes[sftpPaneLeft]
		pane.cursor = clampInt(pane.scroll+y-2, 0, max(0, len(pane.entries)-1))
	} else {
		a.sftp.activePane = sftpPaneRight
		pane := &a.sftp.panes[sftpPaneRight]
		pane.cursor = clampInt(pane.scroll+y-2, 0, max(0, len(pane.entries)-1))
	}
}

func (a *App) toggleSFTPPane() {
	if a.sftp.activePane == sftpPaneLeft {
		a.sftp.activePane = sftpPaneRight
		return
	}
	a.sftp.activePane = sftpPaneLeft
}

func (a *App) moveSFTPCursor(delta int) {
	if a.sftp == nil || delta == 0 {
		return
	}
	pane := &a.sftp.panes[a.sftp.activePane]
	if len(pane.entries) == 0 {
		pane.cursor = 0
		return
	}
	next := (pane.cursor + delta) % len(pane.entries)
	if next < 0 {
		next += len(pane.entries)
	}
	pane.cursor = next
}

func (a *App) enterSFTPEntry(ctx context.Context) error {
	pane := a.activeSFTPPane()
	if pane == nil || !pane.configured() {
		return nil
	}
	entry, ok := a.currentSFTPEntry()
	if !ok || !entry.IsDir {
		return nil
	}
	switch pane.kind {
	case sftpPaneLocal:
		pane.path = entry.Path
	case sftpPaneRemote:
		pane.path = entry.Path
	}
	pane.cursor = 0
	pane.scroll = 0
	return a.refreshSFTPPane(ctx, a.sftp.activePane)
}

func (a *App) sftpParent(ctx context.Context) error {
	pane := a.activeSFTPPane()
	if pane == nil || !pane.configured() {
		return nil
	}
	switch pane.kind {
	case sftpPaneLocal:
		next := filepath.Dir(pane.path)
		if next == pane.path {
			return nil
		}
		pane.path = next
	case sftpPaneRemote:
		next := service.ParentSFTPRemotePath(pane.path)
		if next == pane.path {
			return nil
		}
		pane.path = next
	}
	pane.cursor = 0
	pane.scroll = 0
	return a.refreshSFTPPane(ctx, a.sftp.activePane)
}

func (a *App) openSFTPPathPrompt(ctx context.Context) {
	pane := a.activeSFTPPane()
	if pane == nil || !pane.configured() {
		a.status = "Configure this SFTP pane first."
		return
	}
	current := pane.path
	title := "Path"
	if pane.kind == sftpPaneLocal {
		title = "Local path"
	} else if pane.kind == sftpPaneRemote {
		title = "Remote path"
	}
	a.pushModal(modalState{
		kind: modalKindTextInput,
		textInput: newTextInputModal(title, current, false, false, func(app *App, input string) {
			input = strings.TrimSpace(input)
			if input == "" {
				return
			}
			pane := app.activeSFTPPane()
			if pane == nil {
				return
			}
			if pane.kind == sftpPaneRemote {
				input = service.NormalizeSFTPRemotePath(input)
			}
			pane.path = input
			pane.cursor = 0
			pane.scroll = 0
			if err := app.refreshSFTPPane(ctx, app.sftp.activePane); err != nil {
				app.status = err.Error()
			}
		}),
	})
}

func (a *App) openSFTPSearchPrompt() {
	pane := a.activeSFTPPane()
	if pane == nil || !pane.configured() {
		a.status = "Configure this SFTP pane first."
		return
	}
	if len(pane.entries) == 0 {
		a.status = "No SFTP entries to search."
		return
	}
	a.pushModal(modalState{
		kind: modalKindTextInput,
		textInput: newTextInputModal("Search SFTP entry", "", false, false, func(app *App, input string) {
			query := strings.TrimSpace(input)
			if query == "" {
				return
			}
			pane := app.activeSFTPPane()
			if pane == nil || len(pane.entries) == 0 {
				return
			}
			if index, ok := findSFTPEntry(pane, query); ok {
				pane.cursor = index
				pane.scroll = index
				app.status = fmt.Sprintf("Found %s.", pane.entries[index].Name)
				return
			}
			app.status = fmt.Sprintf("No SFTP entry matches %q.", query)
		}),
	})
}

func findSFTPEntry(pane *sftpPaneState, query string) (int, bool) {
	query = strings.ToLower(strings.TrimSpace(query))
	if pane == nil || query == "" || len(pane.entries) == 0 {
		return 0, false
	}
	start := clampInt(pane.cursor, 0, len(pane.entries)-1)
	for offset := 1; offset <= len(pane.entries); offset++ {
		index := (start + offset) % len(pane.entries)
		entry := pane.entries[index]
		if strings.Contains(strings.ToLower(entry.Name), query) {
			return index, true
		}
	}
	return 0, false
}

func (a *App) setActiveSFTPPaneLocal(ctx context.Context) {
	if a.sftp == nil {
		a.ensureSFTPBrowser()
	}
	pane := a.sftp.activePane
	if a.sftp.panes[pane].configured() {
		a.pushModal(modalState{
			kind: modalKindConfirm,
			confirm: &confirmModal{
				title: "Replace SFTP Pane",
				lines: wrapModalLines(fmt.Sprintf("Replace %s SFTP pane with Local?", sftpPaneName(pane)), 68),
				onConfirm: func(ctx context.Context, app *App) error {
					return app.assignLocalToSFTPPane(ctx, pane)
				},
			},
		})
		return
	}
	if err := a.assignLocalToSFTPPane(ctx, pane); err != nil {
		a.status = err.Error()
	}
}

func (a *App) assignLocalToSFTPPane(ctx context.Context, pane sftpPaneIndex) error {
	if err := a.setSFTPPaneLocal(ctx, pane); err != nil {
		return err
	}
	a.sftp.activePane = pane
	a.status = fmt.Sprintf("Set %s SFTP pane to Local.", sftpPaneName(pane))
	return nil
}

func (a *App) startSFTPUpload(ctx context.Context) {
	if a.sftp == nil || a.sftp.transfer != nil {
		return
	}
	localPane, remotePane, ok := a.localRemoteSFTPPanes()
	if !ok {
		a.status = "Copy between these pane types is not supported yet."
		return
	}
	entry, ok := selectedSFTPEntry(localPane)
	if !ok {
		a.status = "No local file selected."
		return
	}
	if entry.IsDir {
		a.status = "Directory upload is not supported yet."
		return
	}
	session := remotePane.session
	destination := service.JoinSFTPRemotePath(remotePane.path, entry.Name)
	confirm := func() {
		a.runSFTPTransfer(ctx, "Uploading "+entry.Name, func(ctx context.Context) (string, error) {
			report, err := session.Upload(ctx, entry.Path, destination, true)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("Uploaded %s (%d bytes).", report.Destination, report.Bytes), nil
		})
	}
	if sftpPaneEntryExists(remotePane, destination) {
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
	localPane, remotePane, ok := a.localRemoteSFTPPanes()
	if !ok {
		a.status = "Copy between these pane types is not supported yet."
		return
	}
	entry, ok := selectedSFTPEntry(remotePane)
	if !ok {
		a.status = "No remote file selected."
		return
	}
	if entry.IsDir {
		a.status = "Directory download is not supported yet."
		return
	}
	session := remotePane.session
	destination := filepath.Join(localPane.path, entry.Name)
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

func (a *App) localRemoteSFTPPanes() (*sftpPaneState, *sftpPaneState, bool) {
	if a.sftp == nil {
		return nil, nil, false
	}
	left := &a.sftp.panes[sftpPaneLeft]
	right := &a.sftp.panes[sftpPaneRight]
	if left.kind == sftpPaneLocal && right.kind == sftpPaneRemote {
		return left, right, true
	}
	if left.kind == sftpPaneRemote && right.kind == sftpPaneLocal {
		return right, left, true
	}
	return nil, nil, false
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
			a.status = sftpErrorStatus(result.err)
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
	pane := a.activeSFTPPane()
	if pane == nil || pane.kind != sftpPaneRemote {
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
			pane := app.activeSFTPPane()
			if pane == nil || pane.kind != sftpPaneRemote {
				return
			}
			remotePath := service.JoinSFTPRemotePath(pane.path, input)
			if err := pane.session.Mkdir(ctx, remotePath, false); err != nil {
				app.status = sftpErrorStatus(err)
				return
			}
			app.status = "Created " + remotePath + "."
			if err := app.refreshSFTPPane(ctx, app.sftp.activePane); err != nil {
				app.status = err.Error()
			}
		}),
	})
}

func (a *App) openSFTPDeleteConfirm(ctx context.Context) {
	pane := a.activeSFTPPane()
	if pane == nil || pane.kind != sftpPaneRemote {
		a.status = "Remote pane must be active to delete."
		return
	}
	entry, ok := selectedSFTPEntry(pane)
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
			onConfirm: func(_ context.Context, app *App) error {
				pane := app.activeSFTPPane()
				if pane == nil || pane.kind != sftpPaneRemote {
					return nil
				}
				if err := pane.session.Remove(ctx, entry.Path, entry.IsDir); err != nil {
					app.status = sftpErrorStatus(err)
					return nil
				}
				app.status = "Removed " + entry.Path + "."
				if err := app.refreshSFTPPane(ctx, app.sftp.activePane); err != nil {
					app.status = err.Error()
				}
				return nil
			},
		},
	})
}

func (a *App) openSFTPRenamePrompt(ctx context.Context) {
	pane := a.activeSFTPPane()
	if pane == nil || pane.kind != sftpPaneRemote {
		a.status = "Remote pane must be active to rename."
		return
	}
	entry, ok := selectedSFTPEntry(pane)
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
			pane := app.activeSFTPPane()
			if pane == nil || pane.kind != sftpPaneRemote {
				return
			}
			newPath := service.NormalizeSFTPRemotePath(input)
			if err := pane.session.Rename(ctx, entry.Path, newPath); err != nil {
				app.status = sftpErrorStatus(err)
				return
			}
			app.status = "Renamed " + entry.Path + " to " + newPath + "."
			if err := app.refreshSFTPPane(ctx, app.sftp.activePane); err != nil {
				app.status = err.Error()
			}
		}),
	})
}

func (a *App) renderSFTP(w, h int) {
	if a.sftp == nil {
		drawText(a.screen, 0, 2, tcell.StyleDefault, "No SFTP panes. Go to HOST and press s, [, or ].")
		return
	}
	mid := max(1, w/2)
	a.renderSFTPPane(0, mid, h, sftpPaneLeft)
	a.renderSFTPPane(mid, w-mid, h, sftpPaneRight)
	if mid < w {
		style := tcell.StyleDefault.Foreground(tcell.ColorDarkSlateGray)
		for y := 1; y < h-1; y++ {
			a.screen.SetContent(mid-1, y, ' ', nil, style.Background(tcell.ColorDarkSlateGray))
		}
	}
}

func (a *App) renderSFTPPane(x, width, height int, paneIndex sftpPaneIndex) {
	if width <= 0 || a.sftp == nil {
		return
	}
	pane := &a.sftp.panes[paneIndex]
	active := a.sftp.activePane == paneIndex
	titleStyle := tcell.StyleDefault.Foreground(tcell.ColorYellow)
	if active {
		titleStyle = titleStyle.Background(tcell.ColorDarkCyan).Foreground(tcell.ColorWhite)
		fillPartialRow(a.screen, x, 1, width, titleStyle)
	}
	drawText(a.screen, x, 1, titleStyle, truncate(pane.label(paneIndex), width))
	if !pane.configured() {
		drawText(a.screen, x, 2, tcell.StyleDefault.Foreground(tcell.ColorGray), truncate("Empty pane. Press l for Local or choose a Host with [ / ].", width))
		return
	}
	rows := max(0, height-3)
	ensureSFTPCursorVisible(pane, rows)
	for row := 0; row < rows && pane.scroll+row < len(pane.entries); row++ {
		i := pane.scroll + row
		entry := pane.entries[i]
		style := tcell.StyleDefault
		if active && i == pane.cursor {
			style = style.Background(tcell.ColorDarkSlateGray)
			fillPartialRow(a.screen, x, 2+row, width, style)
		}
		drawText(a.screen, x, 2+row, style, truncate(formatSFTPEntry(entry, width), width))
	}
}

func ensureSFTPCursorVisible(pane *sftpPaneState, rows int) {
	if pane == nil {
		return
	}
	if len(pane.entries) == 0 || rows <= 0 {
		if rows <= 0 && len(pane.entries) > 0 {
			pane.cursor = clampInt(pane.cursor, 0, len(pane.entries)-1)
			pane.scroll = clampInt(pane.scroll, 0, max(0, len(pane.entries)-1))
			return
		}
		pane.cursor = 0
		pane.scroll = 0
		return
	}
	pane.cursor = clampInt(pane.cursor, 0, len(pane.entries)-1)
	maxScroll := max(0, len(pane.entries)-rows)
	pane.scroll = clampInt(pane.scroll, 0, maxScroll)
	if pane.cursor < pane.scroll {
		pane.scroll = pane.cursor
	} else if pane.cursor >= pane.scroll+rows {
		pane.scroll = pane.cursor - rows + 1
	}
	pane.scroll = clampInt(pane.scroll, 0, maxScroll)
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

func (a *App) activeSFTPPane() *sftpPaneState {
	if a.sftp == nil || a.sftp.activePane < 0 || a.sftp.activePane >= sftpPaneCount {
		return nil
	}
	return &a.sftp.panes[a.sftp.activePane]
}

func (a *App) currentSFTPEntry() (service.SFTPEntry, bool) {
	return selectedSFTPEntry(a.activeSFTPPane())
}

func selectedSFTPEntry(pane *sftpPaneState) (service.SFTPEntry, bool) {
	if pane == nil || pane.cursor < 0 || pane.cursor >= len(pane.entries) {
		return service.SFTPEntry{}, false
	}
	return pane.entries[pane.cursor], true
}

func sftpPaneEntryExists(pane *sftpPaneState, remotePath string) bool {
	if pane == nil {
		return false
	}
	remotePath = service.NormalizeSFTPRemotePath(remotePath)
	for _, entry := range pane.entries {
		if service.NormalizeSFTPRemotePath(entry.Path) == remotePath {
			return true
		}
	}
	return false
}

func sftpPaneName(pane sftpPaneIndex) string {
	if pane == sftpPaneRight {
		return "right"
	}
	return "left"
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
