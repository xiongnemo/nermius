package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/uniseg"
	"golang.org/x/crypto/ssh"

	"github.com/nermius/nermius/internal/clipboard"
	"github.com/nermius/nermius/internal/config"
	"github.com/nermius/nermius/internal/domain"
	"github.com/nermius/nermius/internal/service"
	"github.com/nermius/nermius/internal/store"
	"github.com/nermius/nermius/internal/termemu"
)

type App struct {
	catalog   *service.Catalog
	connector *service.Connector
	screen    tcell.Screen
	events    chan tcell.Event
	clipboard clipboard.Adapter
	paths     config.Paths

	tabs             []domain.DocumentKind
	activeTab        int
	cursor           int
	records          map[domain.DocumentKind][]store.DocumentSummary
	filters          map[domain.DocumentKind]string
	hostAddresses    map[string]string
	workspace        *workspaceState
	sessions         []*service.EmbeddedSession
	sessionRuntimes  map[*service.EmbeddedSession]*sessionRuntime
	activeSession    int
	sftp             *sftpBrowserState
	runningForwards  map[string]*forwardRuntime
	status           string
	cursorBlinkOn    bool
	cursorBlinkAt    time.Time
	lastMouseButtons tcell.ButtonMask
	lastMouseX       int
	lastMouseY       int
	lastClickAt      time.Time
	lastClickTab     domain.DocumentKind
	lastClickIndex   int
	focused          bool
	selection        sessionSelection
	scrollOffsets    map[*service.EmbeddedSession]int
	modals           []modalState
	exitRequested    bool
}

const (
	workspaceTabKind domain.DocumentKind = "workspace_view"
	sftpTabKind      domain.DocumentKind = "sftp"
)

type forwardRuntimeStatus string

const (
	forwardStatusStopped      forwardRuntimeStatus = "stopped"
	forwardStatusConnecting   forwardRuntimeStatus = "connecting"
	forwardStatusRunning      forwardRuntimeStatus = "running"
	forwardStatusReconnecting forwardRuntimeStatus = "reconnecting"
	forwardStatusDisconnected forwardRuntimeStatus = "disconnected"
	forwardStatusError        forwardRuntimeStatus = "error"
)

type sessionRuntimeStatus string

const (
	sessionStatusRunning      sessionRuntimeStatus = "running"
	sessionStatusReconnecting sessionRuntimeStatus = "reconnecting"
	sessionStatusDisconnected sessionRuntimeStatus = "disconnected"
	sessionStatusFinished     sessionRuntimeStatus = "finished"
)

type sessionRuntime struct {
	hostID   string
	label    string
	status   sessionRuntimeStatus
	attempts int
	reason   string
	closing  bool
	prompted bool
}

type forwardRuntime struct {
	running  *service.RunningForward
	ctx      context.Context
	cancel   context.CancelFunc
	label    string
	status   forwardRuntimeStatus
	attempts int
	reason   string
	started  time.Time
	stopping bool
	prompted bool
}

func (rt *forwardRuntime) active() bool {
	if rt == nil {
		return false
	}
	switch rt.status {
	case forwardStatusConnecting, forwardStatusRunning, forwardStatusReconnecting, forwardStatusDisconnected:
		return true
	default:
		return false
	}
}

func Run(ctx context.Context, catalog *service.Catalog, connector *service.Connector, paths config.Paths) error {
	screen, err := tcell.NewScreen()
	if err != nil {
		return err
	}
	if err := screen.Init(); err != nil {
		return err
	}
	screen.EnableMouse(tcell.MouseMotionEvents)
	screen.EnableFocus()
	defer screen.Fini()
	app := &App{
		catalog:   catalog,
		connector: connector,
		screen:    screen,
		clipboard: clipboard.New(),
		paths:     paths,
		tabs: []domain.DocumentKind{
			domain.KindHost,
			domain.KindGroup,
			domain.KindProfile,
			domain.KindIdentity,
			domain.KindKey,
			domain.KindForward,
			domain.KindWorkspace,
			domain.KindKnownHost,
		},
		records:         map[domain.DocumentKind][]store.DocumentSummary{},
		filters:         map[domain.DocumentKind]string{},
		hostAddresses:   map[string]string{},
		sessionRuntimes: map[*service.EmbeddedSession]*sessionRuntime{},
		runningForwards: map[string]*forwardRuntime{},
		status:          "",
		cursorBlinkOn:   true,
		cursorBlinkAt:   time.Now().Add(500 * time.Millisecond),
		lastMouseX:      -1,
		lastMouseY:      -1,
		lastClickIndex:  -1,
		focused:         true,
		scrollOffsets:   map[*service.EmbeddedSession]int{},
	}
	if err := app.reload(ctx); err != nil {
		return err
	}
	defer app.closeRunningForwards()
	defer app.closeSessionsNow()
	defer app.closeSFTPNow()
	return app.loop(ctx)
}

func (a *App) loop(ctx context.Context) error {
	events := make(chan tcell.Event, 16)
	a.events = events
	go func() {
		for {
			events <- a.screen.PollEvent()
		}
	}()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		a.render()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			now := time.Now()
			if !now.Before(a.cursorBlinkAt) {
				a.cursorBlinkOn = !a.cursorBlinkOn
				a.cursorBlinkAt = now.Add(500 * time.Millisecond)
			}
			a.collectSessionUpdates()
			a.collectForwardUpdates()
			a.collectSFTPUpdates(ctx)
			if a.exitRequested {
				return nil
			}
		case ev := <-events:
			switch event := ev.(type) {
			case *tcell.EventResize:
				a.screen.Sync()
				a.resizeWorkspaceSessions()
			case *tcell.EventFocus:
				a.setFocused(event.Focused)
			case *tcell.EventKey:
				if a.hasModal() {
					if done, err := a.handleModalKey(ctx, event); done {
						return err
					}
					continue
				}
				if done, err := a.handleKey(ctx, event); done {
					return err
				}
				if a.exitRequested {
					return nil
				}
			case *tcell.EventMouse:
				if a.hasModal() {
					if done, err := a.handleModalMouse(ctx, event); done {
						return err
					}
					continue
				}
				if done, err := a.handleMouse(ctx, event); done {
					return err
				}
			}
		}
	}
}

func (a *App) handleKey(ctx context.Context, ev *tcell.EventKey) (bool, error) {
	if a.inSessionTab() {
		if isCopyShortcut(ev) {
			a.copySelection()
			return false, nil
		}
		if isPasteShortcut(ev) {
			a.pasteClipboard()
			a.resetCursorBlink()
			return false, nil
		}
		switch ev.Key() {
		case tcell.KeyF10:
			a.requestQuit()
			return false, nil
		case tcell.KeyF2:
			if len(a.tabs) > 0 {
				a.setActiveTab(len(a.tabs) - 1)
			}
			return false, nil
		case tcell.KeyF3:
			return false, a.openWorkspacePicker(ctx)
		case tcell.KeyF4:
			a.openSaveWorkspacePrompt(ctx)
			return false, nil
		case tcell.KeyF5:
			return false, a.openHostPickerForFocusedPane(ctx)
		case tcell.KeyF6:
			a.focusNextWorkspacePane()
			a.resetCursorBlink()
			return false, nil
		case tcell.KeyF7:
			return false, a.splitFocusedWorkspacePane(ctx, domain.WorkspaceSplitHorizontal, "", "")
		case tcell.KeyF8:
			a.requestCloseFocusedWorkspacePane()
			a.resetCursorBlink()
			return false, nil
		case tcell.KeyF9:
			return false, a.splitFocusedWorkspacePane(ctx, domain.WorkspaceSplitVertical, "", "")
		case tcell.KeyF11:
			if a.workspace != nil {
				a.workspace.zoomed = !a.workspace.zoomed
				a.resizeWorkspaceSessions()
			}
			return false, nil
		case tcell.KeyEnter:
			if a.workspace != nil {
				if pane := a.workspace.focusedPane(); pane != nil && pane.session == nil && pane.hostID != "" {
					if err := a.connectWorkspacePane(ctx, pane); err != nil {
						a.status = err.Error()
					}
					a.resetCursorBlink()
					return false, nil
				}
			}
			a.resetCursorBlink()
			return false, a.forwardSessionKey(ev)
		case tcell.KeyEscape:
			if a.selection.Active && a.selection.Session == a.currentSession() {
				a.clearSelection()
				return false, nil
			}
			a.resetCursorBlink()
			return false, a.forwardSessionKey(ev)
		case tcell.KeyLeft:
			if ev.Modifiers()&tcell.ModAlt != 0 && ev.Modifiers()&tcell.ModCtrl != 0 {
				a.resizeFocusedWorkspacePane(-5, 0)
				return false, nil
			}
			if ev.Modifiers()&tcell.ModAlt != 0 {
				a.focusWorkspaceDirection(-1, 0)
				return false, nil
			}
			a.moveActiveTab(-1)
			a.resetCursorBlink()
			return false, nil
		case tcell.KeyRight:
			if ev.Modifiers()&tcell.ModAlt != 0 && ev.Modifiers()&tcell.ModCtrl != 0 {
				a.resizeFocusedWorkspacePane(5, 0)
				return false, nil
			}
			if ev.Modifiers()&tcell.ModAlt != 0 {
				a.focusWorkspaceDirection(1, 0)
				return false, nil
			}
			a.moveActiveTab(1)
			a.resetCursorBlink()
			return false, nil
		case tcell.KeyUp:
			if ev.Modifiers()&tcell.ModAlt != 0 && ev.Modifiers()&tcell.ModCtrl != 0 {
				a.resizeFocusedWorkspacePane(0, -5)
				return false, nil
			}
			if ev.Modifiers()&tcell.ModAlt != 0 {
				a.focusWorkspaceDirection(0, -1)
				return false, nil
			}
			a.resetCursorBlink()
			return false, a.forwardSessionKey(ev)
		case tcell.KeyDown:
			if ev.Modifiers()&tcell.ModAlt != 0 && ev.Modifiers()&tcell.ModCtrl != 0 {
				a.resizeFocusedWorkspacePane(0, 5)
				return false, nil
			}
			if ev.Modifiers()&tcell.ModAlt != 0 {
				a.focusWorkspaceDirection(0, 1)
				return false, nil
			}
			a.resetCursorBlink()
			return false, a.forwardSessionKey(ev)
		default:
			if ev.Key() == tcell.KeyRune && ev.Rune() == 'q' {
				a.requestQuit()
				return false, nil
			}
			if ev.Key() == tcell.KeyRune && ev.Rune() == 'r' {
				if a.reconnectCurrentSession(ctx) {
					return false, nil
				}
			}
			if ev.Key() == tcell.KeyRune && ev.Rune() == 'D' {
				return false, a.duplicateFocusedWorkspacePane(ctx)
			}
			a.resetCursorBlink()
			return false, a.forwardSessionKey(ev)
		}
	}
	if a.inSFTPTab() {
		return a.handleSFTPKey(ctx, ev)
	}
	switch ev.Key() {
	case tcell.KeyEscape, tcell.KeyCtrlC, tcell.KeyF10:
		a.requestQuit()
		return false, nil
	case tcell.KeyLeft:
		a.moveActiveTab(-1)
	case tcell.KeyRight:
		a.moveActiveTab(1)
	case tcell.KeyUp:
		if a.cursor > 0 {
			a.cursor--
		}
	case tcell.KeyDown:
		if a.cursor < len(a.currentRecords())-1 {
			a.cursor++
		}
	case tcell.KeyEnter:
		if a.currentKind() == domain.KindHost {
			if err := a.openSelectedHostSession(ctx); err != nil {
				a.status = err.Error()
			}
		} else if a.currentKind() == domain.KindForward {
			if err := a.toggleSelectedForward(ctx); err != nil {
				a.status = err.Error()
			}
		} else if a.currentKind() == domain.KindWorkspace {
			if err := a.openSelectedWorkspaceLayout(ctx); err != nil {
				a.status = err.Error()
			}
		} else if err := a.openDetailModal(ctx); err != nil {
			a.status = err.Error()
		}
	case tcell.KeyCtrlR:
		if err := a.reload(ctx); err != nil {
			a.status = err.Error()
		}
	case tcell.KeyDelete:
		if err := a.openDeleteConfirm(ctx); err != nil {
			a.status = err.Error()
		}
	case tcell.KeyF7:
		if a.currentKind() == domain.KindHost {
			record := a.selectedRecord()
			if record.ID != "" {
				if err := a.splitFocusedWorkspacePane(ctx, domain.WorkspaceSplitHorizontal, record.ID, record.Label); err != nil {
					a.status = err.Error()
				}
			}
		}
	case tcell.KeyF9:
		if a.currentKind() == domain.KindHost {
			record := a.selectedRecord()
			if record.ID != "" {
				if err := a.splitFocusedWorkspacePane(ctx, domain.WorkspaceSplitVertical, record.ID, record.Label); err != nil {
					a.status = err.Error()
				}
			}
		}
	default:
		switch ev.Rune() {
		case 'q':
			a.requestQuit()
			return false, nil
		case 'a':
			if err := a.openAddForm(ctx); err != nil {
				a.status = err.Error()
			}
		case 'd':
			if err := a.openDetailModal(ctx); err != nil {
				a.status = err.Error()
			}
		case 'e':
			if err := a.openEditForm(ctx); err != nil {
				a.status = err.Error()
			}
		case 'r':
			if a.currentKind() == domain.KindForward && a.reconnectSelectedForward(ctx) {
				return false, nil
			}
			if err := a.reload(ctx); err != nil {
				a.status = err.Error()
			}
		case 's':
			if a.currentKind() == domain.KindHost {
				if err := a.openSelectedHostSFTP(ctx); err != nil {
					a.status = err.Error()
				}
			}
		case 'S':
			if a.currentKind() == domain.KindHost {
				if err := a.openSelectedHostSession(ctx); err != nil {
					a.status = err.Error()
				}
			}
		case '[':
			if a.currentKind() == domain.KindHost {
				if err := a.assignSelectedHostToSFTPPane(ctx, sftpPaneLeft); err != nil {
					a.status = err.Error()
				}
			}
		case ']':
			if a.currentKind() == domain.KindHost {
				if err := a.assignSelectedHostToSFTPPane(ctx, sftpPaneRight); err != nil {
					a.status = err.Error()
				}
			}
		case '/':
			a.openFilterModal()
		case ' ':
			if a.currentKind() == domain.KindForward {
				if err := a.toggleSelectedForward(ctx); err != nil {
					a.status = err.Error()
				}
			}
		case 'x':
			if err := a.openDeleteConfirm(ctx); err != nil {
				a.status = err.Error()
			}
		}
	}
	return false, nil
}

func (a *App) handleMouse(ctx context.Context, ev *tcell.EventMouse) (bool, error) {
	x, y := ev.Position()
	buttons := ev.Buttons()
	prevButtons := a.lastMouseButtons
	prevX, prevY := a.lastMouseX, a.lastMouseY
	defer func() {
		a.lastMouseButtons = persistentMouseButtons(buttons)
		a.lastMouseX = x
		a.lastMouseY = y
	}()

	if pressedPrimary(buttons, prevButtons) {
		if tab, ok := tabIndexAt(x, y, specialTabKinds(a.tabs)); ok {
			a.setActiveTab(tab)
			a.cursor = 0
			a.resetCursorBlink()
			return false, nil
		}
	}

	if a.inSessionTab() {
		if y >= 2 {
			if pressedPrimary(buttons, prevButtons) {
				a.focusWorkspacePaneAt(x, y)
			}
			handled, err := a.handleSessionMouse(ev, prevButtons, prevX, prevY)
			if err != nil {
				return false, err
			}
			if handled {
				a.resetCursorBlink()
			}
		}
		return false, nil
	}
	if a.inSFTPTab() {
		a.handleSFTPMouse(ctx, ev, prevButtons)
		return false, nil
	}

	a.handleListMouse(ctx, y, buttons, prevButtons)
	return false, nil
}

func (a *App) reload(ctx context.Context) error {
	for _, kind := range a.tabs {
		items, err := a.listRecords(ctx, kind)
		if err != nil {
			return err
		}
		a.records[kind] = items
	}
	a.refreshHostAddresses(ctx)
	if current := a.currentRecords(); len(current) == 0 {
		a.cursor = 0
	} else if a.cursor >= len(current) {
		a.cursor = len(current) - 1
	}
	return nil
}

func (a *App) refreshHostAddresses(ctx context.Context) {
	a.hostAddresses = map[string]string{}
	if a.catalog == nil {
		return
	}
	for _, item := range a.records[domain.KindHost] {
		host, err := a.catalog.GetHost(ctx, item.ID)
		if err != nil || host == nil {
			continue
		}
		a.hostAddresses[item.ID] = hostAddressLabel(*host)
	}
}

func (a *App) handleListMouse(ctx context.Context, y int, buttons, prevButtons tcell.ButtonMask) {
	items := a.currentRecords()
	if buttons&tcell.WheelUp != 0 {
		if a.cursor > 0 {
			a.cursor--
		}
		return
	}
	if buttons&tcell.WheelDown != 0 {
		if a.cursor < len(items)-1 {
			a.cursor++
		}
		return
	}
	if !pressedPrimary(buttons, prevButtons) {
		return
	}
	index := y - 2
	if index < 0 || index >= len(items) {
		return
	}
	a.cursor = index
	if a.currentKind() != domain.KindHost {
		return
	}
	now := time.Now()
	if a.isDoubleClick(a.currentKind(), index, now) {
		if err := a.openSelectedHostSession(ctx); err != nil {
			a.status = err.Error()
		}
		return
	}
	a.recordClick(a.currentKind(), index, now)
}

func (a *App) render() {
	a.screen.Clear()
	a.screen.HideCursor()
	w, h := a.screen.Size()
	tabStyle := tcell.StyleDefault.Foreground(tcell.ColorBlack).Background(tcell.ColorWhite)
	activeStyle := tcell.StyleDefault.Foreground(tcell.ColorWhite).Background(tcell.ColorDarkCyan)
	x := 0
	for idx, kind := range specialTabKinds(a.tabs) {
		label := " " + displayKindName(kind) + " "
		style := tabStyle
		if idx == a.activeTab {
			style = activeStyle
		}
		drawText(a.screen, x, 0, style, label)
		x += len(label)
	}
	if a.inSessionTab() {
		a.renderWorkspace(w, h)
	} else if a.inSFTPTab() {
		a.renderSFTP(w, h)
	} else {
		a.renderList(w, h)
	}
	status := a.footerText()
	if session := a.currentSession(); session != nil {
		if offset := a.scrollOffsetForSession(session); offset > 0 {
			status = fmt.Sprintf("[scrollback %d] %s", offset, status)
		}
	}
	drawText(a.screen, 0, h-1, tcell.StyleDefault.Foreground(tcell.ColorGray), truncate(status, w))
	if a.hasModal() {
		a.renderModal()
	}
	a.screen.Show()
}

func (a *App) footerText() string {
	prompt := a.footerPrompt()
	message := strings.TrimSpace(a.status)
	if message == "" {
		return prompt
	}
	if prompt == "" {
		return message
	}
	return message + " | " + prompt
}

func (a *App) footerPrompt() string {
	if a.inSessionTab() {
		if a.workspace == nil {
			return "HOST Enter/F7/F9 or LAYOUT Enter | F2 back | q/F10 quit"
		}
		return "F5 host | F7 split right | F9 split down | F6 next | Alt+Arrows focus | Ctrl+Alt+Arrows resize | F4 save | F8 close | F11 zoom | r reconnect | wheel scrollback | q/F10 quit"
	}
	if a.inSFTPTab() {
		if a.sftp == nil {
			return "go to HOST and press s/[ / ] | F2 back | q/F10 quit"
		}
		return "Tab pane | l local | / search | Enter open | Backspace parent | u upload | d download | n mkdir | x delete | R rename | g path | r refresh | c close | q/F10 quit"
	}
	enterAction := "Enter detail"
	if a.currentKind() == domain.KindHost {
		enterAction = "Enter workspace | F7/F9 split | s SFTP | [/] assign SFTP pane"
	} else if a.currentKind() == domain.KindForward {
		enterAction = "Enter/Space toggle"
	} else if a.currentKind() == domain.KindWorkspace {
		enterAction = "Enter open layout"
	}
	reloadAction := "r reload"
	if a.currentKind() == domain.KindForward {
		reloadAction = "r reload/reconnect"
	}
	return "click tabs/select | a add | d detail | e edit | Del/x delete | / filter | " + reloadAction + " | " + enterAction + " | q/F10 quit"
}

func (a *App) renderList(w, h int) {
	switch a.currentKind() {
	case domain.KindHost:
		a.renderHostList(w, h)
		return
	case domain.KindForward:
		a.renderForwardList(w, h)
		return
	}
	items := a.currentRecords()
	idWidth, labelWidth, updatedWidth := listColumnWidths(w, items)
	header := formatListRow("ID", "LABEL", "UPDATED", idWidth, labelWidth, updatedWidth)
	drawText(a.screen, 0, 1, tcell.StyleDefault.Foreground(tcell.ColorYellow), truncate(header, w))
	for i := 0; i < h-3 && i < len(items); i++ {
		item := items[i]
		style := tcell.StyleDefault
		if i == a.cursor {
			style = style.Background(tcell.ColorDarkSlateGray)
			fillRow(a.screen, 2+i, w, style)
		}
		line := formatListRow(item.ID, a.displayRecordLabel(a.currentKind(), item), item.UpdatedAt.Format(time.RFC3339), idWidth, labelWidth, updatedWidth)
		drawText(a.screen, 0, 2+i, style, truncate(line, w))
	}
}

func (a *App) renderHostList(w, h int) {
	items := a.currentRecords()
	idWidth, labelWidth, addressWidth, updatedWidth := hostListColumnWidths(w, items, a.hostAddresses)
	header := formatHostListRow("ID", "LABEL", "ADDRESS", "UPDATED", idWidth, labelWidth, addressWidth, updatedWidth)
	drawText(a.screen, 0, 1, tcell.StyleDefault.Foreground(tcell.ColorYellow), truncate(header, w))
	for i := 0; i < h-3 && i < len(items); i++ {
		item := items[i]
		style := tcell.StyleDefault
		if i == a.cursor {
			style = style.Background(tcell.ColorDarkSlateGray)
			fillRow(a.screen, 2+i, w, style)
		}
		line := formatHostListRow(item.ID, item.Label, a.hostAddresses[item.ID], item.UpdatedAt.Format(time.RFC3339), idWidth, labelWidth, addressWidth, updatedWidth)
		drawText(a.screen, 0, 2+i, style, truncate(line, w))
	}
}

func (a *App) renderForwardList(w, h int) {
	items := a.currentRecords()
	idWidth, labelWidth, statusWidth, reasonWidth, updatedWidth := forwardListColumnWidths(w, items, a)
	header := formatForwardListRow("ID", "LABEL", "STATUS", "REASON", "UPDATED", idWidth, labelWidth, statusWidth, reasonWidth, updatedWidth)
	drawText(a.screen, 0, 1, tcell.StyleDefault.Foreground(tcell.ColorYellow), truncate(header, w))
	for i := 0; i < h-3 && i < len(items); i++ {
		item := items[i]
		selected := i == a.cursor
		if selected {
			fillRow(a.screen, 2+i, w, tcell.StyleDefault.Background(tcell.ColorDarkSlateGray))
		}
		statusText, statusColor := a.forwardStatusDisplay(item.ID)
		reasonText := a.forwardReasonDisplay(item.ID)
		x := 0
		x = drawListColumn(a.screen, x, 2+i, item.ID, idWidth, tcell.ColorDefault, selected)
		x = drawListColumn(a.screen, x, 2+i, item.Label, labelWidth, tcell.ColorDefault, selected)
		x = drawListColumn(a.screen, x, 2+i, statusText, statusWidth, statusColor, selected)
		x = drawListColumn(a.screen, x, 2+i, reasonText, reasonWidth, tcell.ColorDefault, selected)
		drawListColumn(a.screen, x, 2+i, item.UpdatedAt.Format(time.RFC3339), updatedWidth, tcell.ColorDefault, selected)
	}
}

func (a *App) displayRecordLabel(kind domain.DocumentKind, item store.DocumentSummary) string {
	return item.Label
}

func (a *App) renderWorkspace(w, h int) {
	if a.workspace == nil {
		drawText(a.screen, 0, 2, tcell.StyleDefault, "No workspace. Go to HOST and press Enter/F7/F9, or open a LAYOUT.")
		return
	}
	rects := a.workspace.computeRects(0, 1, w, max(1, h-2))
	for _, pane := range a.workspace.leaves() {
		rect, ok := rects[pane.id]
		if !ok {
			continue
		}
		a.renderWorkspacePane(pane, rect)
	}
}

func (a *App) renderWorkspacePane(pane *workspacePane, rect workspaceRect) {
	if pane == nil || rect.w <= 0 || rect.h <= 0 {
		return
	}
	active := a.workspace != nil && a.workspace.focused == pane.id
	titleStyle := tcell.StyleDefault.Foreground(tcell.ColorYellow)
	if active {
		titleStyle = titleStyle.Background(tcell.ColorDarkCyan).Foreground(tcell.ColorWhite)
	}
	fillPartialRow(a.screen, rect.x, rect.y, rect.w, titleStyle)
	title := fmt.Sprintf(" %s [%s] ", workspacePaneLabel(pane), workspacePaneStatusLabel(pane))
	drawText(a.screen, rect.x, rect.y, titleStyle, truncate(title, rect.w))
	for y := rect.y; y < rect.y+rect.h; y++ {
		if rect.w > 0 {
			a.screen.SetContent(rect.x, y, ' ', nil, tcell.StyleDefault.Background(tcell.ColorDarkSlateGray))
			a.screen.SetContent(rect.x+rect.w-1, y, ' ', nil, tcell.StyleDefault.Background(tcell.ColorDarkSlateGray))
		}
	}
	if rect.h > 1 {
		for x := rect.x; x < rect.x+rect.w; x++ {
			a.screen.SetContent(x, rect.y+rect.h-1, ' ', nil, tcell.StyleDefault.Background(tcell.ColorDarkSlateGray))
		}
	}
	content := workspaceContentRect(rect)
	if pane.session == nil {
		message := "Empty pane. Press F5 to pick a Host."
		if pane.hostID != "" {
			message = "Pending SSH pane. Press Enter or F5 to connect."
		}
		drawText(a.screen, content.x, content.y, tcell.StyleDefault.Foreground(tcell.ColorGray), truncate(message, content.w))
		return
	}
	a.renderSessionInRect(pane.session, content)
}

func workspaceContentRect(rect workspaceRect) workspaceRect {
	return workspaceRect{x: rect.x + 1, y: rect.y + 1, w: max(0, rect.w-2), h: max(0, rect.h-2)}
}

func (a *App) renderSessionInRect(session *service.EmbeddedSession, rect workspaceRect) {
	if session == nil || session.Terminal == nil || rect.w <= 0 || rect.h <= 0 {
		return
	}
	view := session.Terminal
	view.Lock()
	defer view.Unlock()
	mode := view.Mode()
	viewCols, viewRows := view.Size()
	historyRows := accessibleScrollbackRows(view, mode)
	offset := clampInt(a.scrollOffsetForSession(session), 0, historyRows)
	if offset != a.scrollOffsetForSession(session) {
		a.scrollOffsets[session] = offset
	}
	maxCols := min(rect.w, viewCols)
	maxRows := min(rect.h, viewRows)
	startRow := historyRows - offset
	for y := 0; y < maxRows; y++ {
		bufferRow := startRow + y
		for x := 0; x < maxCols; x++ {
			cell := cellAt(view, historyRows, x, bufferRow)
			style := tcell.StyleDefault.Foreground(vtColor(cell.FG)).Background(vtColor(cell.BG))
			if a.selection.Session == session && a.selection.contains(viewCols, x, bufferRow) {
				style = style.Reverse(true)
			}
			ch := cell.Char
			if ch == 0 {
				continue
			}
			a.screen.SetContent(rect.x+x, rect.y+y, ch, nil, style)
		}
	}
	style := view.CursorStyle()
	if a.workspace != nil && a.workspace.focusedPane() != nil && a.workspace.focusedPane().session == session && offset == 0 && (!style.Blink || a.cursorBlinkOn) {
		a.renderSessionCursorAt(view, rect.x, rect.y, rect.w, maxRows)
	}
}

func (a *App) renderSessions(w, h int) {
	if len(a.sessions) == 0 {
		drawText(a.screen, 0, 2, tcell.StyleDefault, "No active sessions. Go to HOST and press Enter.")
		return
	}
	x := 0
	for idx, session := range a.sessions {
		label := a.sessionTabLabel(session)
		style := tcell.StyleDefault.Foreground(tcell.ColorBlack).Background(tcell.ColorSilver)
		if idx == a.activeSession {
			style = tcell.StyleDefault.Foreground(tcell.ColorWhite).Background(tcell.ColorDarkGreen)
		}
		drawText(a.screen, x, 1, style, label)
		x += len(label)
	}
	session := a.sessions[a.activeSession]
	view := session.Terminal
	view.Lock()
	defer view.Unlock()
	mode := view.Mode()
	viewCols, viewRows := view.Size()
	historyRows := accessibleScrollbackRows(view, mode)
	offset := clampInt(a.scrollOffsetForSession(session), 0, historyRows)
	if offset != a.scrollOffsetForSession(session) {
		a.scrollOffsets[session] = offset
	}
	maxCols := min(w, viewCols)
	maxRows := min(h-3, viewRows)
	startRow := historyRows - offset
	for y := 0; y < maxRows; y++ {
		bufferRow := startRow + y
		for x := 0; x < maxCols; x++ {
			cell := cellAt(view, historyRows, x, bufferRow)
			style := tcell.StyleDefault.Foreground(vtColor(cell.FG)).Background(vtColor(cell.BG))
			if a.selection.Session == session && a.selection.contains(viewCols, x, bufferRow) {
				style = style.Reverse(true)
			}
			ch := cell.Char
			if ch == 0 {
				continue
			}
			a.screen.SetContent(x, y+2, ch, nil, style)
		}
	}
	style := view.CursorStyle()
	if offset == 0 && (!style.Blink || a.cursorBlinkOn) {
		a.renderSessionCursorAt(view, 0, 2, w, maxRows)
	}
}

func (a *App) resetCursorBlink() {
	a.cursorBlinkOn = true
	a.cursorBlinkAt = time.Now().Add(500 * time.Millisecond)
}

func (a *App) renderSessionCursor(view termemu.Terminal, width, maxRows int) {
	a.renderSessionCursorAt(view, 0, 2, width, maxRows)
}

func (a *App) renderSessionCursorAt(view termemu.Terminal, originX, originY, width, maxRows int) {
	if !view.CursorVisible() {
		return
	}
	cursor := view.Cursor()
	if cursor.X < 0 || cursor.X >= width || cursor.Y < 0 || cursor.Y >= maxRows {
		return
	}
	cell := view.Cell(cursor.X, cursor.Y)
	cursorStyle := view.CursorStyle()
	style := tcell.StyleDefault.Foreground(vtColor(cell.FG)).Background(vtColor(cell.BG))
	ch := cell.Char
	if ch == 0 {
		ch = ' '
	}
	switch cursorStyle.Shape {
	case termemu.CursorShapeUnderline:
		style = style.Underline(true)
		if ch == ' ' {
			ch = '_'
		}
	case termemu.CursorShapeBar:
		style = style.Foreground(tcell.ColorWhite)
		ch = '▏'
	default:
		style = style.Reverse(true)
	}
	a.screen.SetContent(originX+cursor.X, originY+cursor.Y, ch, nil, style)
}

func (a *App) collectSessionUpdates() {
	if a.workspace != nil {
		a.collectWorkspaceUpdates()
		return
	}
	previous := a.currentSession()
	next := a.sessions[:0]
	for _, session := range a.sessions {
		select {
		case err := <-session.Done():
			if a.handleSessionDone(session, err) {
				next = append(next, session)
			}
		default:
			next = append(next, session)
		}
	}
	a.sessions = next
	if a.activeSession >= len(a.sessions) && len(a.sessions) > 0 {
		a.activeSession = len(a.sessions) - 1
	}
	a.transitionSessionFocus(previous, a.currentSession())
}

func (a *App) collectWorkspaceUpdates() {
	if a.workspace == nil {
		return
	}
	previous := a.currentSession()
	for _, pane := range a.workspace.leaves() {
		session := pane.session
		if session == nil {
			continue
		}
		if pane.runtime != nil && (pane.runtime.status == sessionStatusDisconnected || pane.runtime.status == sessionStatusFinished) {
			continue
		}
		select {
		case err := <-session.Done():
			a.handleWorkspaceSessionDone(pane, err)
		default:
		}
	}
	a.workspace.rebuildSessionIndex()
	a.transitionSessionFocus(previous, a.currentSession())
}

func (a *App) handleWorkspaceSessionDone(pane *workspacePane, err error) {
	if pane == nil || pane.session == nil {
		return
	}
	session := pane.session
	runtime := a.sessionRuntime(session)
	if pane.runtime != nil && pane.runtime != runtime {
		if runtime.hostID == "" {
			runtime.hostID = pane.runtime.hostID
		}
		if runtime.label == "" {
			runtime.label = pane.runtime.label
		}
		runtime.closing = runtime.closing || pane.runtime.closing
		runtime.prompted = runtime.prompted || pane.runtime.prompted
	}
	pane.runtime = runtime
	_ = session.Close()
	if runtime.closing {
		a.removeWorkspaceSession(pane)
		return
	}
	if sessionEndedNormally(err) {
		runtime.status = sessionStatusFinished
		runtime.reason = ""
		a.status = fmt.Sprintf("Session %q ended.", session.Name)
		pane.status = workspacePaneFinished
		pane.session = nil
		a.removeSessionRuntime(session)
		delete(a.scrollOffsets, session)
		if a.selection.Session == session {
			a.clearSelection()
		}
		return
	}
	runtime.status = sessionStatusDisconnected
	runtime.reason = err.Error()
	runtime.attempts = 0
	pane.status = workspacePaneDisconnected
	a.status = fmt.Sprintf("Session %q disconnected: %s", runtime.label, runtime.reason)
	if !runtime.prompted {
		runtime.prompted = true
		a.openWorkspaceReconnectConfirm(pane, runtime.reason)
	}
}

func (a *App) handleSessionDone(session *service.EmbeddedSession, err error) bool {
	runtime := a.sessionRuntime(session)
	_ = session.Close()
	if runtime.closing {
		a.removeFinishedSession(session)
		return false
	}
	if sessionEndedNormally(err) {
		runtime.status = sessionStatusFinished
		runtime.reason = ""
		a.status = fmt.Sprintf("Session %q ended.", session.Name)
		a.removeFinishedSession(session)
		return false
	}
	runtime.status = sessionStatusDisconnected
	runtime.reason = err.Error()
	runtime.attempts = 0
	a.status = fmt.Sprintf("Session %q disconnected: %s", runtime.label, runtime.reason)
	if !runtime.prompted {
		runtime.prompted = true
		a.openSessionReconnectConfirm(session, runtime.reason)
	}
	return true
}

func (a *App) removeFinishedSession(session *service.EmbeddedSession) {
	a.removeSessionRuntime(session)
	delete(a.scrollOffsets, session)
	if a.selection.Session == session {
		a.clearSelection()
	}
}

func (a *App) collectForwardUpdates() {
	if a.hasModal() {
		return
	}
	for id, runtime := range a.runningForwards {
		if runtime == nil || runtime.status != forwardStatusDisconnected || runtime.prompted {
			continue
		}
		runtime.prompted = true
		a.openForwardReconnectConfirm(id, firstNonEmpty(runtime.label, id), runtime.reason, runtime)
		return
	}
}

func (a *App) currentKind() domain.DocumentKind {
	if a.inSessionTab() {
		return workspaceTabKind
	}
	if a.inSFTPTab() {
		return sftpTabKind
	}
	return a.tabs[a.activeTab]
}

func (a *App) currentSession() *service.EmbeddedSession {
	if a.workspace != nil && a.inSessionTab() {
		if pane := a.workspace.focusedPane(); pane != nil {
			return pane.session
		}
	}
	if !a.inSessionTab() || a.activeSession < 0 || a.activeSession >= len(a.sessions) {
		return nil
	}
	return a.sessions[a.activeSession]
}

func (a *App) currentRecords() []store.DocumentSummary {
	return filterSummaries(a.records[a.currentKind()], a.filters[a.currentKind()])
}

func (a *App) selectedRecord() store.DocumentSummary {
	items := a.currentRecords()
	if a.cursor < 0 || a.cursor >= len(items) {
		return store.DocumentSummary{}
	}
	return items[a.cursor]
}

func (a *App) inSessionTab() bool {
	return a.activeTab == len(a.tabs)
}

func (a *App) openSelectedHostSession(ctx context.Context) error {
	record := a.selectedRecord()
	if record.ID == "" {
		return nil
	}
	return a.openHostInWorkspace(ctx, record.ID, record.Label, domain.WorkspaceSplitHorizontal)
}

func (a *App) openHostInWorkspace(ctx context.Context, hostID, label string, axis domain.WorkspaceSplitAxis) error {
	if strings.TrimSpace(hostID) == "" {
		return nil
	}
	a.ensureWorkspace()
	pane := a.workspace.focusedPane()
	if pane == nil {
		pane = newWorkspacePane(hostID, label)
		a.workspace.root = &workspaceNode{id: pane.id, pane: pane}
		a.workspace.focused = pane.id
	} else if pane.session == nil && pane.hostID == "" {
		pane.hostID = hostID
		pane.label = firstNonEmpty(label, hostID)
		pane.status = workspacePanePending
		pane.runtime = &sessionRuntime{hostID: hostID, label: pane.label, status: sessionStatusFinished}
	} else {
		next := newWorkspacePane(hostID, label)
		if _, err := a.workspace.splitFocused(axis, next); err != nil {
			return err
		}
		pane = next
	}
	if err := a.connectWorkspacePane(ctx, pane); err != nil {
		return err
	}
	a.setActiveTab(len(a.tabs))
	a.resetCursorBlink()
	return nil
}

func (a *App) ensureWorkspace() {
	if a.workspace == nil {
		a.workspace = newWorkspaceState()
	}
	if a.workspace.bySession == nil {
		a.workspace.rebuildSessionIndex()
	}
}

func (a *App) splitFocusedWorkspacePane(ctx context.Context, axis domain.WorkspaceSplitAxis, hostID, label string) error {
	a.ensureWorkspace()
	pane := newWorkspacePane(hostID, label)
	if _, err := a.workspace.splitFocused(axis, pane); err != nil {
		return err
	}
	a.setActiveTab(len(a.tabs))
	a.resizeWorkspaceSessions()
	if hostID != "" {
		return a.connectWorkspacePane(ctx, pane)
	}
	a.status = "Created empty workspace pane."
	return nil
}

func (a *App) duplicateFocusedWorkspacePane(ctx context.Context) error {
	if a.workspace == nil {
		return nil
	}
	pane := a.workspace.focusedPane()
	if pane == nil || pane.hostID == "" {
		a.status = "Focused pane has no Host to duplicate."
		return nil
	}
	return a.splitFocusedWorkspacePane(ctx, domain.WorkspaceSplitHorizontal, pane.hostID, pane.label)
}

func (a *App) connectWorkspacePane(ctx context.Context, pane *workspacePane) error {
	if pane == nil {
		return nil
	}
	a.ensureWorkspace()
	if strings.TrimSpace(pane.hostID) == "" {
		return a.openHostPickerForFocusedPane(ctx)
	}
	previous := a.currentSession()
	rect := workspaceContentRect(a.workspacePaneRect(pane.id))
	cols := max(1, rect.w)
	rows := max(1, rect.h)
	session, err := a.connector.OpenEmbeddedSession(ctx, pane.hostID, a.sessionPrompts(ctx), cols, rows)
	if err != nil {
		pane.status = workspacePaneDisconnected
		if pane.runtime == nil {
			pane.runtime = &sessionRuntime{hostID: pane.hostID, label: pane.label}
		}
		pane.runtime.status = sessionStatusDisconnected
		pane.runtime.reason = err.Error()
		return err
	}
	if a.clipboard != nil {
		session.SetClipboardHandler(func(value string) {
			_ = a.clipboard.WriteText(value)
		})
	}
	pane.session = session
	pane.hostID = firstNonEmpty(pane.hostID, session.Resolved.HostID)
	pane.label = firstNonEmpty(pane.label, session.Name)
	pane.status = workspacePaneConnected
	pane.runtime = &sessionRuntime{hostID: pane.hostID, label: pane.label, status: sessionStatusRunning}
	a.setSessionRuntime(session, pane.runtime)
	a.workspace.focused = pane.id
	a.workspace.rebuildSessionIndex()
	a.scrollToBottom(session)
	a.transitionSessionFocus(previous, session)
	a.status = ""
	return nil
}

func (a *App) workspacePaneRect(id workspacePaneID) workspaceRect {
	w, h := a.screenSizeOrDefault()
	if a.workspace == nil {
		return workspaceRect{x: 0, y: 1, w: w, h: max(1, h-2)}
	}
	if a.workspace.rects == nil {
		a.workspace.computeRects(0, 1, w, max(1, h-2))
	}
	if rect, ok := a.workspace.rects[id]; ok {
		return rect
	}
	return workspaceRect{x: 0, y: 1, w: w, h: max(1, h-2)}
}

func (a *App) openHostPickerForFocusedPane(ctx context.Context) error {
	a.ensureWorkspace()
	return openWorkspaceHostPicker(ctx, a, func(hostID, label string) {
		pane := a.workspace.focusedPane()
		if pane == nil {
			return
		}
		if pane.session != nil {
			a.status = "Focused pane is active. Split or close a pane before assigning a Host."
			return
		}
		pane.hostID = hostID
		pane.label = firstNonEmpty(label, hostID)
		pane.status = workspacePanePending
		pane.runtime = &sessionRuntime{hostID: hostID, label: pane.label, status: sessionStatusFinished}
		a.setActiveTab(len(a.tabs))
		a.status = fmt.Sprintf("Set pane to %s. Press Enter to connect.", pane.label)
	})
}

func (a *App) toggleSelectedForward(ctx context.Context) error {
	record := a.selectedRecord()
	if record.ID == "" {
		return nil
	}
	if a.runningForwards == nil {
		a.runningForwards = map[string]*forwardRuntime{}
	}
	if runtime := a.runningForwards[record.ID]; runtime != nil && runtime.active() {
		a.requestStopForward(record.ID, record.Label)
		return nil
	}

	if runtime := a.runningForwards[record.ID]; runtime != nil {
		runtime.stopping = true
		if runtime.cancel != nil {
			runtime.cancel()
		}
		delete(a.runningForwards, record.ID)
	}
	runCtx, cancel := context.WithCancel(ctx)
	runtime := &forwardRuntime{
		cancel: cancel,
		ctx:    runCtx,
		label:  record.Label,
		status: forwardStatusConnecting,
	}
	a.runningForwards[record.ID] = runtime
	running, err := a.connector.StartForward(runCtx, record.ID, a.sessionPrompts(ctx))
	if err != nil {
		cancel()
		runtime.status = forwardStatusError
		runtime.reason = err.Error()
		return err
	}
	runtime.running = running
	runtime.started = running.Started
	runtime.status = forwardStatusRunning
	runtime.reason = ""
	a.status = fmt.Sprintf("Started forward %q.", record.Label)
	go a.watchForward(record.ID, record.Label, runCtx, runtime)
	return nil
}

func (a *App) openSelectedWorkspaceLayout(ctx context.Context) error {
	record := a.selectedRecord()
	if record.ID == "" || a.currentKind() != domain.KindWorkspace {
		return nil
	}
	return a.openWorkspaceLayoutByID(ctx, record.ID)
}

func (a *App) openWorkspaceLayoutByID(ctx context.Context, id string) error {
	layout, err := a.catalog.GetWorkspace(ctx, id)
	if err != nil {
		return err
	}
	open := func() {
		previous := a.currentSession()
		a.closeSessionsNow()
		a.workspace = workspaceFromDomain(layout)
		a.status = fmt.Sprintf("Opened workspace layout %q.", layout.Name)
		a.setActiveTab(len(a.tabs))
		a.transitionSessionFocus(previous, a.currentSession())
	}
	if a.hasActiveWorkspaceSessions() {
		a.pushModal(modalState{
			kind: modalKindConfirm,
			confirm: &confirmModal{
				title: "Open Workspace",
				lines: wrapModalLines("Close the current workspace sessions and open "+layout.Name+"?", 68),
				onConfirm: func(context.Context, *App) error {
					open()
					return nil
				},
			},
		})
		return nil
	}
	open()
	return nil
}

func (a *App) openWorkspacePicker(ctx context.Context) error {
	return a.openRefPicker(ctx, "Open Workspace Layout", domain.KindWorkspace, false, func(item editorItem) {
		if item.ID == "" {
			return
		}
		if err := a.openWorkspaceLayoutByID(ctx, item.ID); err != nil {
			a.status = err.Error()
		}
	})
}

func (a *App) openSaveWorkspacePrompt(ctx context.Context) {
	if a.workspace == nil {
		a.status = "No workspace to save."
		return
	}
	defaultName := a.workspace.name
	if defaultName == "" {
		defaultName = "workspace"
	}
	a.pushModal(modalState{
		kind: modalKindTextInput,
		textInput: newTextInputModal("Save Workspace Layout", defaultName, false, false, func(app *App, value string) {
			value = strings.TrimSpace(value)
			if value == "" {
				app.status = "Workspace name is required."
				return
			}
			workspace := app.workspace.toDomain(value)
			if app.workspace.id != "" {
				workspace.ID = app.workspace.id
			} else if existing, err := app.catalog.ResolveDocument(ctx, domain.KindWorkspace, value); err == nil {
				workspace.ID = existing.ID
			}
			if workspace.ID != "" {
				if existing, err := app.catalog.GetWorkspace(ctx, workspace.ID); err == nil && existing != nil {
					workspace.Description = existing.Description
				}
			}
			if err := app.catalog.SaveWorkspace(ctx, workspace); err != nil {
				app.status = err.Error()
				return
			}
			app.workspace.id = workspace.ID
			app.workspace.name = workspace.Name
			if err := app.reload(ctx); err != nil {
				app.status = err.Error()
				return
			}
			app.status = fmt.Sprintf("Saved workspace layout %q.", workspace.Name)
		}),
	})
}

func (a *App) reconnectSelectedForward(ctx context.Context) bool {
	record := a.selectedRecord()
	if record.ID == "" || a.currentKind() != domain.KindForward {
		return false
	}
	runtime := a.runningForwards[record.ID]
	if runtime == nil || (runtime.status != forwardStatusDisconnected && runtime.status != forwardStatusError) {
		return false
	}
	go a.reconnectForward(ctx, record.ID, record.Label, runtime)
	return true
}

func (a *App) sessionRuntime(session *service.EmbeddedSession) *sessionRuntime {
	if session == nil {
		return &sessionRuntime{}
	}
	if a.sessionRuntimes == nil {
		a.sessionRuntimes = map[*service.EmbeddedSession]*sessionRuntime{}
	}
	runtime := a.sessionRuntimes[session]
	if runtime == nil {
		runtime = &sessionRuntime{
			hostID: session.Resolved.HostID,
			label:  session.Name,
			status: sessionStatusRunning,
		}
		a.sessionRuntimes[session] = runtime
	}
	if runtime.label == "" {
		runtime.label = session.Name
	}
	if runtime.hostID == "" {
		runtime.hostID = session.Resolved.HostID
	}
	return runtime
}

func (a *App) setSessionRuntime(session *service.EmbeddedSession, runtime *sessionRuntime) {
	if session == nil || runtime == nil {
		return
	}
	if a.sessionRuntimes == nil {
		a.sessionRuntimes = map[*service.EmbeddedSession]*sessionRuntime{}
	}
	a.sessionRuntimes[session] = runtime
}

func (a *App) removeSessionRuntime(session *service.EmbeddedSession) {
	if a.sessionRuntimes == nil {
		return
	}
	delete(a.sessionRuntimes, session)
}

func (a *App) sessionStatusLabel(session *service.EmbeddedSession) string {
	runtime := a.sessionRuntime(session)
	switch runtime.status {
	case sessionStatusDisconnected:
		return "disconnected"
	case sessionStatusReconnecting:
		return fmt.Sprintf("reconnecting %d/%d", runtime.attempts, service.MaxForwardReconnectAttempts)
	case sessionStatusFinished:
		return "finished"
	default:
		return ""
	}
}

func (a *App) sessionTabLabel(session *service.EmbeddedSession) string {
	if session == nil {
		return " [] "
	}
	if status := a.sessionStatusLabel(session); status != "" {
		return " [" + session.Name + ":" + status + "] "
	}
	return " [" + session.Name + "] "
}

func (a *App) reconnectCurrentSession(ctx context.Context) bool {
	if a.workspace != nil {
		pane := a.workspace.focusedPane()
		if pane == nil || pane.runtime == nil {
			return false
		}
		if pane.runtime.status != sessionStatusDisconnected && pane.runtime.status != sessionStatusFinished && pane.status != workspacePanePending {
			return false
		}
		a.reconnectWorkspacePane(ctx, pane)
		return true
	}
	session := a.currentSession()
	if session == nil {
		return false
	}
	runtime := a.sessionRuntime(session)
	if runtime.status != sessionStatusDisconnected && runtime.status != sessionStatusFinished {
		return false
	}
	a.reconnectSession(ctx, session)
	return true
}

func (a *App) openWorkspaceReconnectConfirm(pane *workspacePane, reason string) {
	if pane == nil {
		return
	}
	runtime := pane.runtime
	if runtime == nil {
		runtime = &sessionRuntime{hostID: pane.hostID, label: pane.label}
		pane.runtime = runtime
	}
	a.pushModal(modalState{
		kind: modalKindConfirm,
		confirm: &confirmModal{
			title: "Reconnect Session",
			lines: wrapModalLines(fmt.Sprintf("Session %s disconnected: %s\n\nReconnect now?", runtime.label, reason), 68),
			onConfirm: func(ctx context.Context, app *App) error {
				app.reconnectWorkspacePane(ctx, pane)
				return nil
			},
		},
	})
}

func (a *App) reconnectWorkspacePane(ctx context.Context, pane *workspacePane) {
	if pane == nil {
		return
	}
	runtime := pane.runtime
	if runtime == nil {
		runtime = &sessionRuntime{hostID: pane.hostID, label: pane.label}
		pane.runtime = runtime
	}
	if runtime.hostID == "" {
		runtime.hostID = pane.hostID
	}
	if runtime.hostID == "" {
		runtime.status = sessionStatusDisconnected
		runtime.reason = "missing host id for reconnect"
		a.status = runtime.reason
		return
	}
	runtime.prompted = false
	var reusableTerminal termemu.Terminal
	var oldSession *service.EmbeddedSession
	if pane.session != nil {
		oldSession = pane.session
		reusableTerminal = pane.session.Terminal
	}
	oldOffset := a.scrollOffsetForSession(oldSession)
	for attempt := 1; attempt <= service.MaxForwardReconnectAttempts; attempt++ {
		runtime.status = sessionStatusReconnecting
		runtime.attempts = attempt
		pane.status = workspacePaneReconnecting
		a.status = fmt.Sprintf("Reconnecting session %q %d/%d...", runtime.label, attempt, service.MaxForwardReconnectAttempts)
		if attempt > 1 && !sleepContext(ctx, service.ForwardReconnectDelay(attempt-1)) {
			return
		}
		rect := workspaceContentRect(a.workspacePaneRect(pane.id))
		next, err := a.connector.OpenEmbeddedSessionWithOptions(ctx, runtime.hostID, a.sessionPrompts(ctx), max(1, rect.w), max(1, rect.h), service.EmbeddedSessionOptions{
			Terminal: reusableTerminal,
		})
		if err != nil {
			runtime.reason = err.Error()
			continue
		}
		if a.clipboard != nil {
			next.SetClipboardHandler(func(value string) {
				_ = a.clipboard.WriteText(value)
			})
		}
		if oldSession != nil {
			a.removeSessionRuntime(oldSession)
			delete(a.scrollOffsets, oldSession)
		}
		pane.session = next
		pane.hostID = runtime.hostID
		pane.label = firstNonEmpty(runtime.label, next.Name)
		pane.status = workspacePaneConnected
		pane.runtime = &sessionRuntime{hostID: runtime.hostID, label: pane.label, status: sessionStatusRunning}
		a.setSessionRuntime(next, pane.runtime)
		if oldOffset > 0 {
			a.setScrollOffset(next, oldOffset, next.Terminal.ScrollbackRows())
		}
		if a.selection.Session == oldSession {
			a.clearSelection()
		}
		a.workspace.rebuildSessionIndex()
		a.status = fmt.Sprintf("Reconnected session %q.", pane.label)
		a.transitionSessionFocus(oldSession, a.currentSession())
		return
	}
	runtime.status = sessionStatusDisconnected
	runtime.attempts = service.MaxForwardReconnectAttempts
	pane.status = workspacePaneDisconnected
	a.status = fmt.Sprintf("Session %q reconnect failed: %s", runtime.label, runtime.reason)
	runtime.prompted = true
	a.openWorkspaceReconnectConfirm(pane, runtime.reason)
}

func (a *App) openSessionReconnectConfirm(session *service.EmbeddedSession, reason string) {
	runtime := a.sessionRuntime(session)
	a.pushModal(modalState{
		kind: modalKindConfirm,
		confirm: &confirmModal{
			title: "Reconnect Session",
			lines: wrapModalLines(fmt.Sprintf("Session %s disconnected: %s\n\nReconnect now?", runtime.label, reason), 68),
			onConfirm: func(ctx context.Context, app *App) error {
				app.reconnectSession(ctx, session)
				return nil
			},
		},
	})
}

func (a *App) reconnectSession(ctx context.Context, session *service.EmbeddedSession) {
	index := a.sessionIndex(session)
	if index < 0 {
		return
	}
	runtime := a.sessionRuntime(session)
	if runtime.hostID == "" {
		runtime.status = sessionStatusDisconnected
		runtime.reason = "missing host id for reconnect"
		a.status = runtime.reason
		return
	}
	runtime.prompted = false
	oldOffset := a.scrollOffsetForSession(session)
	for attempt := 1; attempt <= service.MaxForwardReconnectAttempts; attempt++ {
		runtime.status = sessionStatusReconnecting
		runtime.attempts = attempt
		a.status = fmt.Sprintf("Reconnecting session %q %d/%d...", runtime.label, attempt, service.MaxForwardReconnectAttempts)
		if attempt > 1 && !sleepContext(ctx, service.ForwardReconnectDelay(attempt-1)) {
			return
		}
		w, h := a.screenSizeOrDefault()
		next, err := a.connector.OpenEmbeddedSessionWithOptions(ctx, runtime.hostID, a.sessionPrompts(ctx), w, max(1, h-3), service.EmbeddedSessionOptions{
			Terminal: session.Terminal,
		})
		if err != nil {
			runtime.reason = err.Error()
			continue
		}
		if a.clipboard != nil {
			next.SetClipboardHandler(func(value string) {
				_ = a.clipboard.WriteText(value)
			})
		}
		nextRuntime := &sessionRuntime{
			hostID: runtime.hostID,
			label:  firstNonEmpty(runtime.label, next.Name),
			status: sessionStatusRunning,
		}
		a.sessions[index] = next
		a.setSessionRuntime(next, nextRuntime)
		a.removeSessionRuntime(session)
		delete(a.scrollOffsets, session)
		if oldOffset > 0 {
			a.setScrollOffset(next, oldOffset, next.Terminal.ScrollbackRows())
		}
		if a.selection.Session == session {
			a.clearSelection()
		}
		a.status = fmt.Sprintf("Reconnected session %q.", nextRuntime.label)
		a.transitionSessionFocus(session, a.currentSession())
		return
	}
	runtime.status = sessionStatusDisconnected
	runtime.attempts = service.MaxForwardReconnectAttempts
	a.status = fmt.Sprintf("Session %q reconnect failed: %s", runtime.label, runtime.reason)
	runtime.prompted = true
	a.openSessionReconnectConfirm(session, runtime.reason)
}

func (a *App) closeRunningForwards() {
	for id, runtime := range a.runningForwards {
		runtime.stopping = true
		if runtime.cancel != nil {
			runtime.cancel()
		}
		if runtime.running != nil {
			_ = runtime.running.Close()
		}
		delete(a.runningForwards, id)
	}
}

func (a *App) closeSessionsNow() {
	if a.workspace != nil {
		for _, pane := range a.workspace.leaves() {
			if pane.session == nil {
				continue
			}
			if pane.runtime != nil {
				pane.runtime.closing = true
			}
			_ = pane.session.Close()
			a.removeSessionRuntime(pane.session)
			delete(a.scrollOffsets, pane.session)
			pane.session = nil
			if pane.hostID != "" {
				pane.status = workspacePanePending
			} else {
				pane.status = workspacePaneEmpty
			}
		}
		a.workspace.rebuildSessionIndex()
	}
	for _, session := range a.sessions {
		if runtime := a.sessionRuntime(session); runtime != nil {
			runtime.closing = true
		}
		_ = session.Close()
	}
	a.sessions = nil
	a.sessionRuntimes = map[*service.EmbeddedSession]*sessionRuntime{}
	a.scrollOffsets = map[*service.EmbeddedSession]int{}
	a.clearSelection()
}

func (a *App) requestQuit() {
	if a.hasModal() {
		return
	}
	if !a.hasActiveSSHResource() {
		a.exitRequested = true
		return
	}
	a.pushModal(modalState{
		kind: modalKindConfirm,
		confirm: &confirmModal{
			title: "Quit Nermius",
			lines: wrapModalLines("Active SSH resources are still open. Quit and close them?", 68),
			onConfirm: func(context.Context, *App) error {
				a.exitRequested = true
				return nil
			},
		},
	})
}

func (a *App) requestCloseSession(index int) {
	if a.workspace != nil {
		a.requestCloseFocusedWorkspacePane()
		return
	}
	if a.hasModal() {
		return
	}
	if index < 0 || index >= len(a.sessions) {
		return
	}
	session := a.sessions[index]
	runtime := a.sessionRuntime(session)
	a.pushModal(modalState{
		kind: modalKindConfirm,
		confirm: &confirmModal{
			title: "Close Session",
			lines: wrapModalLines(fmt.Sprintf("Close session %s?", runtime.label), 68),
			onConfirm: func(context.Context, *App) error {
				if nextIndex := a.sessionIndex(session); nextIndex >= 0 {
					a.closeSessionAt(nextIndex)
				}
				return nil
			},
		},
	})
}

func (a *App) requestCloseFocusedWorkspacePane() {
	if a.hasModal() || a.workspace == nil {
		return
	}
	pane := a.workspace.focusedPane()
	if pane == nil {
		return
	}
	confirm := pane.session != nil
	if !confirm {
		a.closeWorkspacePane(pane.id)
		return
	}
	a.pushModal(modalState{
		kind: modalKindConfirm,
		confirm: &confirmModal{
			title: "Close Pane",
			lines: wrapModalLines(fmt.Sprintf("Close pane %s?", workspacePaneLabel(pane)), 68),
			onConfirm: func(context.Context, *App) error {
				a.closeWorkspacePane(pane.id)
				return nil
			},
		},
	})
}

func (a *App) closeWorkspacePane(id workspacePaneID) {
	if a.workspace == nil {
		return
	}
	previous := a.currentSession()
	pane := a.workspace.closePane(id)
	if pane != nil {
		a.removeWorkspaceSession(pane)
	}
	if a.workspace != nil && len(a.workspace.leaves()) == 1 {
		only := a.workspace.leaves()[0]
		if only.session == nil && only.hostID == "" && a.inSessionTab() {
			a.workspace = nil
			a.setActiveTab(0)
			a.transitionSessionFocus(previous, nil)
			return
		}
	}
	a.resizeWorkspaceSessions()
	a.transitionSessionFocus(previous, a.currentSession())
}

func (a *App) removeWorkspaceSession(pane *workspacePane) {
	if pane == nil || pane.session == nil {
		return
	}
	session := pane.session
	if pane.runtime != nil {
		pane.runtime.closing = true
	}
	_ = session.Close()
	a.removeSessionRuntime(session)
	delete(a.scrollOffsets, session)
	if a.selection.Session == session {
		a.clearSelection()
	}
	pane.session = nil
	if pane.hostID != "" {
		pane.status = workspacePanePending
		if pane.runtime != nil {
			pane.runtime.status = sessionStatusFinished
		}
	} else {
		pane.status = workspacePaneEmpty
	}
	if a.workspace != nil {
		a.workspace.rebuildSessionIndex()
	}
}

func (a *App) requestStopForward(id, label string) {
	if a.hasModal() {
		return
	}
	a.pushModal(modalState{
		kind: modalKindConfirm,
		confirm: &confirmModal{
			title: "Stop Forward",
			lines: wrapModalLines(fmt.Sprintf("Stop forward %s?", label), 68),
			onConfirm: func(context.Context, *App) error {
				a.stopForward(id, label)
				return nil
			},
		},
	})
}

func (a *App) stopForward(id, label string) {
	runtime := a.runningForwards[id]
	if runtime == nil {
		return
	}
	runtime.stopping = true
	if runtime.cancel != nil {
		runtime.cancel()
	}
	if runtime.running != nil {
		_ = runtime.running.Close()
	}
	runtime.running = nil
	runtime.status = forwardStatusStopped
	runtime.reason = "stopped by user"
	runtime.attempts = 0
	a.status = fmt.Sprintf("Stopped forward %q.", label)
}

func (a *App) hasActiveSSHResource() bool {
	if a.hasActiveWorkspaceSessions() {
		return true
	}
	if len(a.sessions) > 0 {
		return true
	}
	for _, runtime := range a.runningForwards {
		if runtime != nil && runtime.active() {
			return true
		}
	}
	return a.hasRemoteSFTPPane()
}

func (a *App) hasActiveWorkspaceSessions() bool {
	if a.workspace == nil {
		return false
	}
	for _, pane := range a.workspace.leaves() {
		if pane.session != nil {
			return true
		}
		if pane.runtime != nil && (pane.runtime.status == sessionStatusDisconnected || pane.runtime.status == sessionStatusReconnecting) {
			return true
		}
	}
	return false
}

func (a *App) watchForward(id, label string, ctx context.Context, runtime *forwardRuntime) {
	for {
		if runtime.running == nil {
			return
		}
		if runtime.label == "" {
			runtime.label = label
		}
		err := <-runtime.running.Done()
		if runtime.stopping || ctx.Err() != nil {
			return
		}
		if err == nil {
			err = errors.New("forward connection closed")
		}
		runtime.running = nil
		runtime.reason = err.Error()
		runtime.status = forwardStatusDisconnected
		runtime.attempts = 0
		runtime.prompted = false
		a.status = fmt.Sprintf("Forward %q disconnected: %s", label, runtime.reason)
		return
	}
}

func (a *App) openForwardReconnectConfirm(id, label, reason string, runtime *forwardRuntime) {
	a.pushModal(modalState{
		kind: modalKindConfirm,
		confirm: &confirmModal{
			title: "Reconnect Forward",
			lines: wrapModalLines(fmt.Sprintf("Forward %s disconnected: %s\n\nReconnect now?", label, reason), 68),
			onConfirm: func(ctx context.Context, app *App) error {
				go app.reconnectForward(ctx, id, label, runtime)
				return nil
			},
		},
	})
}

func (a *App) reconnectForward(ctx context.Context, id, label string, runtime *forwardRuntime) {
	if runtime == nil {
		return
	}
	runtime.prompted = false
	if runtime.ctx == nil || runtime.ctx.Err() != nil || runtime.cancel == nil {
		runCtx, cancel := context.WithCancel(ctx)
		runtime.ctx = runCtx
		runtime.cancel = cancel
	}
	ctx = runtime.ctx
	runtime.label = firstNonEmpty(runtime.label, label)
	for attempt := 1; attempt <= service.MaxForwardReconnectAttempts; attempt++ {
		runtime.status = forwardStatusReconnecting
		runtime.attempts = attempt
		a.status = fmt.Sprintf("Reconnecting forward %q %d/%d...", label, attempt, service.MaxForwardReconnectAttempts)
		if attempt > 1 && !sleepContext(ctx, service.ForwardReconnectDelay(attempt-1)) {
			return
		}
		next, err := a.connector.StartForward(ctx, id, a.backgroundForwardPrompts())
		if err != nil {
			runtime.reason = err.Error()
			continue
		}
		runtime.running = next
		runtime.started = next.Started
		runtime.status = forwardStatusRunning
		runtime.attempts = 0
		runtime.reason = ""
		runtime.stopping = false
		a.status = fmt.Sprintf("Reconnected forward %q.", label)
		go a.watchForward(id, label, ctx, runtime)
		return
	}
	runtime.status = forwardStatusDisconnected
	runtime.attempts = service.MaxForwardReconnectAttempts
	a.status = fmt.Sprintf("Forward %q reconnect failed: %s", label, runtime.reason)
	runtime.prompted = false
}

func (a *App) backgroundForwardPrompts() service.Prompts {
	return service.Prompts{
		Progress: func(message string) {
			a.status = message
		},
	}
}

func sleepContext(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (a *App) forwardSessionKey(ev *tcell.EventKey) error {
	session := a.currentSession()
	if session == nil {
		return nil
	}
	payload := sessionKeyBytes(ev)
	if len(payload) == 0 {
		return nil
	}
	runtime := a.sessionRuntime(session)
	if runtime.status == sessionStatusDisconnected || runtime.status == sessionStatusReconnecting || runtime.status == sessionStatusFinished {
		a.status = "Session is not connected. Press r to reconnect or F8 to close."
		return nil
	}
	a.scrollToBottom(session)
	return session.WriteKeys(payload)
}

func (a *App) handleSessionMouse(ev *tcell.EventMouse, prevButtons tcell.ButtonMask, prevX, prevY int) (bool, error) {
	session := a.currentSession()
	if session == nil {
		return false, nil
	}
	x, y := ev.Position()
	offsetX, offsetY := 0, 2
	if a.workspace != nil {
		pane := a.workspace.focusedPane()
		if pane == nil {
			return false, nil
		}
		rect := workspaceContentRect(a.workspacePaneRect(pane.id))
		if x < rect.x || x >= rect.x+rect.w || y < rect.y || y >= rect.y+rect.h {
			return false, nil
		}
		offsetX, offsetY = rect.x, rect.y
	}
	view := session.Terminal
	view.Lock()
	mode := view.Mode()
	cols, rows := view.Size()
	historyRows := accessibleScrollbackRows(view, mode)
	view.Unlock()

	if runtime := a.sessionRuntime(session); runtime.status == sessionStatusDisconnected || runtime.status == sessionStatusReconnecting || runtime.status == sessionStatusFinished {
		if ev.Buttons()&(tcell.WheelUp|tcell.WheelDown) != 0 {
			a.adjustScrollOffset(session, scrollDeltaForWheel(ev.Buttons()), historyRows)
		} else {
			a.status = "Session is not connected. Press r to reconnect or F8 to close."
		}
		return true, nil
	}

	if a.shouldUseLocalScrollback(ev, mode, historyRows) {
		a.adjustScrollOffset(session, scrollDeltaForWheel(ev.Buttons()), historyRows)
		return true, nil
	}

	if a.shouldUseLocalSelection(ev, mode, prevButtons) {
		return a.handleLocalSelectionMouse(session, ev, prevButtons, x-offsetX, y-offsetY, cols, rows, historyRows), nil
	}

	if mode&termemu.ModeMouseMask == 0 {
		return false, nil
	}
	a.scrollToBottom(session)
	if a.selection.Active && a.selection.Session == session {
		a.clearSelection()
	}
	payload := sessionMouseBytes(ev, prevButtons, prevX-offsetX, prevY-offsetY, x-offsetX, y-offsetY, mode)
	if len(payload) == 0 {
		return false, nil
	}
	return true, session.WriteKeys(payload)
}

func (a *App) shouldUseLocalScrollback(ev *tcell.EventMouse, mode termemu.ModeFlag, historyRows int) bool {
	if historyRows == 0 {
		return false
	}
	buttons := ev.Buttons()
	if buttons&(tcell.WheelUp|tcell.WheelDown) == 0 {
		return false
	}
	if ev.Modifiers()&tcell.ModShift != 0 {
		return true
	}
	return mode&termemu.ModeMouseMask == 0
}

func (a *App) shouldUseLocalSelection(ev *tcell.EventMouse, mode termemu.ModeFlag, prevButtons tcell.ButtonMask) bool {
	buttons := ev.Buttons()
	persistent := persistentMouseButtons(buttons)
	prevPersistent := persistentMouseButtons(prevButtons)
	if a.selection.Active && a.selection.Dragging && a.selection.Session == a.currentSession() &&
		(persistent&tcell.Button1 != 0 || prevPersistent&tcell.Button1 != 0) {
		return true
	}
	if ev.Modifiers()&tcell.ModShift != 0 && (persistent&tcell.Button1 != 0 || prevPersistent&tcell.Button1 != 0) {
		return true
	}
	if mode&termemu.ModeMouseMask != 0 {
		return false
	}
	return persistent&tcell.Button1 != 0 || prevPersistent&tcell.Button1 != 0
}

func (a *App) handleLocalSelectionMouse(session *service.EmbeddedSession, ev *tcell.EventMouse, prevButtons tcell.ButtonMask, x, y, cols, rows, historyRows int) bool {
	buttons := ev.Buttons()
	persistent := persistentMouseButtons(buttons)
	prevPersistent := persistentMouseButtons(prevButtons)
	pos, ok := clampSessionPosition(x, y, cols, rows)
	if !ok {
		if persistent == tcell.ButtonNone && a.selection.Session == session {
			a.selection.Dragging = false
		}
		return false
	}
	switch {
	case pressedPrimary(buttons, prevButtons):
		bufferY := historyRows - a.scrollOffsetForSession(session) + pos.Y
		a.selection = sessionSelection{
			Session:     session,
			Anchor:      cellPos{X: pos.X, Y: bufferY},
			Focus:       cellPos{X: pos.X, Y: bufferY},
			Dragging:    true,
			Active:      true,
			HistoryRows: historyRows,
		}
		return true
	case persistent&tcell.Button1 != 0 && prevPersistent&tcell.Button1 != 0 && a.selection.Active && a.selection.Session == session:
		a.selection.Focus = cellPos{X: pos.X, Y: historyRows - a.scrollOffsetForSession(session) + pos.Y}
		return true
	case persistent == tcell.ButtonNone && prevPersistent&tcell.Button1 != 0 && a.selection.Active && a.selection.Session == session:
		a.selection.Focus = cellPos{X: pos.X, Y: historyRows - a.scrollOffsetForSession(session) + pos.Y}
		a.selection.Dragging = false
		return true
	default:
		return false
	}
}

func sessionKeyBytes(ev *tcell.EventKey) []byte {
	switch ev.Key() {
	case tcell.KeyEnter:
		return []byte("\r")
	case tcell.KeyTAB:
		return []byte{'\t'}
	case tcell.KeyBacktab:
		return []byte("\x1b[Z")
	case tcell.KeyEscape:
		return []byte{0x1b}
	case tcell.KeyBackspace, tcell.KeyBackspace2:
		return []byte{0x7f}
	case tcell.KeyUp:
		return []byte("\x1b[A")
	case tcell.KeyDown:
		return []byte("\x1b[B")
	case tcell.KeyLeft:
		return []byte("\x1b[D")
	case tcell.KeyRight:
		return []byte("\x1b[C")
	case tcell.KeyHome:
		return []byte("\x1b[H")
	case tcell.KeyEnd:
		return []byte("\x1b[F")
	case tcell.KeyDelete:
		return []byte("\x1b[3~")
	case tcell.KeyInsert:
		return []byte("\x1b[2~")
	case tcell.KeyPgUp:
		return []byte("\x1b[5~")
	case tcell.KeyPgDn:
		return []byte("\x1b[6~")
	case tcell.KeyRune:
		payload := []byte(string(ev.Rune()))
		if ev.Modifiers()&tcell.ModAlt != 0 {
			return append([]byte{0x1b}, payload...)
		}
		return payload
	default:
		if control, ok := sessionControlKeyByte(ev.Key()); ok {
			return []byte{control}
		}
		return nil
	}
}

func sessionControlKeyByte(key tcell.Key) (byte, bool) {
	switch {
	case key == tcell.KeyCtrlSpace:
		return 0x00, true
	case key >= tcell.KeyCtrlA && key <= tcell.KeyCtrlZ:
		return byte(key-tcell.KeyCtrlA) + 1, true
	case key == tcell.KeyCtrlLeftSq:
		return 0x1b, true
	case key == tcell.KeyCtrlBackslash:
		return 0x1c, true
	case key == tcell.KeyCtrlRightSq:
		return 0x1d, true
	case key == tcell.KeyCtrlCarat:
		return 0x1e, true
	case key == tcell.KeyCtrlUnderscore:
		return 0x1f, true
	default:
		return 0, false
	}
}

func sessionMouseBytes(ev *tcell.EventMouse, prevButtons tcell.ButtonMask, prevX, prevY, x, y int, mode termemu.ModeFlag) []byte {
	if x < 0 || y < 0 {
		return nil
	}
	buttons := ev.Buttons()
	persistent := persistentMouseButtons(buttons)
	prevPersistent := persistentMouseButtons(prevButtons)
	moved := prevX != x || prevY != y
	modifiers := mouseModifierCode(ev.Modifiers())

	if base, ok := mouseWheelBase(buttons); ok {
		return encodeMouseSequence(base+modifiers, x, y, true, mode)
	}

	switch {
	case persistent == tcell.ButtonNone && prevPersistent != tcell.ButtonNone:
		if mode&(termemu.ModeMouseButton|termemu.ModeMouseMotion|termemu.ModeMouseMany) == 0 {
			return nil
		}
		base, ok := mouseButtonBase(prevPersistent)
		if !ok {
			return nil
		}
		return encodeMouseRelease(base+modifiers, x, y, mode)
	case persistent != tcell.ButtonNone && prevPersistent == tcell.ButtonNone:
		base, ok := mouseButtonBase(persistent)
		if !ok {
			return nil
		}
		return encodeMouseSequence(base+modifiers, x, y, true, mode)
	case persistent != tcell.ButtonNone && persistent == prevPersistent:
		if !moved || mode&(termemu.ModeMouseMotion|termemu.ModeMouseMany) == 0 {
			return nil
		}
		base, ok := mouseButtonBase(persistent)
		if !ok {
			return nil
		}
		return encodeMouseSequence(base+32+modifiers, x, y, true, mode)
	case persistent == tcell.ButtonNone && prevPersistent == tcell.ButtonNone:
		if !moved || mode&termemu.ModeMouseMany == 0 {
			return nil
		}
		return encodeMouseSequence(3+32+modifiers, x, y, true, mode)
	default:
		base, ok := mouseButtonBase(persistent)
		if !ok {
			return nil
		}
		return encodeMouseSequence(base+modifiers, x, y, true, mode)
	}
}

func encodeMouseSequence(code, x, y int, press bool, mode termemu.ModeFlag) []byte {
	if mode&termemu.ModeMouseSgr != 0 {
		final := 'M'
		if !press {
			final = 'm'
		}
		return []byte(fmt.Sprintf("\x1b[<%d;%d;%d%c", code, x+1, y+1, final))
	}
	if x > 222 || y > 222 {
		return nil
	}
	return []byte{0x1b, '[', 'M', byte(code + 32), byte(x + 33), byte(y + 33)}
}

func encodeMouseRelease(code, x, y int, mode termemu.ModeFlag) []byte {
	if mode&termemu.ModeMouseSgr != 0 {
		return encodeMouseSequence(code, x, y, false, mode)
	}
	return encodeMouseSequence(3+(code-code%4), x, y, true, mode)
}

func mouseButtonBase(buttons tcell.ButtonMask) (int, bool) {
	switch {
	case buttons&tcell.Button1 != 0:
		return 0, true
	case buttons&tcell.Button3 != 0:
		return 1, true
	case buttons&tcell.Button2 != 0:
		return 2, true
	default:
		return 0, false
	}
}

func mouseWheelBase(buttons tcell.ButtonMask) (int, bool) {
	switch {
	case buttons&tcell.WheelUp != 0:
		return 64, true
	case buttons&tcell.WheelDown != 0:
		return 65, true
	case buttons&tcell.WheelLeft != 0:
		return 66, true
	case buttons&tcell.WheelRight != 0:
		return 67, true
	default:
		return 0, false
	}
}

func mouseModifierCode(mod tcell.ModMask) int {
	code := 0
	if mod&tcell.ModShift != 0 {
		code += 4
	}
	if mod&tcell.ModAlt != 0 {
		code += 8
	}
	if mod&tcell.ModCtrl != 0 {
		code += 16
	}
	return code
}

func persistentMouseButtons(buttons tcell.ButtonMask) tcell.ButtonMask {
	return buttons &^ (tcell.WheelUp | tcell.WheelDown | tcell.WheelLeft | tcell.WheelRight)
}

func scrollDeltaForWheel(buttons tcell.ButtonMask) int {
	switch {
	case buttons&tcell.WheelUp != 0:
		return 3
	case buttons&tcell.WheelDown != 0:
		return -3
	default:
		return 0
	}
}

func pressedPrimary(buttons, prevButtons tcell.ButtonMask) bool {
	return buttons&tcell.Button1 != 0 && prevButtons&tcell.Button1 == 0
}

func tabIndexAt(x, y int, tabs []domain.DocumentKind) (int, bool) {
	if y != 0 || x < 0 {
		return 0, false
	}
	offset := 0
	for idx, kind := range tabs {
		label := " " + strings.ToUpper(string(kind)) + " "
		if x >= offset && x < offset+len(label) {
			return idx, true
		}
		offset += len(label)
	}
	return 0, false
}

func (a *App) sessionTabIndexAt(x, y int) (int, bool) {
	if y != 1 || x < 0 {
		return 0, false
	}
	offset := 0
	for idx, session := range a.sessions {
		label := a.sessionTabLabel(session)
		if x >= offset && x < offset+len(label) {
			return idx, true
		}
		offset += len(label)
	}
	return 0, false
}

func (a *App) sessionIndex(target *service.EmbeddedSession) int {
	for index, session := range a.sessions {
		if session == target {
			return index
		}
	}
	return -1
}

func (a *App) screenSizeOrDefault() (int, int) {
	if a.screen == nil {
		return 120, 35
	}
	w, h := a.screen.Size()
	if w <= 0 {
		w = 120
	}
	if h <= 0 {
		h = 35
	}
	return w, h
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func sessionEndedNormally(err error) bool {
	if err == nil {
		return true
	}
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		return true
	}
	return false
}

func isTransportDisconnect(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	message := strings.ToLower(err.Error())
	for _, marker := range []string{
		"connection reset",
		"broken pipe",
		"use of closed network connection",
		"connection refused",
		"connection aborted",
		"connection lost",
		"closed pipe",
		"eof",
	} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func sftpErrorStatus(err error) string {
	if err == nil {
		return ""
	}
	if isTransportDisconnect(err) {
		return "SFTP disconnected: " + err.Error()
	}
	return err.Error()
}

func (a *App) isDoubleClick(kind domain.DocumentKind, index int, now time.Time) bool {
	return a.lastClickTab == kind && a.lastClickIndex == index && now.Sub(a.lastClickAt) <= 400*time.Millisecond
}

func (a *App) recordClick(kind domain.DocumentKind, index int, now time.Time) {
	a.lastClickTab = kind
	a.lastClickIndex = index
	a.lastClickAt = now
}

func drawText(screen tcell.Screen, x, y int, style tcell.Style, value string) {
	col := x
	for _, ch := range value {
		if ch == 0 {
			continue
		}
		screen.SetContent(col, y, ch, nil, style)
		col += displayRuneWidth(ch)
	}
}

func displayRuneWidth(ch rune) int {
	width := uniseg.StringWidth(string(ch))
	if width < 1 {
		return 1
	}
	if width > 2 {
		return 2
	}
	return width
}

func fillRow(screen tcell.Screen, y, width int, style tcell.Style) {
	for x := 0; x < width; x++ {
		screen.SetContent(x, y, ' ', nil, style)
	}
}

func truncate(value string, width int) string {
	if width <= 0 {
		return ""
	}
	if len(value) <= width {
		return value
	}
	if width < 4 {
		return value[:width]
	}
	return value[:width-3] + "..."
}

func listColumnWidths(totalWidth int, items []store.DocumentSummary) (int, int, int) {
	const (
		columnGap        = 2
		defaultIDWidth   = 36
		minIDWidth       = 12
		minLabelWidth    = 12
		defaultTimeWidth = 20
	)
	updatedWidth := max(len("UPDATED"), defaultTimeWidth)
	for _, item := range items {
		updatedWidth = max(updatedWidth, len(item.UpdatedAt.Format(time.RFC3339)))
	}
	if totalWidth <= 0 {
		return minIDWidth, minLabelWidth, updatedWidth
	}
	maxIDWidth := totalWidth - updatedWidth - columnGap*2 - minLabelWidth
	idWidth := min(defaultIDWidth, max(minIDWidth, maxIDWidth))
	labelWidth := max(minLabelWidth, totalWidth-idWidth-updatedWidth-columnGap*2)
	return idWidth, labelWidth, updatedWidth
}

func formatListRow(id, label, updated string, idWidth, labelWidth, updatedWidth int) string {
	return fmt.Sprintf(
		"%-*s  %-*s  %-*s",
		idWidth, truncate(id, idWidth),
		labelWidth, truncate(label, labelWidth),
		updatedWidth, truncate(updated, updatedWidth),
	)
}

func hostListColumnWidths(totalWidth int, items []store.DocumentSummary, addresses map[string]string) (int, int, int, int) {
	const (
		columnGap        = 2
		defaultIDWidth   = 36
		minIDWidth       = 12
		minAddressWidth  = 12
		minLabelWidth    = 12
		maxLabelWidth    = 32
		defaultTimeWidth = 20
	)
	updatedWidth := max(len("UPDATED"), defaultTimeWidth)
	addressWidth := minAddressWidth
	labelWidth := minLabelWidth
	for _, item := range items {
		updatedWidth = max(updatedWidth, len(item.UpdatedAt.Format(time.RFC3339)))
		addressWidth = max(addressWidth, len(addresses[item.ID]))
		labelWidth = max(labelWidth, len(item.Label))
	}
	labelWidth = min(maxLabelWidth, max(labelWidth, len("LABEL")))
	addressWidth = max(addressWidth, len("ADDRESS"))
	if totalWidth <= 0 {
		return minIDWidth, minLabelWidth, minAddressWidth, updatedWidth
	}
	maxIDWidth := totalWidth - addressWidth - updatedWidth - columnGap*3 - minLabelWidth
	idWidth := min(defaultIDWidth, max(minIDWidth, maxIDWidth))
	availableLabel := totalWidth - idWidth - addressWidth - updatedWidth - columnGap*3
	if availableLabel < labelWidth {
		labelWidth = max(minLabelWidth, availableLabel)
	} else {
		addressWidth += availableLabel - labelWidth
	}
	return idWidth, labelWidth, addressWidth, updatedWidth
}

func formatHostListRow(id, label, address, updated string, idWidth, labelWidth, addressWidth, updatedWidth int) string {
	return fmt.Sprintf(
		"%-*s  %-*s  %-*s  %-*s",
		idWidth, truncate(id, idWidth),
		labelWidth, truncate(label, labelWidth),
		addressWidth, truncate(address, addressWidth),
		updatedWidth, truncate(updated, updatedWidth),
	)
}

func forwardListColumnWidths(totalWidth int, items []store.DocumentSummary, app *App) (int, int, int, int, int) {
	const (
		columnGap        = 2
		defaultIDWidth   = 36
		minIDWidth       = 12
		minStatusWidth   = 10
		minLabelWidth    = 12
		maxLabelWidth    = 32
		minReasonWidth   = 12
		defaultTimeWidth = 20
		maxStatusWidth   = 24
	)
	updatedWidth := max(len("UPDATED"), defaultTimeWidth)
	statusWidth := minStatusWidth
	reasonWidth := minReasonWidth
	labelWidth := minLabelWidth
	for _, item := range items {
		updatedWidth = max(updatedWidth, len(item.UpdatedAt.Format(time.RFC3339)))
		labelWidth = max(labelWidth, len(item.Label))
		statusText, _ := app.forwardStatusDisplay(item.ID)
		statusWidth = max(statusWidth, len(statusText))
		reasonWidth = max(reasonWidth, len(app.forwardReasonDisplay(item.ID)))
	}
	labelWidth = min(maxLabelWidth, max(labelWidth, len("LABEL")))
	statusWidth = min(maxStatusWidth, max(statusWidth, len("STATUS")))
	reasonWidth = max(reasonWidth, len("REASON"))
	if totalWidth <= 0 {
		return minIDWidth, minLabelWidth, minStatusWidth, minReasonWidth, updatedWidth
	}
	maxIDWidth := totalWidth - statusWidth - reasonWidth - updatedWidth - columnGap*4 - minLabelWidth
	idWidth := min(defaultIDWidth, max(minIDWidth, maxIDWidth))
	availableLabel := totalWidth - idWidth - statusWidth - reasonWidth - updatedWidth - columnGap*4
	if availableLabel < labelWidth {
		labelWidth = max(minLabelWidth, availableLabel)
	} else {
		reasonWidth += availableLabel - labelWidth
	}
	return idWidth, labelWidth, statusWidth, reasonWidth, updatedWidth
}

func formatForwardListRow(id, label, status, reason, updated string, idWidth, labelWidth, statusWidth, reasonWidth, updatedWidth int) string {
	return fmt.Sprintf(
		"%-*s  %-*s  %-*s  %-*s  %-*s",
		idWidth, truncate(id, idWidth),
		labelWidth, truncate(label, labelWidth),
		statusWidth, truncate(status, statusWidth),
		reasonWidth, truncate(reason, reasonWidth),
		updatedWidth, truncate(updated, updatedWidth),
	)
}

func drawListColumn(screen tcell.Screen, x, y int, value string, width int, foreground tcell.Color, selected bool) int {
	style := tcell.StyleDefault.Foreground(foreground)
	if selected {
		style = style.Background(tcell.ColorDarkSlateGray)
	}
	drawText(screen, x, y, style, truncate(fmt.Sprintf("%-*s", width, truncate(value, width)), width))
	return x + width + 2
}

func (a *App) forwardStatusDisplay(id string) (string, tcell.Color) {
	runtime := a.runningForwards[id]
	if runtime == nil {
		return "stopped", tcell.ColorDefault
	}
	switch runtime.status {
	case forwardStatusStopped:
		return "stopped", tcell.ColorDefault
	case forwardStatusConnecting:
		return "connecting", tcell.ColorYellow
	case forwardStatusRunning:
		return "running", tcell.ColorGreen
	case forwardStatusReconnecting:
		return fmt.Sprintf("reconnecting %d/%d", runtime.attempts, service.MaxForwardReconnectAttempts), tcell.ColorYellow
	case forwardStatusDisconnected:
		return "disconnected", tcell.ColorRed
	case forwardStatusError:
		return "error", tcell.ColorRed
	default:
		return "stopped", tcell.ColorDefault
	}
}

func (a *App) forwardReasonDisplay(id string) string {
	runtime := a.runningForwards[id]
	if runtime == nil {
		return ""
	}
	return runtime.reason
}

func hostAddressLabel(host domain.Host) string {
	port := 22
	if host.Port != nil && *host.Port > 0 {
		port = *host.Port
	}
	return fmt.Sprintf("%s:%d", host.Hostname, port)
}

func clampInt(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func vtColor(color termemu.Color) tcell.Color {
	switch color {
	case termemu.DefaultFG, termemu.DefaultBG, termemu.DefaultCursor:
		return tcell.ColorDefault
	}
	if color.ANSI() || color < 256 {
		return tcell.PaletteColor(int(color))
	}
	r := int32((color >> 16) & 0xff)
	g := int32((color >> 8) & 0xff)
	b := int32(color & 0xff)
	return tcell.NewRGBColor(r, g, b)
}

func accessibleScrollbackRows(view termemu.Terminal, mode termemu.ModeFlag) int {
	if mode&termemu.ModeAltScreen != 0 {
		return 0
	}
	return view.ScrollbackRows()
}

func (a *App) scrollOffsetForSession(session *service.EmbeddedSession) int {
	if session == nil || a.scrollOffsets == nil {
		return 0
	}
	return a.scrollOffsets[session]
}

func (a *App) setScrollOffset(session *service.EmbeddedSession, offset int, maxOffset int) {
	if session == nil {
		return
	}
	if a.scrollOffsets == nil {
		a.scrollOffsets = map[*service.EmbeddedSession]int{}
	}
	offset = clampInt(offset, 0, maxOffset)
	if offset == 0 {
		delete(a.scrollOffsets, session)
		return
	}
	a.scrollOffsets[session] = offset
}

func (a *App) scrollToBottom(session *service.EmbeddedSession) {
	a.setScrollOffset(session, 0, 0)
}

func (a *App) adjustScrollOffset(session *service.EmbeddedSession, delta int, maxOffset int) {
	if session == nil || delta == 0 {
		return
	}
	a.setScrollOffset(session, a.scrollOffsetForSession(session)+delta, maxOffset)
}

func (a *App) focusNextWorkspacePane() {
	if a.workspace == nil {
		return
	}
	previous := a.currentSession()
	a.workspace.focusNext()
	a.transitionSessionFocus(previous, a.currentSession())
}

func (a *App) focusWorkspacePaneAt(x, y int) {
	if a.workspace == nil {
		return
	}
	previous := a.currentSession()
	if a.workspace.focusPaneAt(x, y) {
		a.transitionSessionFocus(previous, a.currentSession())
	}
}

func (a *App) focusWorkspaceDirection(dx, dy int) {
	if a.workspace == nil {
		return
	}
	previous := a.currentSession()
	if a.workspace.focusDirection(dx, dy) {
		a.transitionSessionFocus(previous, a.currentSession())
	}
}

func (a *App) resizeFocusedWorkspacePane(dx, dy int) {
	if a.workspace == nil {
		return
	}
	w, h := a.screenSizeOrDefault()
	if a.workspace.resizeFocused(dx, dy, w, max(1, h-2)) {
		a.resizeWorkspaceSessions()
	}
}

func (a *App) resizeWorkspaceSessions() {
	if a.workspace == nil {
		if a.inSessionTab() && a.activeSession < len(a.sessions) {
			w, h := a.screenSizeOrDefault()
			_ = a.sessions[a.activeSession].Resize(w, max(1, h-3))
		}
		return
	}
	w, h := a.screenSizeOrDefault()
	rects := a.workspace.computeRects(0, 1, w, max(1, h-2))
	for _, pane := range a.workspace.leaves() {
		if pane.session == nil {
			continue
		}
		rect := workspaceContentRect(rects[pane.id])
		_ = pane.session.Resize(max(1, rect.w), max(1, rect.h))
	}
}

func (a *App) setActiveTab(index int) {
	if index < 0 || index > a.sftpTabIndex() {
		return
	}
	previous := a.currentSession()
	a.activeTab = index
	a.transitionSessionFocus(previous, a.currentSession())
}

func (a *App) moveActiveTab(delta int) {
	if delta == 0 {
		return
	}
	next := a.activeTab + delta
	if next < 0 || next > a.sftpTabIndex() {
		return
	}
	a.setActiveTab(next)
	a.cursor = 0
}

func (a *App) setActiveSession(index int) {
	if index < 0 || index >= len(a.sessions) {
		return
	}
	previous := a.currentSession()
	a.activeSession = index
	a.transitionSessionFocus(previous, a.currentSession())
}

func (a *App) setFocused(focused bool) {
	if a.focused == focused {
		return
	}
	a.focused = focused
	if session := a.currentSession(); session != nil {
		_ = session.SendFocus(focused)
	}
}

func (a *App) transitionSessionFocus(previous, next *service.EmbeddedSession) {
	if previous == next {
		return
	}
	if a.focused && previous != nil {
		_ = previous.SendFocus(false)
	}
	if a.focused && next != nil {
		_ = next.SendFocus(true)
	}
}

func (a *App) clearSelection() {
	a.selection = sessionSelection{}
}

func (a *App) closeSessionAt(index int) {
	if index < 0 || index >= len(a.sessions) {
		return
	}
	previous := a.currentSession()
	session := a.sessions[index]
	runtime := a.sessionRuntime(session)
	runtime.closing = true
	_ = session.Close()
	a.sessions = append(a.sessions[:index], a.sessions[index+1:]...)
	a.removeSessionRuntime(session)
	delete(a.scrollOffsets, session)
	if a.selection.Session == session {
		a.clearSelection()
	}
	if len(a.sessions) == 0 {
		a.activeSession = 0
		if a.inSessionTab() {
			a.setActiveTab(0)
		}
	} else if a.activeSession >= len(a.sessions) {
		a.activeSession = len(a.sessions) - 1
	}
	a.transitionSessionFocus(previous, a.currentSession())
}

func (a *App) copySelection() {
	session := a.currentSession()
	if session == nil {
		return
	}
	if !a.selection.Active || a.selection.Session != session {
		a.status = "No active selection to copy."
		return
	}
	if a.clipboard == nil {
		a.status = "Clipboard is unavailable."
		return
	}
	text := extractSelection(session.Terminal, a.selection)
	if text == "" {
		a.status = "Selection is empty."
		return
	}
	if err := a.clipboard.WriteText(text); err != nil {
		a.status = clipboardStatus("Clipboard write failed", err)
		return
	}
	a.status = fmt.Sprintf("Copied %d bytes.", len(text))
}

func (a *App) pasteClipboard() {
	session := a.currentSession()
	if session == nil {
		return
	}
	if a.clipboard == nil {
		a.status = "Clipboard is unavailable."
		return
	}
	text, err := a.clipboard.ReadText()
	if err != nil {
		a.status = clipboardStatus("Clipboard read failed", err)
		return
	}
	if err := session.Paste(text); err != nil {
		a.status = err.Error()
		return
	}
	a.status = fmt.Sprintf("Pasted %d bytes.", len(text))
}

func clipboardStatus(prefix string, err error) string {
	if clipboard.IsUnavailable(err) {
		return "Clipboard is unavailable on this system."
	}
	return fmt.Sprintf("%s: %v", prefix, err)
}

func isCopyShortcut(ev *tcell.EventKey) bool {
	return isCtrlShiftRune(ev, 'c') || (ev.Key() == tcell.KeyCtrlC && ev.Modifiers()&tcell.ModShift != 0)
}

func isPasteShortcut(ev *tcell.EventKey) bool {
	return isCtrlShiftRune(ev, 'v') || (ev.Key() == tcell.KeyCtrlV && ev.Modifiers()&tcell.ModShift != 0)
}

func isCtrlShiftRune(ev *tcell.EventKey, want rune) bool {
	if ev.Modifiers()&tcell.ModCtrl == 0 || ev.Modifiers()&tcell.ModShift == 0 {
		return false
	}
	if ev.Key() != tcell.KeyRune {
		return false
	}
	return strings.EqualFold(string(ev.Rune()), string(want))
}

func (a *App) sessionPrompts(ctx context.Context) service.Prompts {
	return service.Prompts{
		Text: func(label string) (string, error) {
			return a.promptTextModal(ctx, label, false)
		},
		Secret: func(label string) (string, error) {
			return a.promptTextModal(ctx, label, true)
		},
		Confirm: func(label string) (bool, error) {
			return a.promptConfirmModal(ctx, label)
		},
		Progress: func(message string) {
			a.status = "Connecting: " + message
			a.render()
		},
	}
}

func (a *App) promptTextModal(ctx context.Context, label string, secret bool) (string, error) {
	if a.events == nil {
		return "", errors.New("TUI prompt event loop is unavailable")
	}
	var (
		value string
		saved bool
	)
	a.pushModal(modalState{
		kind: modalKindTextInput,
		textInput: newTextInputModal(label, "", false, secret, func(app *App, input string) {
			value = input
			saved = true
		}),
	})
	if err := a.runBlockingPromptLoop(ctx); err != nil {
		return "", err
	}
	if !saved {
		return "", errors.New("prompt canceled")
	}
	return strings.TrimSpace(value), nil
}

func (a *App) promptConfirmModal(ctx context.Context, label string) (bool, error) {
	if a.events == nil {
		return false, errors.New("TUI prompt event loop is unavailable")
	}
	approved := false
	a.pushModal(modalState{
		kind: modalKindConfirm,
		confirm: &confirmModal{
			title: "Confirm",
			lines: append(wrapModalLines(label, 68), "", "Approve?"),
			onConfirm: func(ctx context.Context, app *App) error {
				approved = true
				return nil
			},
		},
	})
	if err := a.runBlockingPromptLoop(ctx); err != nil {
		return false, err
	}
	return approved, nil
}

func (a *App) runBlockingPromptLoop(ctx context.Context) error {
	startDepth := len(a.modals)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for len(a.modals) >= startDepth {
		a.render()
		select {
		case <-ctx.Done():
			for len(a.modals) >= startDepth {
				a.popModal()
			}
			return ctx.Err()
		case <-tick.C:
			now := time.Now()
			if !now.Before(a.cursorBlinkAt) {
				a.cursorBlinkOn = !a.cursorBlinkOn
				a.cursorBlinkAt = now.Add(500 * time.Millisecond)
			}
			a.collectSessionUpdates()
			a.collectForwardUpdates()
		case ev := <-a.events:
			if err := a.handlePromptEvent(ctx, ev); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *App) handlePromptEvent(ctx context.Context, ev tcell.Event) error {
	switch event := ev.(type) {
	case *tcell.EventResize:
		a.screen.Sync()
		a.resizeWorkspaceSessions()
	case *tcell.EventFocus:
		a.setFocused(event.Focused)
	case *tcell.EventKey:
		if done, err := a.handleModalKey(ctx, event); done || err != nil {
			return err
		}
	case *tcell.EventMouse:
		if done, err := a.handleModalMouse(ctx, event); done || err != nil {
			return err
		}
	}
	return nil
}

func wrapModalLines(text string, width int) []string {
	var out []string
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			out = append(out, "")
			continue
		}
		for len(line) > width {
			cut := strings.LastIndex(line[:width], " ")
			if cut <= 0 {
				cut = width
			}
			out = append(out, strings.TrimSpace(line[:cut]))
			line = strings.TrimSpace(line[cut:])
		}
		out = append(out, line)
	}
	return out
}
