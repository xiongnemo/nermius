package tui

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"golang.org/x/term"

	"github.com/nermius/nermius/internal/clipboard"
	"github.com/nermius/nermius/internal/domain"
	"github.com/nermius/nermius/internal/service"
	"github.com/nermius/nermius/internal/store"
	"github.com/nermius/nermius/internal/termemu"
)

type App struct {
	catalog   *service.Catalog
	connector *service.Connector
	screen    tcell.Screen
	clipboard clipboard.Adapter

	tabs             []domain.DocumentKind
	activeTab        int
	cursor           int
	records          map[domain.DocumentKind][]store.DocumentSummary
	sessions         []*service.EmbeddedSession
	activeSession    int
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
}

func Run(ctx context.Context, catalog *service.Catalog, connector *service.Connector) error {
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
		tabs: []domain.DocumentKind{
			domain.KindHost,
			domain.KindGroup,
			domain.KindProfile,
			domain.KindIdentity,
			domain.KindForward,
		},
		records:        map[domain.DocumentKind][]store.DocumentSummary{},
		status:         "click tabs/select | wheel scrollback | drag select | Shift forces local mouse | Ctrl+Shift+C/V copy/paste | F2 back | F6 next | F8 close | F10 quit",
		cursorBlinkOn:  true,
		cursorBlinkAt:  time.Now().Add(500 * time.Millisecond),
		lastMouseX:     -1,
		lastMouseY:     -1,
		lastClickIndex: -1,
		focused:        true,
		scrollOffsets:  map[*service.EmbeddedSession]int{},
	}
	if err := app.reload(ctx); err != nil {
		return err
	}
	return app.loop(ctx)
}

func (a *App) loop(ctx context.Context) error {
	events := make(chan tcell.Event, 16)
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
		case ev := <-events:
			switch event := ev.(type) {
			case *tcell.EventResize:
				a.screen.Sync()
				if a.inSessionTab() && a.activeSession < len(a.sessions) {
					w, h := a.screen.Size()
					_ = a.sessions[a.activeSession].Resize(w, max(1, h-3))
				}
			case *tcell.EventFocus:
				a.setFocused(event.Focused)
			case *tcell.EventKey:
				if done, err := a.handleKey(ctx, event); done {
					return err
				}
			case *tcell.EventMouse:
				if done, err := a.handleMouse(ctx, event); done {
					return err
				}
			}
		}
	}
}

func (a *App) handleKey(ctx context.Context, ev *tcell.EventKey) (bool, error) {
	if a.inSessionTab() && a.activeSession < len(a.sessions) {
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
			return true, nil
		case tcell.KeyF2:
			if len(a.tabs) > 0 {
				a.setActiveTab(len(a.tabs) - 1)
			}
			return false, nil
		case tcell.KeyF6:
			if len(a.sessions) > 0 {
				a.setActiveSession((a.activeSession + 1) % len(a.sessions))
			}
			a.resetCursorBlink()
			return false, nil
		case tcell.KeyF8:
			a.closeSessionAt(a.activeSession)
			a.resetCursorBlink()
			return false, nil
		case tcell.KeyEscape:
			if a.selection.Active && a.selection.Session == a.currentSession() {
				a.clearSelection()
				return false, nil
			}
			a.resetCursorBlink()
			return false, a.forwardSessionKey(ev)
		default:
			a.resetCursorBlink()
			return false, a.forwardSessionKey(ev)
		}
	}
	switch ev.Key() {
	case tcell.KeyEscape, tcell.KeyCtrlC, tcell.KeyF10:
		return true, nil
	case tcell.KeyLeft:
		if a.activeTab > 0 {
			a.setActiveTab(a.activeTab - 1)
			a.cursor = 0
		}
	case tcell.KeyRight:
		if a.activeTab < len(a.tabs) {
			a.setActiveTab(a.activeTab + 1)
			a.cursor = 0
		}
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
		}
	case tcell.KeyCtrlR:
		if err := a.reload(ctx); err != nil {
			a.status = err.Error()
		}
	default:
		if ev.Rune() == 'q' {
			return true, nil
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
		if tab, ok := tabIndexAt(x, y, append(a.tabs, domain.DocumentKind("sessions"))); ok {
			a.setActiveTab(tab)
			a.cursor = 0
			a.resetCursorBlink()
			return false, nil
		}
	}

	if a.inSessionTab() {
		if pressedPrimary(buttons, prevButtons) {
			if idx, ok := sessionTabIndexAt(x, y, a.sessions); ok {
				a.setActiveSession(idx)
				a.resetCursorBlink()
				return false, nil
			}
		}
		if y >= 2 {
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

	a.handleListMouse(ctx, y, buttons, prevButtons)
	return false, nil
}

func (a *App) reload(ctx context.Context) error {
	for _, kind := range a.tabs {
		items, err := a.catalog.List(ctx, kind)
		if err != nil {
			return err
		}
		a.records[kind] = items
	}
	return nil
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
	for idx, kind := range append(a.tabs, domain.DocumentKind("sessions")) {
		label := " " + strings.ToUpper(string(kind)) + " "
		style := tabStyle
		if idx == a.activeTab {
			style = activeStyle
		}
		drawText(a.screen, x, 0, style, label)
		x += len(label)
	}
	if a.inSessionTab() {
		a.renderSessions(w, h)
	} else {
		a.renderList(w, h)
	}
	status := a.status
	if session := a.currentSession(); session != nil {
		if offset := a.scrollOffsetForSession(session); offset > 0 {
			status = fmt.Sprintf("[scrollback %d] %s", offset, status)
		}
	}
	drawText(a.screen, 0, h-1, tcell.StyleDefault.Foreground(tcell.ColorGray), truncate(status, w))
	a.screen.Show()
}

func (a *App) renderList(w, h int) {
	items := a.currentRecords()
	header := fmt.Sprintf("%-38s %-24s %s", "ID", "LABEL", "UPDATED")
	drawText(a.screen, 0, 1, tcell.StyleDefault.Foreground(tcell.ColorYellow), truncate(header, w))
	for i := 0; i < h-3 && i < len(items); i++ {
		item := items[i]
		style := tcell.StyleDefault
		if i == a.cursor {
			style = style.Background(tcell.ColorDarkSlateGray)
		}
		line := fmt.Sprintf("%-38s %-24s %s", item.ID, truncate(item.Label, 24), item.UpdatedAt.Format(time.RFC3339))
		drawText(a.screen, 0, 2+i, style, truncate(line, w))
	}
}

func (a *App) renderSessions(w, h int) {
	if len(a.sessions) == 0 {
		drawText(a.screen, 0, 2, tcell.StyleDefault, "No active sessions. Go to HOST and press Enter.")
		return
	}
	x := 0
	for idx, session := range a.sessions {
		label := " [" + session.Name + "] "
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
				ch = ' '
			}
			a.screen.SetContent(x, y+2, ch, nil, style)
		}
	}
	style := view.CursorStyle()
	if offset == 0 && (!style.Blink || a.cursorBlinkOn) {
		a.renderSessionCursor(view, w, maxRows)
	}
}

func (a *App) resetCursorBlink() {
	a.cursorBlinkOn = true
	a.cursorBlinkAt = time.Now().Add(500 * time.Millisecond)
}

func (a *App) renderSessionCursor(view termemu.Terminal, width, maxRows int) {
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
	a.screen.SetContent(cursor.X, cursor.Y+2, ch, nil, style)
}

func (a *App) collectSessionUpdates() {
	previous := a.currentSession()
	next := a.sessions[:0]
	for _, session := range a.sessions {
		select {
		case err := <-session.Done():
			if err != nil {
				a.status = err.Error()
			}
			_ = session.Close()
			delete(a.scrollOffsets, session)
			if a.selection.Session == session {
				a.clearSelection()
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

func (a *App) currentKind() domain.DocumentKind {
	if a.activeTab >= len(a.tabs) {
		return domain.DocumentKind("sessions")
	}
	return a.tabs[a.activeTab]
}

func (a *App) currentSession() *service.EmbeddedSession {
	if !a.inSessionTab() || a.activeSession < 0 || a.activeSession >= len(a.sessions) {
		return nil
	}
	return a.sessions[a.activeSession]
}

func (a *App) currentRecords() []store.DocumentSummary {
	return a.records[a.currentKind()]
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
	w, h := a.screen.Size()
	session, err := a.connector.OpenEmbeddedSession(ctx, record.ID, service.Prompts{
		Text:    promptTextScreen(a.screen),
		Secret:  promptSecretScreen(a.screen),
		Confirm: promptConfirmScreen(a.screen),
	}, w, max(1, h-3))
	if err != nil {
		return err
	}
	if a.clipboard != nil {
		session.SetClipboardHandler(func(value string) {
			_ = a.clipboard.WriteText(value)
		})
	}
	a.sessions = append(a.sessions, session)
	a.scrollToBottom(session)
	a.setActiveTab(len(a.tabs))
	a.setActiveSession(len(a.sessions) - 1)
	a.resetCursorBlink()
	return nil
}

func (a *App) forwardSessionKey(ev *tcell.EventKey) error {
	if a.activeSession >= len(a.sessions) {
		return nil
	}
	payload := sessionKeyBytes(ev)
	if len(payload) == 0 {
		return nil
	}
	session := a.sessions[a.activeSession]
	a.scrollToBottom(session)
	return session.WriteKeys(payload)
}

func (a *App) handleSessionMouse(ev *tcell.EventMouse, prevButtons tcell.ButtonMask, prevX, prevY int) (bool, error) {
	session := a.currentSession()
	if session == nil {
		return false, nil
	}
	x, y := ev.Position()
	view := session.Terminal
	view.Lock()
	mode := view.Mode()
	cols, rows := view.Size()
	historyRows := accessibleScrollbackRows(view, mode)
	view.Unlock()

	if a.shouldUseLocalScrollback(ev, mode, historyRows) {
		a.adjustScrollOffset(session, scrollDeltaForWheel(ev.Buttons()), historyRows)
		return true, nil
	}

	if a.shouldUseLocalSelection(ev, mode, prevButtons) {
		return a.handleLocalSelectionMouse(session, ev, prevButtons, x, y-2, cols, rows, historyRows), nil
	}

	if mode&termemu.ModeMouseMask == 0 {
		return false, nil
	}
	a.scrollToBottom(session)
	if a.selection.Active && a.selection.Session == session {
		a.clearSelection()
	}
	payload := sessionMouseBytes(ev, prevButtons, prevX, prevY, x, y-2, mode)
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

func sessionTabIndexAt(x, y int, sessions []*service.EmbeddedSession) (int, bool) {
	if y != 1 || x < 0 {
		return 0, false
	}
	offset := 0
	for idx, session := range sessions {
		label := " [" + session.Name + "] "
		if x >= offset && x < offset+len(label) {
			return idx, true
		}
		offset += len(label)
	}
	return 0, false
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
	for i, ch := range value {
		screen.SetContent(x+i, y, ch, nil, style)
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

func (a *App) setActiveTab(index int) {
	if index < 0 || index > len(a.tabs) {
		return
	}
	previous := a.currentSession()
	a.activeTab = index
	a.transitionSessionFocus(previous, a.currentSession())
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
	_ = session.Close()
	a.sessions = append(a.sessions[:index], a.sessions[index+1:]...)
	delete(a.scrollOffsets, session)
	if a.selection.Session == session {
		a.clearSelection()
	}
	if len(a.sessions) == 0 {
		a.activeSession = 0
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

func promptTextScreen(screen tcell.Screen) func(string) (string, error) {
	return func(label string) (string, error) {
		screen.Fini()
		defer reinitScreen(screen)
		fmt.Fprintf(os.Stderr, "%s: ", label)
		return readScreenPromptLine()
	}
}

func promptSecretScreen(screen tcell.Screen) func(string) (string, error) {
	return func(label string) (string, error) {
		screen.Fini()
		defer reinitScreen(screen)
		fmt.Fprintf(os.Stderr, "%s: ", label)
		value, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return strings.TrimSpace(string(value)), err
	}
}

func promptConfirmScreen(screen tcell.Screen) func(string) (bool, error) {
	return func(label string) (bool, error) {
		screen.Fini()
		defer reinitScreen(screen)
		for {
			fmt.Fprintf(os.Stderr, "%s [y/N]: ", label)
			value, err := readScreenPromptLine()
			if err != nil {
				return false, err
			}
			switch strings.ToLower(value) {
			case "y", "yes":
				return true, nil
			case "", "n", "no":
				return false, nil
			default:
				fmt.Fprintln(os.Stderr, "Please answer y or n.")
			}
		}
	}
}

func readScreenPromptLine() (string, error) {
	reader := bufio.NewReader(os.Stdin)
	value, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(value), nil
}

func reinitScreen(screen tcell.Screen) {
	_ = screen.Init()
	screen.EnableMouse(tcell.MouseMotionEvents)
	screen.EnableFocus()
}
