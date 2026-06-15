package tui

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"github.com/nermius/nermius/internal/domain"
	"github.com/nermius/nermius/internal/service"
	"github.com/nermius/nermius/internal/store"
	"github.com/nermius/nermius/internal/termemu"
)

func TestSessionKeyBytesControlKeys(t *testing.T) {
	tests := []struct {
		name string
		ev   *tcell.EventKey
		want []byte
	}{
		{name: "ctrl-c", ev: tcell.NewEventKey(tcell.KeyCtrlC, 0, tcell.ModNone), want: []byte{0x03}},
		{name: "ctrl-d", ev: tcell.NewEventKey(tcell.KeyCtrlD, 0, tcell.ModNone), want: []byte{0x04}},
		{name: "ctrl-z", ev: tcell.NewEventKey(tcell.KeyCtrlZ, 0, tcell.ModNone), want: []byte{0x1a}},
		{name: "escape", ev: tcell.NewEventKey(tcell.KeyEscape, 0, tcell.ModNone), want: []byte{0x1b}},
		{name: "tab", ev: tcell.NewEventKey(tcell.KeyTAB, 0, tcell.ModNone), want: []byte{'\t'}},
		{name: "backtab", ev: tcell.NewEventKey(tcell.KeyBacktab, 0, tcell.ModNone), want: []byte("\x1b[Z")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sessionKeyBytes(tt.ev)
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("sessionKeyBytes(%s) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestSessionKeyBytesAltRune(t *testing.T) {
	got := sessionKeyBytes(tcell.NewEventKey(tcell.KeyRune, 'x', tcell.ModAlt))
	want := []byte{0x1b, 'x'}
	if !bytes.Equal(got, want) {
		t.Fatalf("sessionKeyBytes(alt-rune) = %v, want %v", got, want)
	}
}

func TestSessionMouseBytesSGRPressAndRelease(t *testing.T) {
	mode := termemu.ModeMouseButton | termemu.ModeMouseSgr

	press := sessionMouseBytes(tcell.NewEventMouse(10, 4, tcell.Button1, tcell.ModNone), tcell.ButtonNone, -1, -1, 10, 4, mode)
	if !bytes.Equal(press, []byte("\x1b[<0;11;5M")) {
		t.Fatalf("unexpected sgr press payload: %q", string(press))
	}

	release := sessionMouseBytes(tcell.NewEventMouse(10, 4, tcell.ButtonNone, tcell.ModNone), tcell.Button1, 10, 4, 10, 4, mode)
	if !bytes.Equal(release, []byte("\x1b[<0;11;5m")) {
		t.Fatalf("unexpected sgr release payload: %q", string(release))
	}
}

func TestSessionMouseBytesClassicWheel(t *testing.T) {
	mode := termemu.ModeMouseButton
	got := sessionMouseBytes(tcell.NewEventMouse(1, 2, tcell.WheelUp, tcell.ModNone), tcell.ButtonNone, -1, -1, 1, 2, mode)
	want := []byte{0x1b, '[', 'M', '`', '"', '#'}
	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected classic wheel payload: %v", got)
	}
}

func TestSessionSelectionExtractionAcrossRows(t *testing.T) {
	term := termemu.New(4, 2)
	if _, err := term.Write([]byte("abcdWXYZ")); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	session := &service.EmbeddedSession{Name: "test", Terminal: term}
	selection := sessionSelection{
		Session:     session,
		Anchor:      cellPos{X: 1, Y: 0},
		Focus:       cellPos{X: 2, Y: 1},
		Active:      true,
		HistoryRows: 0,
	}
	got := extractSelection(term, selection)
	want := "bcd\nWXY"
	if got != want {
		t.Fatalf("extractSelection() = %q, want %q", got, want)
	}
}

func TestSessionSelectionSkipsWideRuneTrailCells(t *testing.T) {
	term := termemu.New(12, 2)
	if _, err := term.Write([]byte("地址: 中国")); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	session := &service.EmbeddedSession{Name: "test", Terminal: term}
	selection := sessionSelection{
		Session:     session,
		Anchor:      cellPos{X: 0, Y: 0},
		Focus:       cellPos{X: 9, Y: 0},
		Active:      true,
		HistoryRows: 0,
	}
	got := extractSelection(term, selection)
	want := "地址: 中国"
	if got != want {
		t.Fatalf("extractSelection(wide) = %q, want %q", got, want)
	}
}

func TestSelectionExtractionIncludesScrollback(t *testing.T) {
	term := termemu.New(4, 2)
	if _, err := term.Write([]byte("ab\r\ncd\r\nef")); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	session := &service.EmbeddedSession{Name: "test", Terminal: term}
	selection := sessionSelection{
		Session:     session,
		Anchor:      cellPos{X: 0, Y: 0},
		Focus:       cellPos{X: 1, Y: 2},
		Active:      true,
		HistoryRows: 1,
	}
	got := extractSelection(term, selection)
	want := "ab\ncd\nef"
	if got != want {
		t.Fatalf("extractSelection(history) = %q, want %q", got, want)
	}
}

func TestShouldUseLocalSelectionWithShiftOverride(t *testing.T) {
	app := &App{}
	ev := tcell.NewEventMouse(10, 5, tcell.Button1, tcell.ModShift)
	if !app.shouldUseLocalSelection(ev, termemu.ModeMouseButton, tcell.ButtonNone) {
		t.Fatal("expected shift+drag to force local selection")
	}
	if app.shouldUseLocalSelection(tcell.NewEventMouse(10, 5, tcell.Button1, tcell.ModNone), termemu.ModeMouseButton, tcell.ButtonNone) {
		t.Fatal("expected remote mouse mode to keep plain click remote")
	}
}

func TestLocalWheelScrollbackRules(t *testing.T) {
	app := &App{}
	if !app.shouldUseLocalScrollback(tcell.NewEventMouse(10, 5, tcell.WheelUp, tcell.ModNone), 0, 10) {
		t.Fatal("expected local wheel scrollback without remote mouse mode")
	}
	if app.shouldUseLocalScrollback(tcell.NewEventMouse(10, 5, tcell.WheelUp, tcell.ModNone), termemu.ModeMouseButton, 10) {
		t.Fatal("expected plain wheel to stay remote when mouse mode is enabled")
	}
	if !app.shouldUseLocalScrollback(tcell.NewEventMouse(10, 5, tcell.WheelUp, tcell.ModShift), termemu.ModeMouseButton, 10) {
		t.Fatal("expected shift+wheel to force local scrollback")
	}
}

func TestAdjustScrollOffsetClamps(t *testing.T) {
	session := &service.EmbeddedSession{Name: "test"}
	app := &App{scrollOffsets: map[*service.EmbeddedSession]int{}}
	app.adjustScrollOffset(session, 5, 3)
	if got := app.scrollOffsetForSession(session); got != 3 {
		t.Fatalf("scroll offset = %d, want 3", got)
	}
	app.adjustScrollOffset(session, -10, 3)
	if got := app.scrollOffsetForSession(session); got != 0 {
		t.Fatalf("scroll offset = %d, want 0", got)
	}
}

func TestListColumnWidthsExpandLabelOnWideScreen(t *testing.T) {
	items := []store.DocumentSummary{
		{UpdatedAt: time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)},
	}
	idWidth, labelWidth, updatedWidth := listColumnWidths(140, items)
	if idWidth != 36 {
		t.Fatalf("id width = %d, want 36", idWidth)
	}
	if labelWidth <= 24 {
		t.Fatalf("label width = %d, want > 24 on a wide screen", labelWidth)
	}
	if updatedWidth < len(time.Now().UTC().Format(time.RFC3339)) {
		t.Fatalf("updated width = %d, too small", updatedWidth)
	}
}

func TestListColumnWidthsShrinkIDBeforeLabel(t *testing.T) {
	idWidth, labelWidth, _ := listColumnWidths(60, nil)
	if idWidth >= 36 {
		t.Fatalf("id width = %d, expected shrink below 36", idWidth)
	}
	if labelWidth < 12 {
		t.Fatalf("label width = %d, want at least 12", labelWidth)
	}
}

func TestHostAddressLabelDefaultsPort(t *testing.T) {
	if got := hostAddressLabel(domain.Host{Hostname: "db.internal"}); got != "db.internal:22" {
		t.Fatalf("host address = %q, want default port 22", got)
	}
	port := 2200
	if got := hostAddressLabel(domain.Host{Hostname: "db.internal", Port: &port}); got != "db.internal:2200" {
		t.Fatalf("host address = %q, want explicit port", got)
	}
}

func TestHostListColumnWidthsCapLabel(t *testing.T) {
	items := []store.DocumentSummary{
		{ID: "host-1", Label: "a very long host label that should not claim the whole row", UpdatedAt: time.Date(2026, 4, 27, 0, 0, 0, 0, time.UTC)},
	}
	_, labelWidth, addressWidth, _ := hostListColumnWidths(160, items, map[string]string{"host-1": "long.host.name.example.com:2200"})
	if labelWidth != 32 {
		t.Fatalf("host label width = %d, want cap 32", labelWidth)
	}
	if addressWidth <= 32 {
		t.Fatalf("host address width = %d, want extra space allocated to address", addressWidth)
	}
}

func TestForwardListColumnWidthsCapLabelAndGrowReason(t *testing.T) {
	app := &App{
		runningForwards: map[string]*forwardRuntime{
			"forward-1": {status: forwardStatusError, reason: "connection reset by peer while waiting for remote listener"},
		},
	}
	items := []store.DocumentSummary{
		{ID: "forward-1", Label: "a very long forward label that should be capped", UpdatedAt: time.Date(2026, 4, 27, 0, 0, 0, 0, time.UTC)},
	}
	_, labelWidth, _, reasonWidth, _ := forwardListColumnWidths(170, items, app)
	if labelWidth != 32 {
		t.Fatalf("forward label width = %d, want cap 32", labelWidth)
	}
	if reasonWidth <= 56 {
		t.Fatalf("forward reason width = %d, want extra space allocated to reason", reasonWidth)
	}
}

func TestFooterPromptRefreshesForActiveView(t *testing.T) {
	app := &App{
		tabs:      []domain.DocumentKind{domain.KindHost, domain.KindIdentity},
		activeTab: 0,
	}
	if got := app.footerText(); !strings.Contains(got, "Enter workspace") {
		t.Fatalf("host footer = %q, want workspace prompt", got)
	}

	app.setActiveTab(1)
	if got := app.footerText(); !strings.Contains(got, "Enter detail") {
		t.Fatalf("identity footer = %q, want detail prompt", got)
	}

	app.workspace = newWorkspaceState()
	app.setActiveTab(len(app.tabs))
	if got := app.footerText(); !strings.Contains(got, "F8 close") || !strings.Contains(got, "F2 back") {
		t.Fatalf("workspace footer = %q, want workspace prompt", got)
	}

	app.status = "Connecting: dialing test"
	app.setActiveTab(0)
	got := app.footerText()
	if !strings.Contains(got, "Connecting: dialing test") || !strings.Contains(got, "Enter workspace") {
		t.Fatalf("status footer = %q, want status plus refreshed host prompt", got)
	}
}

func TestLayoutTabUsesListNavigationAndQuit(t *testing.T) {
	app := &App{
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
		activeTab: 6,
		records:   map[domain.DocumentKind][]store.DocumentSummary{},
		filters:   map[domain.DocumentKind]string{},
	}

	if app.inSessionTab() {
		t.Fatal("layout tab must not be treated as workspace session tab")
	}
	if _, err := app.handleKey(nil, tcell.NewEventKey(tcell.KeyLeft, 0, tcell.ModNone)); err != nil {
		t.Fatalf("handleKey(left) returned error: %v", err)
	}
	if app.activeTab != 5 {
		t.Fatalf("active tab after left = %d, want forward tab 5", app.activeTab)
	}
	if _, err := app.handleKey(nil, tcell.NewEventKey(tcell.KeyRight, 0, tcell.ModNone)); err != nil {
		t.Fatalf("handleKey(right) returned error: %v", err)
	}
	if app.activeTab != 6 {
		t.Fatalf("active tab after right = %d, want layout tab 6", app.activeTab)
	}
	if _, err := app.handleKey(nil, tcell.NewEventKey(tcell.KeyRune, 'q', tcell.ModNone)); err != nil {
		t.Fatalf("handleKey(q) returned error: %v", err)
	}
	if !app.exitRequested {
		t.Fatal("expected q on layout tab to request quit")
	}
}

func TestWorkspaceTabPlainKeysStayInTerminalView(t *testing.T) {
	app := &App{
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
		activeTab:       8,
		workspace:       newWorkspaceState(),
		sessionRuntimes: map[*service.EmbeddedSession]*sessionRuntime{},
	}
	pane := app.workspace.focusedPane()
	session := &service.EmbeddedSession{Name: "one", Terminal: termemu.New(4, 2)}
	pane.session = session
	pane.status = workspacePaneConnected
	app.setSessionRuntime(session, &sessionRuntime{hostID: "host-1", label: "one", status: sessionStatusDisconnected})

	if !app.inSessionTab() {
		t.Fatal("expected active tab to be workspace view")
	}
	if _, err := app.handleKey(nil, tcell.NewEventKey(tcell.KeyLeft, 0, tcell.ModNone)); err != nil {
		t.Fatalf("handleKey(left) returned error: %v", err)
	}
	if app.activeTab != 8 {
		t.Fatalf("active tab after left = %d, want workspace tab 8", app.activeTab)
	}
	if !strings.Contains(app.status, "Session is not connected") {
		t.Fatalf("status after left = %q, want terminal forwarding status", app.status)
	}
	app.status = ""
	if _, err := app.handleKey(nil, tcell.NewEventKey(tcell.KeyRight, 0, tcell.ModNone)); err != nil {
		t.Fatalf("handleKey(right) returned error: %v", err)
	}
	if app.activeTab != 8 {
		t.Fatalf("active tab after right = %d, want workspace tab 8", app.activeTab)
	}
	if _, err := app.handleKey(nil, tcell.NewEventKey(tcell.KeyRune, 'q', tcell.ModNone)); err != nil {
		t.Fatalf("handleKey(q) returned error: %v", err)
	}
	if app.exitRequested {
		t.Fatal("did not expect q on workspace tab to request app quit")
	}
}

func TestWorkspacePaneShowsCloseHintInHeader(t *testing.T) {
	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatalf("screen init failed: %v", err)
	}
	defer screen.Fini()
	screen.SetSize(48, 8)
	workspace := newWorkspaceState()
	app := &App{
		screen:    screen,
		workspace: workspace,
	}

	app.renderWorkspacePane(workspace.focusedPane(), workspaceRect{x: 0, y: 1, w: 48, h: 5})

	header := simulationScreenText(screen, 0, 1, 48)
	if !strings.Contains(header, "F8 close") {
		t.Fatalf("workspace pane header = %q, want F8 close hint", header)
	}
	body := simulationScreenText(screen, 1, 2, 46)
	if !strings.Contains(body, "F8 close") {
		t.Fatalf("workspace pane body = %q, want F8 close hint", body)
	}
}

func TestWorkspaceSplitAndClose(t *testing.T) {
	workspace := newWorkspaceState()
	first := workspace.focused
	second, err := workspace.splitFocused(domain.WorkspaceSplitHorizontal, newWorkspacePane("host-2", "two"))
	if err != nil {
		t.Fatalf("splitFocused returned error: %v", err)
	}
	if len(workspace.leaves()) != 2 {
		t.Fatalf("leaf count = %d, want 2", len(workspace.leaves()))
	}
	if workspace.focused != second.id {
		t.Fatalf("focused pane = %s, want new pane %s", workspace.focused, second.id)
	}
	closed := workspace.closePane(second.id)
	if closed == nil || closed.id != second.id {
		t.Fatalf("closed pane = %#v, want %s", closed, second.id)
	}
	if len(workspace.leaves()) != 1 || workspace.focused != first {
		t.Fatalf("workspace leaves/focus after close = %d/%s, want 1/%s", len(workspace.leaves()), workspace.focused, first)
	}
}

func TestWorkspaceDomainRoundTripPreservesHostRefs(t *testing.T) {
	workspace := newWorkspaceState()
	if _, err := workspace.splitFocused(domain.WorkspaceSplitVertical, newWorkspacePane("host-1", "prod")); err != nil {
		t.Fatalf("splitFocused returned error: %v", err)
	}
	layout := workspace.toDomain("ops")
	if layout.Name != "ops" || layout.Root.Split == nil || layout.Root.Split.Second.Pane.HostRef != "host-1" {
		t.Fatalf("layout = %#v", layout)
	}
	restored := workspaceFromDomain(layout)
	if len(restored.leaves()) != 2 {
		t.Fatalf("restored leaves = %d, want 2", len(restored.leaves()))
	}
	if restored.leaves()[1].hostID != "host-1" || restored.leaves()[1].status != workspacePanePending {
		t.Fatalf("restored second pane = %#v", restored.leaves()[1])
	}
}

func TestCopyPasteShortcuts(t *testing.T) {
	if !isCopyShortcut(tcell.NewEventKey(tcell.KeyCtrlC, 0, tcell.ModShift)) {
		t.Fatal("expected ctrl+shift+c shortcut")
	}
	if !isPasteShortcut(tcell.NewEventKey(tcell.KeyCtrlV, 0, tcell.ModShift)) {
		t.Fatal("expected ctrl+shift+v shortcut")
	}
	if isCopyShortcut(tcell.NewEventKey(tcell.KeyCtrlC, 0, tcell.ModNone)) {
		t.Fatal("did not expect plain ctrl+c to be treated as copy")
	}
}

func TestRequestQuitConfirmsActiveSSHResources(t *testing.T) {
	app := &App{
		sessions: []*service.EmbeddedSession{{Name: "one", Terminal: termemu.New(4, 2)}},
	}
	app.requestQuit()
	if app.exitRequested {
		t.Fatal("expected quit to wait for confirmation")
	}
	if !app.hasModal() {
		t.Fatal("expected quit confirmation modal")
	}
	top := app.topModal()
	if top == nil || top.kind != modalKindConfirm || top.confirm == nil || top.confirm.title != "Quit Nermius" {
		t.Fatalf("top modal = %+v, want quit confirm", top)
	}
	if err := top.confirm.onConfirm(nil, app); err != nil {
		t.Fatalf("confirm quit failed: %v", err)
	}
	if !app.exitRequested {
		t.Fatal("expected confirmed quit to request exit")
	}
}

func TestRequestQuitWithoutActiveResourcesExitsImmediately(t *testing.T) {
	app := &App{}
	app.requestQuit()
	if !app.exitRequested {
		t.Fatal("expected immediate exit request")
	}
	if app.hasModal() {
		t.Fatal("did not expect confirmation without active resources")
	}
}

func TestCollectSessionUpdatesKeepsDisconnectedSessionAndPromptsReconnect(t *testing.T) {
	session := &service.EmbeddedSession{Name: "one", Terminal: termemu.New(4, 2)}
	app := &App{
		tabs:            []domain.DocumentKind{domain.KindHost},
		activeTab:       1,
		activeSession:   0,
		sessionRuntimes: map[*service.EmbeddedSession]*sessionRuntime{},
		scrollOffsets:   map[*service.EmbeddedSession]int{},
		sessions:        []*service.EmbeddedSession{session},
	}
	app.setSessionRuntime(session, &sessionRuntime{hostID: "host-1", label: "one", status: sessionStatusRunning})
	keep := app.handleSessionDone(session, io.EOF)
	if !keep {
		t.Fatal("expected disconnected session to be retained")
	}
	runtime := app.sessionRuntime(session)
	if runtime.status != sessionStatusDisconnected {
		t.Fatalf("session status = %s, want disconnected", runtime.status)
	}
	if !app.hasModal() {
		t.Fatal("expected reconnect confirmation modal")
	}
	if got := app.sessionTabLabel(session); !strings.Contains(got, "disconnected") {
		t.Fatalf("session tab label = %q, want disconnected status", got)
	}
}

func TestWorkspaceSessionDoneKeepsDisconnectedPaneSession(t *testing.T) {
	session := &service.EmbeddedSession{Name: "one", Terminal: termemu.New(4, 2)}
	workspace := newWorkspaceState()
	pane := workspace.focusedPane()
	pane.hostID = "host-1"
	pane.label = "one"
	pane.session = session
	pane.status = workspacePaneConnected
	app := &App{
		tabs:            []domain.DocumentKind{domain.KindHost},
		activeTab:       1,
		workspace:       workspace,
		sessionRuntimes: map[*service.EmbeddedSession]*sessionRuntime{},
		scrollOffsets:   map[*service.EmbeddedSession]int{},
	}
	app.setSessionRuntime(session, &sessionRuntime{hostID: "host-1", label: "one", status: sessionStatusRunning})

	app.handleWorkspaceSessionDone(pane, io.EOF)

	if pane.session != session {
		t.Fatal("expected disconnected workspace pane to retain its session")
	}
	if pane.status != workspacePaneDisconnected {
		t.Fatalf("pane status = %s, want disconnected", pane.status)
	}
	if runtime := app.sessionRuntime(session); runtime.status != sessionStatusDisconnected {
		t.Fatalf("session status = %s, want disconnected", runtime.status)
	}
	if !app.hasModal() {
		t.Fatal("expected reconnect confirmation modal")
	}
}

func TestCollectSessionUpdatesRemovesNormalExit(t *testing.T) {
	session := &service.EmbeddedSession{Name: "one", Terminal: termemu.New(4, 2)}
	app := &App{
		tabs:            []domain.DocumentKind{domain.KindHost},
		activeTab:       1,
		sessionRuntimes: map[*service.EmbeddedSession]*sessionRuntime{},
		scrollOffsets:   map[*service.EmbeddedSession]int{},
		sessions:        []*service.EmbeddedSession{session},
	}
	keep := app.handleSessionDone(session, nil)
	if keep {
		t.Fatal("expected normal exit not to be retained")
	}
	if app.hasModal() {
		t.Fatal("did not expect reconnect prompt on normal exit")
	}
}

func TestCloseLastSessionReturnsToFirstTab(t *testing.T) {
	app := &App{
		tabs:          []domain.DocumentKind{domain.KindHost, domain.KindIdentity},
		activeTab:     2,
		activeSession: 0,
		focused:       true,
		scrollOffsets: map[*service.EmbeddedSession]int{},
		sessions:      []*service.EmbeddedSession{{Name: "one", Terminal: termemu.New(4, 2)}},
	}
	app.closeSessionAt(0)
	if len(app.sessions) != 0 {
		t.Fatalf("sessions len = %d, want 0", len(app.sessions))
	}
	if app.activeTab != 0 {
		t.Fatalf("active tab = %d, want first tab", app.activeTab)
	}
}

func TestCloseLastWorkspacePaneReturnsToFirstTab(t *testing.T) {
	workspace := newWorkspaceState()
	app := &App{
		tabs:      []domain.DocumentKind{domain.KindHost, domain.KindIdentity},
		activeTab: 2,
		workspace: workspace,
		focused:   true,
	}
	app.closeWorkspacePane(workspace.focused)
	if app.workspace != nil {
		t.Fatal("expected empty workspace to close")
	}
	if app.activeTab != 0 {
		t.Fatalf("active tab = %d, want first tab", app.activeTab)
	}
}

func TestCloseSessionKeepsSessionsTabWhenSessionsRemain(t *testing.T) {
	app := &App{
		tabs:          []domain.DocumentKind{domain.KindHost, domain.KindIdentity},
		activeTab:     2,
		activeSession: 1,
		focused:       true,
		scrollOffsets: map[*service.EmbeddedSession]int{},
		sessions: []*service.EmbeddedSession{
			{Name: "one", Terminal: termemu.New(4, 2)},
			{Name: "two", Terminal: termemu.New(4, 2)},
		},
	}
	app.closeSessionAt(1)
	if len(app.sessions) != 1 {
		t.Fatalf("sessions len = %d, want 1", len(app.sessions))
	}
	if !app.inSessionTab() {
		t.Fatalf("active tab = %d, want sessions tab %d", app.activeTab, len(app.tabs))
	}
	if app.activeSession != 0 {
		t.Fatalf("active session = %d, want 0", app.activeSession)
	}
}

func TestForwardStatusDisplayDisconnected(t *testing.T) {
	app := &App{
		runningForwards: map[string]*forwardRuntime{
			"forward-disconnected": {status: forwardStatusDisconnected, reason: "network reset"},
		},
	}
	status, color := app.forwardStatusDisplay("forward-disconnected")
	if status != "disconnected" {
		t.Fatalf("forward status = %q, want disconnected", status)
	}
	if color != tcell.ColorRed {
		t.Fatalf("forward status color = %v, want red", color)
	}
}

func TestCollectForwardUpdatesPromptsDisconnectedForward(t *testing.T) {
	app := &App{
		runningForwards: map[string]*forwardRuntime{
			"forward-disconnected": {status: forwardStatusDisconnected, label: "prod-db", reason: "network reset"},
		},
	}
	app.collectForwardUpdates()
	if !app.hasModal() {
		t.Fatal("expected reconnect confirmation modal")
	}
	runtime := app.runningForwards["forward-disconnected"]
	if !runtime.prompted {
		t.Fatal("expected disconnected forward to be marked prompted")
	}
	top := app.topModal()
	if top == nil || top.kind != modalKindConfirm || top.confirm == nil || top.confirm.title != "Reconnect Forward" {
		t.Fatalf("top modal = %+v, want reconnect forward confirm", top)
	}
}

func TestSFTPDisconnectStatusOnlyForTransportErrors(t *testing.T) {
	if got := sftpErrorStatus(io.EOF); !strings.Contains(got, "SFTP disconnected") {
		t.Fatalf("transport status = %q, want disconnected", got)
	}
	ordinary := errors.New("permission denied")
	if got := sftpErrorStatus(ordinary); got != ordinary.Error() {
		t.Fatalf("ordinary status = %q, want original error", got)
	}
}

func TestTabIndexAt(t *testing.T) {
	tabs := []domain.DocumentKind{domain.KindHost, domain.KindGroup, domain.DocumentKind("sessions")}
	index, ok := tabIndexAt(2, 0, tabs)
	if !ok || index != 0 {
		t.Fatalf("expected x=2 to hit first tab, got index=%d ok=%v", index, ok)
	}
	index, ok = tabIndexAt(len(" HOST ")+2, 0, tabs)
	if !ok || index != 1 {
		t.Fatalf("expected x in second tab to hit group, got index=%d ok=%v", index, ok)
	}
	if _, ok := tabIndexAt(2, 2, tabs); ok {
		t.Fatal("expected non-header row to miss tab hit testing")
	}
}
