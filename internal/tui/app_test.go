package tui

import (
	"bytes"
	"testing"

	"github.com/gdamore/tcell/v2"

	"github.com/nermius/nermius/internal/domain"
	"github.com/nermius/nermius/internal/service"
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
