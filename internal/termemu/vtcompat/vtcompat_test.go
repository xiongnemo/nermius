package vtcompat

import "testing"

func TestBracketedPasteMode(t *testing.T) {
	term := New(WithSize(80, 24))
	if _, err := term.Write([]byte("\x1b[?2004h")); err != nil {
		t.Fatalf("Write enable failed: %v", err)
	}
	if term.Mode()&ModeBracketedPaste == 0 {
		t.Fatal("expected bracketed paste mode to be enabled")
	}
	if _, err := term.Write([]byte("\x1b[?2004l")); err != nil {
		t.Fatalf("Write disable failed: %v", err)
	}
	if term.Mode()&ModeBracketedPaste != 0 {
		t.Fatal("expected bracketed paste mode to be disabled")
	}
}

func TestCursorStyleCSI(t *testing.T) {
	term := New(WithSize(80, 24))
	if _, err := term.Write([]byte("\x1b[5 q")); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	style := term.CursorStyle()
	if style.Shape != CursorShapeBar || !style.Blink {
		t.Fatalf("unexpected cursor style: %#v", style)
	}
	if _, err := term.Write([]byte("\x1b[2 q")); err != nil {
		t.Fatalf("Write steady block failed: %v", err)
	}
	style = term.CursorStyle()
	if style.Shape != CursorShapeBlock || style.Blink {
		t.Fatalf("unexpected steady cursor style: %#v", style)
	}
}

func TestOSC52ClipboardHandler(t *testing.T) {
	term := New(WithSize(80, 24))
	var got string
	term.SetClipboardHandler(func(value string) {
		got = value
	})
	if _, err := term.Write([]byte("\x1b]52;c;aGVsbG8=\x07")); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if got != "hello" {
		t.Fatalf("unexpected clipboard payload: %q", got)
	}
}

func TestScrollbackCapturesNormalScreenOnly(t *testing.T) {
	term := New(WithSize(4, 2))
	if _, err := term.Write([]byte("ab\r\ncd\r\nef")); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if term.ScrollbackRows() != 1 {
		t.Fatalf("expected 1 scrollback row, got %d", term.ScrollbackRows())
	}
	if got := term.HistoryCell(0, 0).Char; got != 'a' {
		t.Fatalf("unexpected first history cell: %q", got)
	}

	if _, err := term.Write([]byte("\x1b[?1049h12\r\n34\r\n56")); err != nil {
		t.Fatalf("alt screen write failed: %v", err)
	}
	if term.ScrollbackRows() != 1 {
		t.Fatalf("expected alt screen writes to avoid normal scrollback, got %d", term.ScrollbackRows())
	}
}
