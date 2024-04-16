package termemu

import (
	"bufio"
	"io"
	"os"

	"github.com/nermius/nermius/internal/termemu/vtcompat"
)

type Color uint32

const (
	DefaultFG     Color = Color(vtcompat.DefaultFG)
	DefaultBG     Color = Color(vtcompat.DefaultBG)
	DefaultCursor Color = Color(vtcompat.DefaultCursor)
)

func (c Color) ANSI() bool {
	return c < 16
}

type Glyph struct {
	Char   rune
	Mode   int16
	FG, BG Color
}

type CursorStyleShape int

const (
	CursorShapeBlock CursorStyleShape = iota
	CursorShapeUnderline
	CursorShapeBar
)

type CursorStyle struct {
	Shape CursorStyleShape
	Blink bool
}

type Cursor struct {
	Attr  Glyph
	X, Y  int
	State uint8
}

type ModeFlag uint32

const (
	ModeWrap ModeFlag = 1 << iota
	ModeInsert
	ModeAppKeypad
	ModeAltScreen
	ModeCRLF
	ModeMouseButton
	ModeMouseMotion
	ModeReverse
	ModeKeyboardLock
	ModeHide
	ModeEcho
	ModeAppCursor
	ModeMouseSgr
	Mode8bit
	ModeBlink
	ModeFBlink
	ModeFocus
	ModeMouseX10
	ModeMouseMany
	ModeBracketedPaste
	ModeMouseMask = ModeMouseButton | ModeMouseMotion | ModeMouseX10 | ModeMouseMany
)

type Terminal interface {
	io.Writer
	Parse(*bufio.Reader) error
	Size() (cols, rows int)
	Resize(cols, rows int)
	Mode() ModeFlag
	Title() string
	Cell(x, y int) Glyph
	HistoryCell(x, y int) Glyph
	ScrollbackRows() int
	Cursor() Cursor
	CursorVisible() bool
	CursorStyle() CursorStyle
	Lock()
	Unlock()
	SetClipboardHandler(func(string))
}

func New(cols, rows int) Terminal {
	switch os.Getenv("NERMIUS_TUI_ENGINE") {
	case "", "vtcompat", "xterm":
		return newVTCompat(cols, rows)
	default:
		return newVTCompat(cols, rows)
	}
}

type vtCompatTerminal struct {
	inner vtcompat.Terminal
}

func newVTCompat(cols, rows int) Terminal {
	return &vtCompatTerminal{
		inner: vtcompat.New(vtcompat.WithSize(cols, rows)),
	}
}

func (t *vtCompatTerminal) Write(p []byte) (int, error) {
	return t.inner.Write(p)
}

func (t *vtCompatTerminal) Parse(br *bufio.Reader) error {
	return t.inner.Parse(br)
}

func (t *vtCompatTerminal) Size() (int, int) {
	return t.inner.Size()
}

func (t *vtCompatTerminal) Resize(cols, rows int) {
	t.inner.Resize(cols, rows)
}

func (t *vtCompatTerminal) Mode() ModeFlag {
	return ModeFlag(t.inner.Mode())
}

func (t *vtCompatTerminal) Title() string {
	return t.inner.Title()
}

func (t *vtCompatTerminal) Cell(x, y int) Glyph {
	cell := t.inner.Cell(x, y)
	return glyphFromVT(cell)
}

func (t *vtCompatTerminal) HistoryCell(x, y int) Glyph {
	cell := t.inner.HistoryCell(x, y)
	return glyphFromVT(cell)
}

func (t *vtCompatTerminal) ScrollbackRows() int {
	return t.inner.ScrollbackRows()
}

func glyphFromVT(cell vtcompat.Glyph) Glyph {
	return Glyph{
		Char: cell.Char,
		Mode: cell.Mode,
		FG:   Color(cell.FG),
		BG:   Color(cell.BG),
	}
}

func (t *vtCompatTerminal) Cursor() Cursor {
	cursor := t.inner.Cursor()
	return Cursor{
		Attr: Glyph{
			Char: cursor.Attr.Char,
			Mode: cursor.Attr.Mode,
			FG:   Color(cursor.Attr.FG),
			BG:   Color(cursor.Attr.BG),
		},
		X:     cursor.X,
		Y:     cursor.Y,
		State: cursor.State,
	}
}

func (t *vtCompatTerminal) CursorVisible() bool {
	return t.inner.CursorVisible()
}

func (t *vtCompatTerminal) CursorStyle() CursorStyle {
	style := t.inner.CursorStyle()
	return CursorStyle{
		Shape: CursorStyleShape(style.Shape),
		Blink: style.Blink,
	}
}

func (t *vtCompatTerminal) Lock() {
	t.inner.Lock()
}

func (t *vtCompatTerminal) Unlock() {
	t.inner.Unlock()
}

func (t *vtCompatTerminal) SetClipboardHandler(handler func(string)) {
	t.inner.SetClipboardHandler(handler)
}
