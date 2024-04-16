package tui

import (
	"strings"

	"github.com/nermius/nermius/internal/service"
	"github.com/nermius/nermius/internal/termemu"
)

type cellPos struct {
	X int
	Y int
}

type sessionSelection struct {
	Session     *service.EmbeddedSession
	Anchor      cellPos
	Focus       cellPos
	Dragging    bool
	Active      bool
	HistoryRows int
}

func clampSessionPosition(x, y, cols, rows int) (cellPos, bool) {
	if cols <= 0 || rows <= 0 {
		return cellPos{}, false
	}
	if x < 0 || y < 0 || x >= cols || y >= rows {
		return cellPos{}, false
	}
	return cellPos{X: x, Y: y}, true
}

func (s sessionSelection) normalized(width int) (cellPos, cellPos, bool) {
	if !s.Active || s.Session == nil || width <= 0 {
		return cellPos{}, cellPos{}, false
	}
	start := s.Anchor
	end := s.Focus
	if selectionLinearIndex(end, width) < selectionLinearIndex(start, width) {
		start, end = end, start
	}
	return start, end, true
}

func (s sessionSelection) contains(width, x, y int) bool {
	start, end, ok := s.normalized(width)
	if !ok {
		return false
	}
	index := selectionLinearIndex(cellPos{X: x, Y: y}, width)
	return index >= selectionLinearIndex(start, width) && index <= selectionLinearIndex(end, width)
}

func selectionLinearIndex(pos cellPos, width int) int {
	return pos.Y*width + pos.X
}

func extractSelection(term termemu.Terminal, selection sessionSelection) string {
	if term == nil {
		return ""
	}
	cols, rows := term.Size()
	start, end, ok := selection.normalized(cols)
	if !ok {
		return ""
	}
	term.Lock()
	defer term.Unlock()

	totalRows := selection.HistoryRows + rows
	if start.Y < 0 || start.Y >= totalRows {
		return ""
	}
	if end.Y >= totalRows {
		end.Y = totalRows - 1
	}
	lines := make([]string, 0, end.Y-start.Y+1)
	for y := start.Y; y <= end.Y; y++ {
		rowStart := 0
		if y == start.Y {
			rowStart = start.X
		}
		rowEnd := cols - 1
		if y == end.Y {
			rowEnd = end.X
		}
		var b strings.Builder
		for x := rowStart; x <= rowEnd; x++ {
			ch := cellAt(term, selection.HistoryRows, x, y).Char
			if ch == 0 {
				ch = ' '
			}
			b.WriteRune(ch)
		}
		lines = append(lines, strings.TrimRight(b.String(), " "))
	}
	return strings.Join(lines, "\n")
}

func cellAt(term termemu.Terminal, historyRows, x, y int) termemu.Glyph {
	if y < historyRows {
		return term.HistoryCell(x, y)
	}
	return term.Cell(x, y-historyRows)
}
