package tui

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/google/uuid"

	"github.com/nermius/nermius/internal/domain"
	"github.com/nermius/nermius/internal/service"
)

const (
	minWorkspacePaneWidth  = 20
	minWorkspacePaneHeight = 6
)

type workspacePaneID string

type workspacePaneStatus string

const (
	workspacePaneEmpty        workspacePaneStatus = "empty"
	workspacePanePending      workspacePaneStatus = "pending"
	workspacePaneConnected    workspacePaneStatus = "connected"
	workspacePaneReconnecting workspacePaneStatus = "reconnecting"
	workspacePaneDisconnected workspacePaneStatus = "disconnected"
	workspacePaneFinished     workspacePaneStatus = "finished"
)

type workspaceState struct {
	id        string
	name      string
	root      *workspaceNode
	focused   workspacePaneID
	zoomed    bool
	rects     map[workspacePaneID]workspaceRect
	bySession map[*service.EmbeddedSession]workspacePaneID
}

type workspaceNode struct {
	id     workspacePaneID
	split  *workspaceSplit
	pane   *workspacePane
	parent *workspaceNode
}

type workspaceSplit struct {
	axis   domain.WorkspaceSplitAxis
	ratio  float64
	first  *workspaceNode
	second *workspaceNode
}

type workspacePane struct {
	id       workspacePaneID
	hostID   string
	label    string
	session  *service.EmbeddedSession
	runtime  *sessionRuntime
	status   workspacePaneStatus
	prompted bool
}

type workspaceRect struct {
	x, y int
	w, h int
}

func newWorkspaceState() *workspaceState {
	pane := newWorkspacePane("", "")
	return &workspaceState{
		root:      &workspaceNode{id: pane.id, pane: pane},
		focused:   pane.id,
		rects:     map[workspacePaneID]workspaceRect{},
		bySession: map[*service.EmbeddedSession]workspacePaneID{},
	}
}

func workspaceFromDomain(layout *domain.Workspace) *workspaceState {
	state := newWorkspaceState()
	if layout == nil {
		return state
	}
	state.id = layout.ID
	state.name = layout.Name
	if layout.Root != nil {
		state.root = workspaceNodeFromDomain(layout.Root, nil)
		if first := firstWorkspacePane(state.root); first != nil {
			state.focused = first.id
		}
	}
	state.rebuildSessionIndex()
	return state
}

func workspaceNodeFromDomain(in *domain.WorkspaceNode, parent *workspaceNode) *workspaceNode {
	if in == nil {
		pane := newWorkspacePane("", "")
		return &workspaceNode{id: pane.id, pane: pane, parent: parent}
	}
	node := &workspaceNode{id: workspaceNodeID(in.ID), parent: parent}
	if in.Split != nil {
		axis := in.Split.Axis
		if axis == "" {
			axis = domain.WorkspaceSplitHorizontal
		}
		ratio := in.Split.Ratio
		if ratio == 0 {
			ratio = 0.5
		}
		ratio = clampFloat(ratio, 0.2, 0.8)
		node.split = &workspaceSplit{axis: axis, ratio: ratio}
		node.split.first = workspaceNodeFromDomain(in.Split.First, node)
		node.split.second = workspaceNodeFromDomain(in.Split.Second, node)
		return node
	}
	pane := newWorkspacePane("", "")
	if in.Pane != nil && in.Pane.Type == domain.WorkspacePaneSSH {
		pane.hostID = in.Pane.HostRef
		pane.label = firstNonEmpty(in.Pane.Title, in.Pane.HostRef)
		pane.status = workspacePanePending
		pane.runtime = &sessionRuntime{hostID: pane.hostID, label: pane.label, status: sessionStatusFinished}
	}
	if node.id == "" {
		node.id = pane.id
	} else {
		pane.id = node.id
	}
	node.pane = pane
	return node
}

func newWorkspacePane(hostID, label string) *workspacePane {
	id := workspacePaneID(uuid.NewString())
	status := workspacePaneEmpty
	if strings.TrimSpace(hostID) != "" {
		status = workspacePanePending
	}
	return &workspacePane{
		id:     id,
		hostID: hostID,
		label:  firstNonEmpty(label, hostID),
		status: status,
		runtime: &sessionRuntime{
			hostID: hostID,
			label:  firstNonEmpty(label, hostID),
			status: sessionStatusFinished,
		},
	}
}

func workspaceNodeID(value string) workspacePaneID {
	value = strings.TrimSpace(value)
	if value == "" {
		return workspacePaneID(uuid.NewString())
	}
	return workspacePaneID(value)
}

func (w *workspaceState) focusedPane() *workspacePane {
	if w == nil {
		return nil
	}
	return w.paneByID(w.focused)
}

func (w *workspaceState) paneByID(id workspacePaneID) *workspacePane {
	if w == nil || id == "" {
		return nil
	}
	node := w.nodeByID(id)
	if node == nil {
		return nil
	}
	return node.pane
}

func (w *workspaceState) nodeByID(id workspacePaneID) *workspaceNode {
	if w == nil || id == "" {
		return nil
	}
	return findWorkspaceNodeByID(w.root, id)
}

func findWorkspaceNodeByID(node *workspaceNode, id workspacePaneID) *workspaceNode {
	if node == nil {
		return nil
	}
	if node.pane != nil && node.id == id {
		return node
	}
	if node.split == nil {
		return nil
	}
	if found := findWorkspaceNodeByID(node.split.first, id); found != nil {
		return found
	}
	return findWorkspaceNodeByID(node.split.second, id)
}

func (w *workspaceState) leaves() []*workspacePane {
	if w == nil {
		return nil
	}
	out := []*workspacePane{}
	collectWorkspacePanes(w.root, &out)
	return out
}

func collectWorkspacePanes(node *workspaceNode, out *[]*workspacePane) {
	if node == nil {
		return
	}
	if node.pane != nil {
		*out = append(*out, node.pane)
		return
	}
	collectWorkspacePanes(node.split.first, out)
	collectWorkspacePanes(node.split.second, out)
}

func firstWorkspacePane(node *workspaceNode) *workspacePane {
	if node == nil {
		return nil
	}
	if node.pane != nil {
		return node.pane
	}
	if first := firstWorkspacePane(node.split.first); first != nil {
		return first
	}
	return firstWorkspacePane(node.split.second)
}

func (w *workspaceState) splitFocused(axis domain.WorkspaceSplitAxis, newPane *workspacePane) (*workspacePane, error) {
	if w == nil {
		return nil, errors.New("workspace is not open")
	}
	if len(w.leaves()) >= 16 {
		return nil, errors.New("workspace supports at most 16 panes")
	}
	target := w.nodeByID(w.focused)
	if target == nil || target.pane == nil {
		return nil, errors.New("no focused pane")
	}
	existing := target.pane
	existingNode := &workspaceNode{id: existing.id, pane: existing, parent: target}
	newNode := &workspaceNode{id: newPane.id, pane: newPane, parent: target}
	target.id = ""
	target.pane = nil
	target.split = &workspaceSplit{
		axis:   axis,
		ratio:  0.5,
		first:  existingNode,
		second: newNode,
	}
	w.focused = newPane.id
	w.rebuildSessionIndex()
	return newPane, nil
}

func (w *workspaceState) closePane(id workspacePaneID) *workspacePane {
	if w == nil || w.root == nil {
		return nil
	}
	node := w.nodeByID(id)
	if node == nil || node.pane == nil {
		return nil
	}
	closed := node.pane
	if node.parent == nil {
		pane := newWorkspacePane("", "")
		w.root = &workspaceNode{id: pane.id, pane: pane}
		w.focused = pane.id
		w.rebuildSessionIndex()
		return closed
	}
	parent := node.parent
	var sibling *workspaceNode
	if parent.split.first == node {
		sibling = parent.split.second
	} else {
		sibling = parent.split.first
	}
	replaceWorkspaceNode(parent, sibling)
	if first := firstWorkspacePane(w.root); first != nil {
		w.focused = first.id
	}
	w.rebuildSessionIndex()
	return closed
}

func replaceWorkspaceNode(target, source *workspaceNode) {
	target.id = source.id
	target.pane = source.pane
	target.split = source.split
	if target.pane != nil {
		target.pane.id = target.id
	}
	if target.split != nil {
		target.split.first.parent = target
		target.split.second.parent = target
	}
}

func (w *workspaceState) focusNext() {
	panes := w.leaves()
	if len(panes) == 0 {
		return
	}
	for i, pane := range panes {
		if pane.id == w.focused {
			w.focused = panes[(i+1)%len(panes)].id
			return
		}
	}
	w.focused = panes[0].id
}

func (w *workspaceState) focusPaneAt(x, y int) bool {
	if w == nil {
		return false
	}
	for id, rect := range w.rects {
		if x >= rect.x && x < rect.x+rect.w && y >= rect.y && y < rect.y+rect.h {
			w.focused = id
			return true
		}
	}
	return false
}

func (w *workspaceState) focusDirection(dx, dy int) bool {
	if w == nil || (dx == 0 && dy == 0) {
		return false
	}
	current, ok := w.rects[w.focused]
	if !ok {
		return false
	}
	best := workspacePaneID("")
	bestScore := math.MaxInt
	cx := current.x + current.w/2
	cy := current.y + current.h/2
	for id, rect := range w.rects {
		if id == w.focused {
			continue
		}
		rx := rect.x + rect.w/2
		ry := rect.y + rect.h/2
		if dx < 0 && rx >= cx {
			continue
		}
		if dx > 0 && rx <= cx {
			continue
		}
		if dy < 0 && ry >= cy {
			continue
		}
		if dy > 0 && ry <= cy {
			continue
		}
		primary := absInt(rx-cx)*absInt(dx) + absInt(ry-cy)*absInt(dy)
		secondary := absInt(ry-cy)*absInt(dx) + absInt(rx-cx)*absInt(dy)
		score := primary*1000 + secondary
		if score < bestScore {
			bestScore = score
			best = id
		}
	}
	if best == "" {
		return false
	}
	w.focused = best
	return true
}

func (w *workspaceState) resizeFocused(dx, dy int, totalW, totalH int) bool {
	node := w.nodeByID(w.focused)
	if node == nil || node.parent == nil {
		return false
	}
	for parent := node.parent; parent != nil; parent = parent.parent {
		if parent.split == nil {
			continue
		}
		if dx != 0 && parent.split.axis == domain.WorkspaceSplitHorizontal {
			return resizeWorkspaceSplit(parent, node, dx, totalW)
		}
		if dy != 0 && parent.split.axis == domain.WorkspaceSplitVertical {
			return resizeWorkspaceSplit(parent, node, dy, totalH)
		}
	}
	return false
}

func resizeWorkspaceSplit(parent, focused *workspaceNode, delta, total int) bool {
	if parent == nil || parent.split == nil || total <= 0 {
		return false
	}
	amount := float64(delta) / float64(total)
	if !workspaceNodeContains(parent.split.first, focused) {
		amount = -amount
	}
	next := clampFloat(parent.split.ratio+amount, 0.2, 0.8)
	if next == parent.split.ratio {
		return false
	}
	parent.split.ratio = next
	return true
}

func workspaceNodeContains(root, target *workspaceNode) bool {
	if root == nil || target == nil {
		return false
	}
	if root == target {
		return true
	}
	if root.split == nil {
		return false
	}
	return workspaceNodeContains(root.split.first, target) || workspaceNodeContains(root.split.second, target)
}

func (w *workspaceState) computeRects(x, y, width, height int) map[workspacePaneID]workspaceRect {
	if w == nil || w.root == nil {
		return nil
	}
	w.rects = map[workspacePaneID]workspaceRect{}
	if w.zoomed {
		if pane := w.focusedPane(); pane != nil {
			w.rects[pane.id] = workspaceRect{x: x, y: y, w: width, h: height}
		}
		return w.rects
	}
	assignWorkspaceRects(w.root, workspaceRect{x: x, y: y, w: width, h: height}, w.rects)
	return w.rects
}

func assignWorkspaceRects(node *workspaceNode, rect workspaceRect, out map[workspacePaneID]workspaceRect) {
	if node == nil || rect.w <= 0 || rect.h <= 0 {
		return
	}
	if node.pane != nil {
		out[node.pane.id] = rect
		return
	}
	split := node.split
	if split.axis == domain.WorkspaceSplitVertical {
		firstH := clampInt(int(math.Round(float64(rect.h)*split.ratio)), minWorkspacePaneHeight, max(minWorkspacePaneHeight, rect.h-minWorkspacePaneHeight))
		if rect.h < minWorkspacePaneHeight*2 {
			firstH = max(1, rect.h/2)
		}
		assignWorkspaceRects(split.first, workspaceRect{x: rect.x, y: rect.y, w: rect.w, h: firstH}, out)
		assignWorkspaceRects(split.second, workspaceRect{x: rect.x, y: rect.y + firstH, w: rect.w, h: rect.h - firstH}, out)
		return
	}
	firstW := clampInt(int(math.Round(float64(rect.w)*split.ratio)), minWorkspacePaneWidth, max(minWorkspacePaneWidth, rect.w-minWorkspacePaneWidth))
	if rect.w < minWorkspacePaneWidth*2 {
		firstW = max(1, rect.w/2)
	}
	assignWorkspaceRects(split.first, workspaceRect{x: rect.x, y: rect.y, w: firstW, h: rect.h}, out)
	assignWorkspaceRects(split.second, workspaceRect{x: rect.x + firstW, y: rect.y, w: rect.w - firstW, h: rect.h}, out)
}

func (w *workspaceState) rebuildSessionIndex() {
	if w == nil {
		return
	}
	w.bySession = map[*service.EmbeddedSession]workspacePaneID{}
	for _, pane := range w.leaves() {
		if pane.session != nil {
			w.bySession[pane.session] = pane.id
		}
	}
}

func (w *workspaceState) paneForSession(session *service.EmbeddedSession) *workspacePane {
	if w == nil || session == nil {
		return nil
	}
	if id, ok := w.bySession[session]; ok {
		return w.paneByID(id)
	}
	for _, pane := range w.leaves() {
		if pane.session == session {
			return pane
		}
	}
	return nil
}

func (w *workspaceState) toDomain(name string) *domain.Workspace {
	return &domain.Workspace{
		ID:   w.id,
		Name: name,
		Root: workspaceNodeToDomain(w.root),
	}
}

func workspaceNodeToDomain(node *workspaceNode) *domain.WorkspaceNode {
	if node == nil {
		return nil
	}
	if node.pane != nil {
		paneType := domain.WorkspacePaneEmpty
		if node.pane.hostID != "" {
			paneType = domain.WorkspacePaneSSH
		}
		return &domain.WorkspaceNode{
			ID: string(node.pane.id),
			Pane: &domain.WorkspacePane{
				Type:    paneType,
				HostRef: node.pane.hostID,
				Title:   node.pane.label,
			},
		}
	}
	return &domain.WorkspaceNode{
		Split: &domain.WorkspaceSplit{
			Axis:   node.split.axis,
			Ratio:  node.split.ratio,
			First:  workspaceNodeToDomain(node.split.first),
			Second: workspaceNodeToDomain(node.split.second),
		},
	}
}

func openWorkspaceHostPicker(ctx context.Context, app *App, onPick func(hostID, label string)) error {
	return app.openRefPicker(ctx, "Pick Host", domain.KindHost, false, func(item editorItem) {
		onPick(item.ID, item.Label)
	})
}

func clampFloat(value, minValue, maxValue float64) float64 {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

func workspacePaneLabel(pane *workspacePane) string {
	if pane == nil {
		return "EMPTY"
	}
	switch {
	case pane.session != nil:
		return firstNonEmpty(pane.label, pane.session.Name)
	case pane.hostID != "":
		return firstNonEmpty(pane.label, pane.hostID)
	default:
		return "EMPTY"
	}
}

func workspacePaneStatusLabel(pane *workspacePane) string {
	if pane == nil {
		return "empty"
	}
	if pane.runtime != nil {
		switch pane.runtime.status {
		case sessionStatusDisconnected:
			return "disconnected"
		case sessionStatusReconnecting:
			return fmt.Sprintf("reconnecting %d/%d", pane.runtime.attempts, service.MaxForwardReconnectAttempts)
		case sessionStatusFinished:
			if pane.hostID != "" && pane.session == nil {
				return "pending"
			}
			return "finished"
		}
	}
	switch pane.status {
	case workspacePaneConnected:
		return "connected"
	case workspacePanePending:
		return "pending"
	case workspacePaneDisconnected:
		return "disconnected"
	case workspacePaneReconnecting:
		return "reconnecting"
	case workspacePaneFinished:
		return "finished"
	default:
		return "empty"
	}
}
