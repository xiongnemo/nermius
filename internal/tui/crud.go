package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"

	"github.com/nermius/nermius/internal/domain"
	"github.com/nermius/nermius/internal/service"
	"github.com/nermius/nermius/internal/store"
)

type modalKind int

const (
	modalKindDetail modalKind = iota
	modalKindForm
	modalKindPicker
	modalKindListEditor
	modalKindTextInput
	modalKindConfirm
)

type fieldKind int

const (
	fieldKindText fieldKind = iota
	fieldKindInt
	fieldKindSecret
	fieldKindTextArea
	fieldKindBool
	fieldKindEnum
	fieldKindSingleRef
	fieldKindRefList
	fieldKindStringList
	fieldKindMethodList
)

type modalState struct {
	kind       modalKind
	detail     *detailModal
	form       *formModal
	picker     *pickerModal
	listEditor *listEditorModal
	textInput  *textInputModal
	confirm    *confirmModal
}

type detailModal struct {
	title      string
	kind       domain.DocumentKind
	id         string
	lines      []string
	scroll     int
	canEdit    bool
	canConnect bool
}

type formField struct {
	key         string
	label       string
	kind        fieldKind
	required    bool
	value       string
	boolValue   bool
	options     []string
	refKind     domain.DocumentKind
	refValue    editorItem
	items       []editorItem
	placeholder string
	secret      bool
	visible     func(*formModal) bool
}

type formModal struct {
	title  string
	kind   domain.DocumentKind
	id     string
	isNew  bool
	fields []*formField
	cursor int
	scroll int
	dirty  bool
	onSave func(context.Context, *App, *formModal) error
}

type pickerOption struct {
	ID    string
	Label string
	Value string
	Kind  domain.DocumentKind
}

type pickerModal struct {
	title    string
	query    string
	options  []pickerOption
	cursor   int
	onPick   func(*App, pickerOption)
	onCancel func(*App)
}

type editorItem struct {
	ID     string
	Label  string
	Value  string
	Method *domain.AuthMethod
}

type listEditorModal struct {
	title    string
	items    []editorItem
	original []editorItem
	cursor   int
	scroll   int
	onSave   func(*App, []editorItem)
	onAdd    func(*App, *listEditorModal)
	onEdit   func(*App, *listEditorModal, int)
}

type textInputModal struct {
	title     string
	lines     []string
	cursorX   int
	cursorY   int
	scroll    int
	multiline bool
	secret    bool
	onSave    func(*App, string)
}

type confirmModal struct {
	title     string
	lines     []string
	onConfirm func(context.Context, *App) error
}

func (a *App) hasModal() bool {
	return len(a.modals) > 0
}

func (a *App) pushModal(modal modalState) {
	a.modals = append(a.modals, modal)
}

func (a *App) popModal() {
	if len(a.modals) == 0 {
		return
	}
	a.modals = a.modals[:len(a.modals)-1]
}

func (a *App) topModal() *modalState {
	if len(a.modals) == 0 {
		return nil
	}
	return &a.modals[len(a.modals)-1]
}

func (a *App) handleModalMouse(ctx context.Context, ev *tcell.EventMouse) (bool, error) {
	_ = ctx
	_ = ev
	return false, nil
}

func (a *App) handleModalKey(ctx context.Context, ev *tcell.EventKey) (bool, error) {
	top := a.topModal()
	if top == nil {
		return false, nil
	}
	switch top.kind {
	case modalKindDetail:
		return a.handleDetailModalKey(ctx, top.detail, ev)
	case modalKindForm:
		return a.handleFormModalKey(ctx, top.form, ev)
	case modalKindPicker:
		return a.handlePickerModalKey(top.picker, ev)
	case modalKindListEditor:
		return a.handleListEditorModalKey(top.listEditor, ev)
	case modalKindTextInput:
		return a.handleTextInputModalKey(top.textInput, ev)
	case modalKindConfirm:
		return a.handleConfirmModalKey(ctx, top.confirm, ev)
	default:
		return false, nil
	}
}

func (a *App) renderModal() {
	top := a.topModal()
	if top == nil {
		return
	}
	switch top.kind {
	case modalKindDetail:
		a.renderDetailModal(top.detail)
	case modalKindForm:
		a.renderFormModal(top.form)
	case modalKindPicker:
		a.renderPickerModal(top.picker)
	case modalKindListEditor:
		a.renderListEditorModal(top.listEditor)
	case modalKindTextInput:
		a.renderTextInputModal(top.textInput)
	case modalKindConfirm:
		a.renderConfirmModal(top.confirm)
	}
}

func (a *App) openAddForm(ctx context.Context) error {
	if a.inSessionTab() {
		return nil
	}
	form, err := a.buildFormModal(ctx, a.currentKind(), "", true)
	if err != nil {
		return err
	}
	a.pushModal(modalState{kind: modalKindForm, form: form})
	return nil
}

func (a *App) openEditForm(ctx context.Context) error {
	if top := a.topModal(); top != nil && top.kind == modalKindDetail && top.detail != nil {
		form, err := a.buildFormModal(ctx, top.detail.kind, top.detail.id, false)
		if err != nil {
			return err
		}
		a.pushModal(modalState{kind: modalKindForm, form: form})
		return nil
	}
	record := a.selectedRecord()
	if record.ID == "" {
		return nil
	}
	form, err := a.buildFormModal(ctx, a.currentKind(), record.ID, false)
	if err != nil {
		return err
	}
	a.pushModal(modalState{kind: modalKindForm, form: form})
	return nil
}

func (a *App) openDetailModal(ctx context.Context) error {
	record := a.selectedRecord()
	if record.ID == "" || a.inSessionTab() {
		return nil
	}
	detail, err := a.buildDetailModal(ctx, a.currentKind(), record.ID)
	if err != nil {
		return err
	}
	a.pushModal(modalState{kind: modalKindDetail, detail: detail})
	return nil
}

func (a *App) openDeleteConfirm(ctx context.Context) error {
	record := a.selectedRecord()
	if record.ID == "" || a.inSessionTab() {
		return nil
	}
	if a.currentKind() != domain.KindKnownHost {
		refs, err := a.catalog.FindReferences(ctx, record.ID)
		if err != nil {
			return err
		}
		if len(refs) > 0 {
			lines := []string{
				fmt.Sprintf("Cannot delete %s %q because it is still referenced:", strings.ToUpper(string(a.currentKind())), record.Label),
				"",
			}
			for _, ref := range refs {
				lines = append(lines, fmt.Sprintf("- %s %s (%s) via %s", strings.ToUpper(string(ref.Kind)), ref.Label, ref.ID, ref.Field))
			}
			a.pushModal(modalState{
				kind: modalKindDetail,
				detail: &detailModal{
					title:   "Delete blocked",
					lines:   lines,
					canEdit: false,
				},
			})
			return nil
		}
	}
	kind := a.currentKind()
	id := record.ID
	label := record.Label
	a.pushModal(modalState{
		kind: modalKindConfirm,
		confirm: &confirmModal{
			title: "Confirm delete",
			lines: []string{
				fmt.Sprintf("Delete %s %q?", strings.ToUpper(string(kind)), label),
				"This action cannot be undone.",
			},
			onConfirm: func(ctx context.Context, app *App) error {
				if err := app.deleteObject(ctx, kind, id); err != nil {
					return err
				}
				if err := app.reload(ctx); err != nil {
					return err
				}
				app.status = fmt.Sprintf("Deleted %s %q.", string(kind), label)
				return nil
			},
		},
	})
	return nil
}

func (a *App) openFilterModal() {
	kind := a.currentKind()
	current := a.filters[kind]
	a.pushModal(modalState{
		kind: modalKindTextInput,
		textInput: newTextInputModal(
			fmt.Sprintf("Filter %s", strings.ToUpper(string(kind))),
			current,
			false,
			false,
			func(app *App, value string) {
				app.filters[kind] = strings.TrimSpace(value)
				app.cursor = 0
				app.status = fmt.Sprintf("Filter for %s updated.", string(kind))
			},
		),
	})
}

func (a *App) buildDetailModal(ctx context.Context, kind domain.DocumentKind, id string) (*detailModal, error) {
	lines, canConnect, err := a.buildDetailLines(ctx, kind, id)
	if err != nil {
		return nil, err
	}
	return &detailModal{
		title:      strings.ToUpper(string(kind)) + " detail",
		kind:       kind,
		id:         id,
		lines:      lines,
		canEdit:    true,
		canConnect: canConnect,
	}, nil
}

func (a *App) buildDetailLines(ctx context.Context, kind domain.DocumentKind, id string) ([]string, bool, error) {
	switch kind {
	case domain.KindHost:
		host, err := a.loadEditableHost(ctx, id)
		if err != nil {
			return nil, false, err
		}
		masked := maskHostForDisplay(host)
		resolved, _ := a.catalog.ResolveHost(ctx, id)
		hostJSON, err := json.MarshalIndent(masked, "", "  ")
		if err != nil {
			return nil, false, err
		}
		resolvedJSON, err := json.MarshalIndent(resolved, "", "  ")
		if err != nil {
			return nil, false, err
		}
		refs, err := a.catalog.FindReferences(ctx, id)
		if err != nil {
			return nil, false, err
		}
		lines := []string{"Host object:", string(hostJSON), "", "Resolved config:", string(resolvedJSON), "", "Referenced by:"}
		if len(refs) == 0 {
			lines = append(lines, "(none)")
		} else {
			for _, ref := range refs {
				lines = append(lines, fmt.Sprintf("- %s %s (%s) via %s", strings.ToUpper(string(ref.Kind)), ref.Label, ref.ID, ref.Field))
			}
		}
		return flattenJSONLines(lines), true, nil
	case domain.KindGroup:
		group, err := a.catalog.GetGroup(ctx, id)
		if err != nil {
			return nil, false, err
		}
		return a.genericDetailLines(ctx, kind, id, group)
	case domain.KindProfile:
		profile, err := a.loadEditableProfile(ctx, id)
		if err != nil {
			return nil, false, err
		}
		return a.genericDetailLines(ctx, kind, id, maskProfileForDisplay(profile))
	case domain.KindIdentity:
		identity, err := a.loadEditableIdentity(ctx, id)
		if err != nil {
			return nil, false, err
		}
		return a.genericDetailLines(ctx, kind, id, maskIdentityForDisplay(identity))
	case domain.KindKey:
		key, err := a.loadEditableKey(ctx, id)
		if err != nil {
			return nil, false, err
		}
		return a.genericDetailLines(ctx, kind, id, maskKeyForDisplay(key))
	case domain.KindForward:
		forward, err := a.catalog.GetForward(ctx, id)
		if err != nil {
			return nil, false, err
		}
		return a.genericDetailLines(ctx, kind, id, forward)
	case domain.KindKnownHost:
		entry, err := service.LoadKnownHostEntry(ctx, a.catalog, a.paths.KnownHostsPath, id)
		if err != nil {
			return nil, false, err
		}
		return a.genericDetailLines(ctx, kind, id, entry)
	default:
		return []string{"Unsupported detail view."}, false, nil
	}
}

func (a *App) genericDetailLines(ctx context.Context, kind domain.DocumentKind, id string, value any) ([]string, bool, error) {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, false, err
	}
	lines := []string{string(body)}
	if kind != domain.KindKnownHost {
		refs, err := a.catalog.FindReferences(ctx, id)
		if err != nil {
			return nil, false, err
		}
		lines = append(lines, "", "Referenced by:")
		if len(refs) == 0 {
			lines = append(lines, "(none)")
		} else {
			for _, ref := range refs {
				lines = append(lines, fmt.Sprintf("- %s %s (%s) via %s", strings.ToUpper(string(ref.Kind)), ref.Label, ref.ID, ref.Field))
			}
		}
	}
	return flattenJSONLines(lines), false, nil
}

func flattenJSONLines(lines []string) []string {
	out := []string{}
	for _, line := range lines {
		out = append(out, strings.Split(line, "\n")...)
	}
	return out
}

func filterSummaries(items []store.DocumentSummary, query string) []store.DocumentSummary {
	query = strings.TrimSpace(strings.ToLower(query))
	if query == "" {
		return items
	}
	filtered := make([]store.DocumentSummary, 0, len(items))
	for _, item := range items {
		if strings.Contains(strings.ToLower(item.Label), query) || strings.Contains(strings.ToLower(item.ID), query) {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func (a *App) listRecords(ctx context.Context, kind domain.DocumentKind) ([]store.DocumentSummary, error) {
	if kind != domain.KindKnownHost {
		return a.catalog.List(ctx, kind)
	}
	entries, err := service.ListKnownHostsEntries(ctx, a.catalog, a.paths.KnownHostsPath, "all")
	if err != nil {
		return nil, err
	}
	out := make([]store.DocumentSummary, 0, len(entries))
	for _, entry := range entries {
		out = append(out, store.DocumentSummary{
			ID:        entry.ID,
			Kind:      string(domain.KindKnownHost),
			Label:     entry.Label(),
			UpdatedAt: entry.UpdatedAt,
		})
	}
	return out, nil
}
