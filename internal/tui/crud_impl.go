package tui

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/gdamore/tcell/v2"

	"github.com/nermius/nermius/internal/domain"
	"github.com/nermius/nermius/internal/service"
)

func (a *App) handleDetailModalKey(ctx context.Context, modal *detailModal, ev *tcell.EventKey) (bool, error) {
	if modal == nil {
		return false, nil
	}
	switch ev.Key() {
	case tcell.KeyEscape:
		a.popModal()
	case tcell.KeyUp:
		if modal.scroll > 0 {
			modal.scroll--
		}
	case tcell.KeyDown:
		modal.scroll++
	case tcell.KeyPgUp:
		modal.scroll = max(0, modal.scroll-10)
	case tcell.KeyPgDn:
		modal.scroll += 10
	case tcell.KeyEnter:
		if modal.canConnect && modal.kind == domain.KindHost {
			a.popModal()
			return false, a.openHostSessionByID(ctx, modal.id)
		}
	default:
		switch ev.Rune() {
		case 'e':
			if modal.canEdit {
				return false, a.openEditForm(ctx)
			}
		case 'c':
			if modal.canConnect && modal.kind == domain.KindHost {
				a.popModal()
				return false, a.openHostSessionByID(ctx, modal.id)
			}
		}
	}
	return false, nil
}

func (a *App) handleFormModalKey(ctx context.Context, modal *formModal, ev *tcell.EventKey) (bool, error) {
	if modal == nil {
		return false, nil
	}
	visible := visibleFieldIndexes(modal)
	if len(visible) == 0 {
		switch ev.Key() {
		case tcell.KeyEscape:
			a.popModal()
			return false, nil
		}
		return false, nil
	}
	modal.cursor = clampInt(modal.cursor, 0, len(visible)-1)
	switch ev.Key() {
	case tcell.KeyEscape:
		if !modal.dirty {
			a.popModal()
			return false, nil
		}
		a.pushDiscardConfirm("Discard changes?", func(app *App) {
			app.popModal()
		})
	case tcell.KeyUp:
		if modal.cursor > 0 {
			modal.cursor--
		}
	case tcell.KeyDown:
		if modal.cursor < len(visible)-1 {
			modal.cursor++
		}
	case tcell.KeyEnter:
		return false, a.editFormField(ctx, modal, modal.fields[visible[modal.cursor]])
	case tcell.KeyDelete:
		field := modal.fields[visible[modal.cursor]]
		if field.kind == fieldKindSingleRef {
			field.refValue = editorItem{}
			modal.dirty = true
		}
	case tcell.KeyCtrlS:
		return false, a.saveFormModal(ctx, modal)
	default:
		switch ev.Rune() {
		case 'e':
			return false, a.editFormField(ctx, modal, modal.fields[visible[modal.cursor]])
		case 's':
			return false, a.saveFormModal(ctx, modal)
		case ' ':
			field := modal.fields[visible[modal.cursor]]
			if field.kind == fieldKindBool {
				field.boolValue = !field.boolValue
				modal.dirty = true
			}
		case 'x':
			field := modal.fields[visible[modal.cursor]]
			if field.kind == fieldKindSingleRef {
				field.refValue = editorItem{}
				modal.dirty = true
			}
		}
	}
	modal.scroll = clampInt(modal.scroll, 0, max(0, len(visible)-1))
	if modal.cursor < modal.scroll {
		modal.scroll = modal.cursor
	}
	return false, nil
}

func (a *App) handlePickerModalKey(modal *pickerModal, ev *tcell.EventKey) (bool, error) {
	if modal == nil {
		return false, nil
	}
	switch ev.Key() {
	case tcell.KeyEscape:
		a.popModal()
		if modal.onCancel != nil {
			modal.onCancel(a)
		}
	case tcell.KeyUp:
		if modal.cursor > 0 {
			modal.cursor--
		}
	case tcell.KeyDown:
		filtered := filteredPickerOptions(modal)
		if modal.cursor < len(filtered)-1 {
			modal.cursor++
		}
	case tcell.KeyBackspace, tcell.KeyBackspace2:
		if modal.query != "" {
			modal.query = modal.query[:len(modal.query)-1]
			modal.cursor = 0
		}
	case tcell.KeyEnter:
		filtered := filteredPickerOptions(modal)
		if len(filtered) == 0 {
			return false, nil
		}
		choice := filtered[clampInt(modal.cursor, 0, len(filtered)-1)]
		a.popModal()
		if modal.onPick != nil {
			modal.onPick(a, choice)
		}
	default:
		if ev.Key() == tcell.KeyRune {
			modal.query += string(ev.Rune())
			modal.cursor = 0
		}
	}
	return false, nil
}

func (a *App) handleListEditorModalKey(modal *listEditorModal, ev *tcell.EventKey) (bool, error) {
	if modal == nil {
		return false, nil
	}
	if len(modal.items) == 0 {
		modal.cursor = 0
	} else {
		modal.cursor = clampInt(modal.cursor, 0, len(modal.items)-1)
	}
	switch ev.Key() {
	case tcell.KeyEscape:
		a.popModal()
	case tcell.KeyUp:
		if modal.cursor > 0 {
			modal.cursor--
		}
	case tcell.KeyDown:
		if modal.cursor < len(modal.items)-1 {
			modal.cursor++
		}
	case tcell.KeyEnter:
		if len(modal.items) > 0 && modal.onEdit != nil {
			modal.onEdit(a, modal, modal.cursor)
		}
	case tcell.KeyDelete:
		if len(modal.items) > 0 {
			modal.items = append(modal.items[:modal.cursor], modal.items[modal.cursor+1:]...)
			if modal.cursor >= len(modal.items) && modal.cursor > 0 {
				modal.cursor--
			}
		}
	case tcell.KeyCtrlS:
		if modal.onSave != nil {
			items := append([]editorItem(nil), modal.items...)
			modal.onSave(a, items)
		}
		a.popModal()
	default:
		switch ev.Rune() {
		case 'a':
			if modal.onAdd != nil {
				modal.onAdd(a, modal)
			}
		case 'e':
			if len(modal.items) > 0 && modal.onEdit != nil {
				modal.onEdit(a, modal, modal.cursor)
			}
		case 'x':
			if len(modal.items) > 0 {
				modal.items = append(modal.items[:modal.cursor], modal.items[modal.cursor+1:]...)
				if modal.cursor >= len(modal.items) && modal.cursor > 0 {
					modal.cursor--
				}
			}
		case '[':
			if modal.cursor > 0 {
				modal.items[modal.cursor-1], modal.items[modal.cursor] = modal.items[modal.cursor], modal.items[modal.cursor-1]
				modal.cursor--
			}
		case ']':
			if modal.cursor >= 0 && modal.cursor < len(modal.items)-1 {
				modal.items[modal.cursor+1], modal.items[modal.cursor] = modal.items[modal.cursor], modal.items[modal.cursor+1]
				modal.cursor++
			}
		case 's':
			if modal.onSave != nil {
				items := append([]editorItem(nil), modal.items...)
				modal.onSave(a, items)
			}
			a.popModal()
		}
	}
	return false, nil
}

func (a *App) handleTextInputModalKey(modal *textInputModal, ev *tcell.EventKey) (bool, error) {
	if modal == nil {
		return false, nil
	}
	switch {
	case isPasteShortcut(ev):
		if a.clipboard == nil {
			a.status = "Clipboard is unavailable."
			return false, nil
		}
		text, err := a.clipboard.ReadText()
		if err != nil {
			a.status = clipboardStatus("Clipboard read failed", err)
			return false, nil
		}
		insertText(modal, text)
		return false, nil
	}
	switch ev.Key() {
	case tcell.KeyEscape:
		a.popModal()
	case tcell.KeyCtrlS:
		if modal.onSave != nil {
			modal.onSave(a, strings.Join(modal.lines, "\n"))
		}
		a.popModal()
	case tcell.KeyEnter:
		if modal.multiline {
			insertText(modal, "\n")
		} else {
			if modal.onSave != nil {
				modal.onSave(a, strings.Join(modal.lines, "\n"))
			}
			a.popModal()
		}
	case tcell.KeyLeft:
		moveTextCursorLeft(modal)
	case tcell.KeyRight:
		moveTextCursorRight(modal)
	case tcell.KeyUp:
		if modal.cursorY > 0 {
			modal.cursorY--
			modal.cursorX = clampInt(modal.cursorX, 0, len(modal.lines[modal.cursorY]))
		}
	case tcell.KeyDown:
		if modal.cursorY < len(modal.lines)-1 {
			modal.cursorY++
			modal.cursorX = clampInt(modal.cursorX, 0, len(modal.lines[modal.cursorY]))
		}
	case tcell.KeyHome:
		modal.cursorX = 0
	case tcell.KeyEnd:
		modal.cursorX = len(modal.lines[modal.cursorY])
	case tcell.KeyBackspace, tcell.KeyBackspace2:
		deleteTextLeft(modal)
	case tcell.KeyDelete:
		deleteTextRight(modal)
	default:
		switch {
		case ev.Key() == tcell.KeyRune:
			insertText(modal, string(ev.Rune()))
		case ev.Rune() == 's':
			// handled above via Ctrl+S; plain 's' is text
		}
	}
	return false, nil
}

func (a *App) handleConfirmModalKey(ctx context.Context, modal *confirmModal, ev *tcell.EventKey) (bool, error) {
	if modal == nil {
		return false, nil
	}
	switch ev.Key() {
	case tcell.KeyEscape:
		a.popModal()
	case tcell.KeyEnter:
		a.popModal()
		if modal.onConfirm != nil {
			if err := modal.onConfirm(ctx, a); err != nil {
				a.status = err.Error()
			}
		}
	default:
		switch ev.Rune() {
		case 'y', 'Y':
			a.popModal()
			if modal.onConfirm != nil {
				if err := modal.onConfirm(ctx, a); err != nil {
					a.status = err.Error()
				}
			}
		case 'n', 'N':
			a.popModal()
		}
	}
	return false, nil
}

func (a *App) renderDetailModal(modal *detailModal) {
	if modal == nil {
		return
	}
	x, y, w, h := a.modalRect(100, 24)
	footer := "Esc close | Up/Down scroll"
	if modal.canEdit {
		footer = "e edit | " + footer
	}
	if modal.canConnect {
		footer = "Enter/c connect | " + footer
	}
	a.drawModalBox(x, y, w, h, modal.title, footer)
	maxLines := max(1, h-4)
	scrollMax := max(0, len(modal.lines)-maxLines)
	modal.scroll = clampInt(modal.scroll, 0, scrollMax)
	for i := 0; i < maxLines && modal.scroll+i < len(modal.lines); i++ {
		drawText(a.screen, x+1, y+2+i, tcell.StyleDefault, truncate(modal.lines[modal.scroll+i], w-2))
	}
}

func (a *App) renderFormModal(modal *formModal) {
	if modal == nil {
		return
	}
	x, y, w, h := a.modalRect(104, 26)
	footer := "Enter edit | Space toggle | s save | Esc close"
	a.drawModalBox(x, y, w, h, modal.title, footer)
	indexes := visibleFieldIndexes(modal)
	maxLines := max(1, h-4)
	scrollMax := max(0, len(indexes)-maxLines)
	modal.cursor = clampInt(modal.cursor, 0, max(0, len(indexes)-1))
	if modal.cursor < modal.scroll {
		modal.scroll = modal.cursor
	}
	if modal.cursor >= modal.scroll+maxLines {
		modal.scroll = modal.cursor - maxLines + 1
	}
	modal.scroll = clampInt(modal.scroll, 0, scrollMax)
	for i := 0; i < maxLines && modal.scroll+i < len(indexes); i++ {
		field := modal.fields[indexes[modal.scroll+i]]
		style := tcell.StyleDefault
		if modal.scroll+i == modal.cursor {
			style = style.Background(tcell.ColorDarkSlateGray)
		}
		label := field.label
		if field.required {
			label += "*"
		}
		line := fmt.Sprintf("%-20s %s", label, truncate(formFieldDisplayValue(field), max(0, w-24)))
		drawText(a.screen, x+1, y+2+i, style, truncate(line, w-2))
	}
}

func (a *App) renderPickerModal(modal *pickerModal) {
	if modal == nil {
		return
	}
	x, y, w, h := a.modalRect(80, 20)
	a.drawModalBox(x, y, w, h, modal.title, "Type to filter | Enter pick | Esc close")
	drawText(a.screen, x+1, y+2, tcell.StyleDefault.Foreground(tcell.ColorYellow), truncate("Search: "+modal.query, w-2))
	filtered := filteredPickerOptions(modal)
	if len(filtered) == 0 {
		drawText(a.screen, x+1, y+4, tcell.StyleDefault, "(no matches)")
		return
	}
	maxLines := max(1, h-5)
	modal.cursor = clampInt(modal.cursor, 0, len(filtered)-1)
	scroll := 0
	if modal.cursor >= maxLines {
		scroll = modal.cursor - maxLines + 1
	}
	for i := 0; i < maxLines && scroll+i < len(filtered); i++ {
		style := tcell.StyleDefault
		if scroll+i == modal.cursor {
			style = style.Background(tcell.ColorDarkSlateGray)
		}
		item := filtered[scroll+i]
		line := item.Label
		if item.ID != "" && item.ID != item.Label {
			line += " (" + item.ID + ")"
		}
		drawText(a.screen, x+1, y+4+i, style, truncate(line, w-2))
	}
}

func (a *App) renderListEditorModal(modal *listEditorModal) {
	if modal == nil {
		return
	}
	x, y, w, h := a.modalRect(90, 22)
	a.drawModalBox(x, y, w, h, modal.title, "a add | e edit | x delete | [ ] move | s save | Esc close")
	if len(modal.items) == 0 {
		drawText(a.screen, x+1, y+2, tcell.StyleDefault, "(empty)")
		return
	}
	maxLines := max(1, h-4)
	scrollMax := max(0, len(modal.items)-maxLines)
	modal.cursor = clampInt(modal.cursor, 0, len(modal.items)-1)
	if modal.cursor < modal.scroll {
		modal.scroll = modal.cursor
	}
	if modal.cursor >= modal.scroll+maxLines {
		modal.scroll = modal.cursor - maxLines + 1
	}
	modal.scroll = clampInt(modal.scroll, 0, scrollMax)
	for i := 0; i < maxLines && modal.scroll+i < len(modal.items); i++ {
		style := tcell.StyleDefault
		if modal.scroll+i == modal.cursor {
			style = style.Background(tcell.ColorDarkSlateGray)
		}
		item := modal.items[modal.scroll+i]
		drawText(a.screen, x+1, y+2+i, style, truncate(itemDisplayValue(item), w-2))
	}
}

func (a *App) renderTextInputModal(modal *textInputModal) {
	if modal == nil {
		return
	}
	x, y, w, h := a.modalRect(96, 26)
	footer := "Ctrl+S save | Esc close"
	if modal.multiline {
		footer = "Enter newline | Ctrl+Shift+V paste | " + footer
	}
	a.drawModalBox(x, y, w, h, modal.title, footer)
	maxLines := max(1, h-4)
	if modal.cursorY < modal.scroll {
		modal.scroll = modal.cursorY
	}
	if modal.cursorY >= modal.scroll+maxLines {
		modal.scroll = modal.cursorY - maxLines + 1
	}
	for i := 0; i < maxLines && modal.scroll+i < len(modal.lines); i++ {
		line := modal.lines[modal.scroll+i]
		if modal.secret {
			line = strings.Repeat("*", len(line))
		}
		drawText(a.screen, x+1, y+2+i, tcell.StyleDefault, truncate(line, w-2))
	}
	cursorX := x + 1 + clampInt(modal.cursorX, 0, max(0, w-3))
	cursorY := y + 2 + clampInt(modal.cursorY-modal.scroll, 0, maxLines-1)
	a.screen.ShowCursor(cursorX, cursorY)
}

func (a *App) renderConfirmModal(modal *confirmModal) {
	if modal == nil {
		return
	}
	x, y, w, h := a.modalRect(72, 10)
	a.drawModalBox(x, y, w, h, modal.title, "Enter/Y confirm | Esc/N cancel")
	for i := 0; i < h-4 && i < len(modal.lines); i++ {
		drawText(a.screen, x+1, y+2+i, tcell.StyleDefault, truncate(modal.lines[i], w-2))
	}
}

func (a *App) buildFormModal(ctx context.Context, kind domain.DocumentKind, id string, isNew bool) (*formModal, error) {
	switch kind {
	case domain.KindHost:
		return a.buildHostForm(ctx, id, isNew)
	case domain.KindGroup:
		return a.buildGroupForm(ctx, id, isNew)
	case domain.KindProfile:
		return a.buildProfileForm(ctx, id, isNew)
	case domain.KindIdentity:
		return a.buildIdentityForm(ctx, id, isNew)
	case domain.KindKey:
		return a.buildKeyForm(ctx, id, isNew)
	case domain.KindForward:
		return a.buildForwardForm(ctx, id, isNew)
	case domain.KindKnownHost:
		return a.buildKnownHostForm(ctx, id, isNew)
	default:
		return nil, fmt.Errorf("unsupported form kind %s", kind)
	}
}

func (a *App) buildHostForm(ctx context.Context, id string, isNew bool) (*formModal, error) {
	host := &domain.Host{}
	if !isNew {
		var err error
		host, err = a.loadEditableHost(ctx, id)
		if err != nil {
			return nil, err
		}
	}
	form := &formModal{
		title: "Edit HOST",
		kind:  domain.KindHost,
		id:    host.ID,
		isNew: isNew,
		fields: []*formField{
			{key: "title", label: "Title", kind: fieldKindText, value: host.Title},
			{key: "hostname", label: "Hostname", kind: fieldKindText, required: true, value: host.Hostname},
			{key: "port", label: "Port", kind: fieldKindInt, value: intPtrString(host.Port)},
			{key: "username", label: "Username", kind: fieldKindText, value: stringPtrValue(host.Username)},
			{key: "groups", label: "Groups", kind: fieldKindRefList, refKind: domain.KindGroup, items: a.refItems(ctx, domain.KindGroup, host.GroupIDs)},
			{key: "profiles", label: "Profiles", kind: fieldKindRefList, refKind: domain.KindProfile, items: a.refItems(ctx, domain.KindProfile, host.ProfileIDs)},
			{key: "identity_ref", label: "Identity", kind: fieldKindSingleRef, refKind: domain.KindIdentity, refValue: a.refItem(ctx, domain.KindIdentity, stringPtrValue(host.IdentityRef))},
			{key: "key_ref", label: "Direct Key", kind: fieldKindSingleRef, refKind: domain.KindKey, refValue: a.refItem(ctx, domain.KindKey, stringPtrValue(host.KeyRef))},
			{key: "password", label: "Direct Password", kind: fieldKindSecret, value: host.Password, secret: true},
			{key: "forwards", label: "Forwards", kind: fieldKindRefList, refKind: domain.KindForward, items: a.refItems(ctx, domain.KindForward, host.ForwardIDs)},
			{key: "kh_policy", label: "KnownHosts Policy", kind: fieldKindEnum, value: knownHostsPolicyValue(host.KnownHosts), options: []string{"", string(domain.KnownHostsStrict), string(domain.KnownHostsAcceptNew), string(domain.KnownHostsOff)}},
			{key: "kh_backend", label: "KnownHosts Backend", kind: fieldKindEnum, value: knownHostsBackendValue(host.KnownHosts), options: []string{"", string(domain.KnownHostsBackendVault), string(domain.KnownHostsBackendFile), string(domain.KnownHostsBackendVaultFile), string(domain.KnownHostsBackendFileVault)}},
			{key: "kh_path", label: "KnownHosts Path", kind: fieldKindText, value: knownHostsPathValue(host.KnownHosts)},
			{key: "jump", label: "Jump Hosts", kind: fieldKindStringList, items: stringItems(routeProxyJumps(host.Route))},
			{key: "proxy_type", label: "Proxy Type", kind: fieldKindEnum, value: routeProxyType(host.Route), options: []string{"", string(domain.ProxySOCKS5), string(domain.ProxyHTTP)}},
			{key: "proxy_address", label: "Proxy Address", kind: fieldKindText, value: routeProxyAddress(host.Route), visible: visibleWhenProxyType},
			{key: "proxy_username", label: "Proxy Username", kind: fieldKindText, value: routeProxyUsername(host.Route), visible: visibleWhenProxyType},
			{key: "proxy_password", label: "Proxy Password", kind: fieldKindSecret, value: routeProxyPassword(host.Route), secret: true, visible: visibleWhenProxyType},
		},
	}
	form.onSave = func(ctx context.Context, app *App, form *formModal) error {
		host := domain.Host{
			ID:          form.id,
			Title:       formValue(form, "title"),
			Hostname:    strings.TrimSpace(formValue(form, "hostname")),
			Port:        parseOptionalIntPtr(formValue(form, "port")),
			Username:    parseOptionalStringPtr(formValue(form, "username")),
			GroupIDs:    itemIDs(formItems(form, "groups")),
			ProfileIDs:  itemIDs(formItems(form, "profiles")),
			IdentityRef: parseOptionalRefPtr(formFieldByKey(form, "identity_ref")),
			KeyRef:      parseOptionalRefPtr(formFieldByKey(form, "key_ref")),
			Password:    formValue(form, "password"),
			ForwardIDs:  itemIDs(formItems(form, "forwards")),
		}
		host.KnownHosts = buildKnownHostsConfigFromForm(form)
		host.Route = buildRouteFromForm(form)
		if err := app.catalog.SaveHost(ctx, &host); err != nil {
			return err
		}
		return app.completeFormSave(ctx, form, host.ID, host.Label())
	}
	return form, nil
}

func (a *App) buildGroupForm(ctx context.Context, id string, isNew bool) (*formModal, error) {
	group := &domain.Group{}
	if !isNew {
		var err error
		group, err = a.catalog.GetGroup(ctx, id)
		if err != nil {
			return nil, err
		}
	}
	form := &formModal{
		title: "Edit GROUP",
		kind:  domain.KindGroup,
		id:    group.ID,
		isNew: isNew,
		fields: []*formField{
			{key: "name", label: "Name", kind: fieldKindText, required: true, value: group.Name},
			{key: "description", label: "Description", kind: fieldKindTextArea, value: group.Description},
		},
	}
	form.onSave = func(ctx context.Context, app *App, form *formModal) error {
		group := domain.Group{
			ID:          form.id,
			Name:        strings.TrimSpace(formValue(form, "name")),
			Description: formValue(form, "description"),
		}
		if err := app.catalog.SaveGroup(ctx, &group); err != nil {
			return err
		}
		return app.completeFormSave(ctx, form, group.ID, group.Label())
	}
	return form, nil
}

func (a *App) buildProfileForm(ctx context.Context, id string, isNew bool) (*formModal, error) {
	profile := &domain.Profile{}
	if !isNew {
		var err error
		profile, err = a.loadEditableProfile(ctx, id)
		if err != nil {
			return nil, err
		}
	}
	form := &formModal{
		title: "Edit PROFILE",
		kind:  domain.KindProfile,
		id:    profile.ID,
		isNew: isNew,
		fields: []*formField{
			{key: "name", label: "Name", kind: fieldKindText, required: true, value: profile.Name},
			{key: "description", label: "Description", kind: fieldKindTextArea, value: profile.Description},
			{key: "port", label: "Port", kind: fieldKindInt, value: intPtrString(profile.Port)},
			{key: "username", label: "Username", kind: fieldKindText, value: stringPtrValue(profile.Username)},
			{key: "identity_ref", label: "Identity", kind: fieldKindSingleRef, refKind: domain.KindIdentity, refValue: a.refItem(ctx, domain.KindIdentity, stringPtrValue(profile.IdentityRef))},
			{key: "forwards", label: "Forwards", kind: fieldKindRefList, refKind: domain.KindForward, items: a.refItems(ctx, domain.KindForward, profile.ForwardIDs)},
			{key: "kh_policy", label: "KnownHosts Policy", kind: fieldKindEnum, value: knownHostsPolicyValue(profile.KnownHosts), options: []string{"", string(domain.KnownHostsStrict), string(domain.KnownHostsAcceptNew), string(domain.KnownHostsOff)}},
			{key: "kh_backend", label: "KnownHosts Backend", kind: fieldKindEnum, value: knownHostsBackendValue(profile.KnownHosts), options: []string{"", string(domain.KnownHostsBackendVault), string(domain.KnownHostsBackendFile), string(domain.KnownHostsBackendVaultFile), string(domain.KnownHostsBackendFileVault)}},
			{key: "kh_path", label: "KnownHosts Path", kind: fieldKindText, value: knownHostsPathValue(profile.KnownHosts)},
			{key: "jump", label: "Jump Hosts", kind: fieldKindStringList, items: stringItems(routeProxyJumps(profile.Route))},
			{key: "proxy_type", label: "Proxy Type", kind: fieldKindEnum, value: routeProxyType(profile.Route), options: []string{"", string(domain.ProxySOCKS5), string(domain.ProxyHTTP)}},
			{key: "proxy_address", label: "Proxy Address", kind: fieldKindText, value: routeProxyAddress(profile.Route), visible: visibleWhenProxyType},
			{key: "proxy_username", label: "Proxy Username", kind: fieldKindText, value: routeProxyUsername(profile.Route), visible: visibleWhenProxyType},
			{key: "proxy_password", label: "Proxy Password", kind: fieldKindSecret, value: routeProxyPassword(profile.Route), secret: true, visible: visibleWhenProxyType},
		},
	}
	form.onSave = func(ctx context.Context, app *App, form *formModal) error {
		profile := domain.Profile{
			ID:          form.id,
			Name:        strings.TrimSpace(formValue(form, "name")),
			Description: formValue(form, "description"),
			Port:        parseOptionalIntPtr(formValue(form, "port")),
			Username:    parseOptionalStringPtr(formValue(form, "username")),
			IdentityRef: parseOptionalRefPtr(formFieldByKey(form, "identity_ref")),
			ForwardIDs:  itemIDs(formItems(form, "forwards")),
		}
		profile.KnownHosts = buildKnownHostsConfigFromForm(form)
		profile.Route = buildRouteFromForm(form)
		if err := app.catalog.SaveProfile(ctx, &profile); err != nil {
			return err
		}
		return app.completeFormSave(ctx, form, profile.ID, profile.Label())
	}
	return form, nil
}

func (a *App) buildIdentityForm(ctx context.Context, id string, isNew bool) (*formModal, error) {
	identity := &domain.Identity{}
	if !isNew {
		var err error
		identity, err = a.loadEditableIdentity(ctx, id)
		if err != nil {
			return nil, err
		}
	}
	form := &formModal{
		title: "Edit IDENTITY",
		kind:  domain.KindIdentity,
		id:    identity.ID,
		isNew: isNew,
		fields: []*formField{
			{key: "name", label: "Name", kind: fieldKindText, required: true, value: identity.Name},
			{key: "username", label: "Username", kind: fieldKindText, required: true, value: identity.Username},
			{key: "methods", label: "Methods", kind: fieldKindMethodList, items: methodItems(ctx, a, identity.Methods)},
		},
	}
	form.onSave = func(ctx context.Context, app *App, form *formModal) error {
		identity := domain.Identity{
			ID:       form.id,
			Name:     strings.TrimSpace(formValue(form, "name")),
			Username: strings.TrimSpace(formValue(form, "username")),
			Methods:  itemMethods(formItems(form, "methods")),
		}
		if err := app.catalog.SaveIdentity(ctx, &identity); err != nil {
			return err
		}
		return app.completeFormSave(ctx, form, identity.ID, identity.Label())
	}
	return form, nil
}

func (a *App) buildKeyForm(ctx context.Context, id string, isNew bool) (*formModal, error) {
	key := &domain.Key{}
	if !isNew {
		var err error
		key, err = a.loadEditableKey(ctx, id)
		if err != nil {
			return nil, err
		}
	} else {
		key.Kind = domain.KeyKindPrivateKey
	}
	form := &formModal{
		title: "Edit KEY",
		kind:  domain.KindKey,
		id:    key.ID,
		isNew: isNew,
		fields: []*formField{
			{key: "name", label: "Name", kind: fieldKindText, required: true, value: key.Name},
			{key: "kind", label: "Kind", kind: fieldKindEnum, value: string(key.Kind), options: []string{string(domain.KeyKindPrivateKey), string(domain.KeyKindAgent)}},
			{key: "source_path", label: "Source Path", kind: fieldKindText, value: key.SourcePath, visible: visibleWhenKeyPrivate},
			{key: "private_key_pem", label: "Private Key PEM", kind: fieldKindTextArea, value: key.PrivateKeyPEM, secret: true, visible: visibleWhenKeyPrivate},
			{key: "passphrase", label: "Passphrase", kind: fieldKindSecret, value: key.Passphrase, secret: true, visible: visibleWhenKeyPrivate},
			{key: "agent_socket", label: "Agent Socket", kind: fieldKindText, value: key.AgentSocket, visible: visibleWhenKeyAgent},
		},
	}
	form.onSave = func(ctx context.Context, app *App, form *formModal) error {
		key := domain.Key{
			ID:            form.id,
			Name:          strings.TrimSpace(formValue(form, "name")),
			Kind:          domain.KeyKind(formValue(form, "kind")),
			SourcePath:    formValue(form, "source_path"),
			PrivateKeyPEM: formValue(form, "private_key_pem"),
			Passphrase:    formValue(form, "passphrase"),
			AgentSocket:   formValue(form, "agent_socket"),
		}
		if err := app.catalog.SaveKey(ctx, &key); err != nil {
			return err
		}
		return app.completeFormSave(ctx, form, key.ID, key.Label())
	}
	return form, nil
}

func (a *App) buildForwardForm(ctx context.Context, id string, isNew bool) (*formModal, error) {
	forward := &domain.Forward{Enabled: true}
	if !isNew {
		var err error
		forward, err = a.catalog.GetForward(ctx, id)
		if err != nil {
			return nil, err
		}
	}
	form := &formModal{
		title: "Edit FORWARD",
		kind:  domain.KindForward,
		id:    forward.ID,
		isNew: isNew,
		fields: []*formField{
			{key: "name", label: "Name", kind: fieldKindText, required: true, value: forward.Name},
			{key: "description", label: "Description", kind: fieldKindTextArea, value: forward.Description},
			{key: "type", label: "Type", kind: fieldKindEnum, value: string(forward.Type), options: []string{string(domain.ForwardLocal), string(domain.ForwardRemote), string(domain.ForwardDynamic)}},
			{key: "listen_host", label: "Listen Host", kind: fieldKindText, value: forward.ListenHost},
			{key: "listen_port", label: "Listen Port", kind: fieldKindInt, required: true, value: strconv.Itoa(forward.ListenPort)},
			{key: "target_host", label: "Target Host", kind: fieldKindText, value: forward.TargetHost, visible: visibleWhenForwardTarget},
			{key: "target_port", label: "Target Port", kind: fieldKindInt, value: optionalIntString(forward.TargetPort), visible: visibleWhenForwardTarget},
			{key: "auto_start", label: "Auto Start", kind: fieldKindBool, boolValue: forward.AutoStart},
			{key: "enabled", label: "Enabled", kind: fieldKindBool, boolValue: forward.Enabled},
		},
	}
	form.onSave = func(ctx context.Context, app *App, form *formModal) error {
		listenPort, err := parseRequiredInt(formValue(form, "listen_port"), "listen port")
		if err != nil {
			return err
		}
		forward := domain.Forward{
			ID:          form.id,
			Name:        strings.TrimSpace(formValue(form, "name")),
			Description: formValue(form, "description"),
			Type:        domain.ForwardType(formValue(form, "type")),
			ListenHost:  formValue(form, "listen_host"),
			ListenPort:  listenPort,
			TargetHost:  formValue(form, "target_host"),
			TargetPort:  parseOptionalInt(formValue(form, "target_port")),
			AutoStart:   formBool(form, "auto_start"),
			Enabled:     formBool(form, "enabled"),
		}
		if err := app.catalog.SaveForward(ctx, &forward); err != nil {
			return err
		}
		return app.completeFormSave(ctx, form, forward.ID, forward.Label())
	}
	return form, nil
}

func (a *App) buildKnownHostForm(ctx context.Context, id string, isNew bool) (*formModal, error) {
	entry := &domain.KnownHost{Source: string(domain.KnownHostsBackendVault)}
	if !isNew {
		var err error
		entry, err = service.LoadKnownHostEntry(ctx, a.catalog, a.paths.KnownHostsPath, id)
		if err != nil {
			return nil, err
		}
	}
	form := &formModal{
		title: "Edit KNOWN-HOST",
		kind:  domain.KindKnownHost,
		id:    entry.ID,
		isNew: isNew,
		fields: []*formField{
			{key: "source", label: "Source", kind: fieldKindEnum, value: entry.Source, options: []string{string(domain.KnownHostsBackendVault), string(domain.KnownHostsBackendFile)}},
			{key: "hosts", label: "Hosts", kind: fieldKindStringList, items: stringItems(entry.Hosts)},
			{key: "public_key", label: "Public Key", kind: fieldKindTextArea, required: true, value: entry.PublicKey},
		},
	}
	form.onSave = func(ctx context.Context, app *App, form *formModal) error {
		source := formValue(form, "source")
		if source == "" {
			source = string(domain.KnownHostsBackendVault)
		}
		entry := domain.KnownHost{
			ID:        form.id,
			Source:    source,
			Hosts:     itemValues(formItems(form, "hosts")),
			PublicKey: strings.TrimSpace(formValue(form, "public_key")),
		}
		previousSource := ""
		if form.id != "" {
			if strings.HasPrefix(form.id, "file:") {
				previousSource = string(domain.KnownHostsBackendFile)
			} else {
				previousSource = string(domain.KnownHostsBackendVault)
			}
		}
		if previousSource != "" && previousSource != entry.Source {
			spec := form.id
			if _, err := service.DeleteKnownHostsEntries(ctx, app.catalog, app.paths.KnownHostsPath, spec, previousSource); err != nil {
				return err
			}
			entry.ID = ""
		}
		if err := service.SaveKnownHostEntry(ctx, app.catalog, app.paths.KnownHostsPath, &entry); err != nil {
			return err
		}
		return app.completeFormSave(ctx, form, entry.ID, entry.Label())
	}
	return form, nil
}

func (a *App) editFormField(ctx context.Context, form *formModal, field *formField) error {
	if field == nil {
		return nil
	}
	switch field.kind {
	case fieldKindBool:
		field.boolValue = !field.boolValue
		form.dirty = true
		return nil
	case fieldKindText, fieldKindInt, fieldKindSecret, fieldKindTextArea:
		multiline := field.kind == fieldKindTextArea
		a.pushModal(modalState{
			kind: modalKindTextInput,
			textInput: newTextInputModal(field.label, field.value, multiline, field.secret, func(app *App, value string) {
				field.value = value
				form.dirty = true
			}),
		})
		return nil
	case fieldKindEnum:
		options := make([]pickerOption, 0, len(field.options))
		for _, option := range field.options {
			label := option
			if label == "" {
				label = "(empty)"
			}
			options = append(options, pickerOption{Label: label, Value: option})
		}
		a.pushModal(modalState{
			kind: modalKindPicker,
			picker: &pickerModal{
				title:   "Pick " + field.label,
				options: options,
				onPick: func(app *App, choice pickerOption) {
					field.value = choice.Value
					form.dirty = true
				},
			},
		})
		return nil
	case fieldKindSingleRef:
		return a.openRefPicker(ctx, "Pick "+field.label, field.refKind, true, func(item editorItem) {
			field.refValue = item
			form.dirty = true
		})
	case fieldKindRefList:
		a.openRefListEditor(ctx, form, field)
		return nil
	case fieldKindStringList:
		a.openStringListEditor(form, field)
		return nil
	case fieldKindMethodList:
		a.openMethodListEditor(ctx, form, field)
		return nil
	default:
		return nil
	}
}

func (a *App) saveFormModal(ctx context.Context, form *formModal) error {
	if form == nil || form.onSave == nil {
		return nil
	}
	return form.onSave(ctx, a, form)
}

func (a *App) deleteObject(ctx context.Context, kind domain.DocumentKind, id string) error {
	if kind == domain.KindKnownHost {
		source := "vault"
		if strings.HasPrefix(id, "file:") {
			source = "file"
		}
		_, err := service.DeleteKnownHostsEntries(ctx, a.catalog, a.paths.KnownHostsPath, id, source)
		return err
	}
	return a.catalog.Delete(ctx, id)
}

func (a *App) openHostSessionByID(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	w, h := a.screen.Size()
	session, err := a.connector.OpenEmbeddedSession(ctx, id, a.sessionPrompts(ctx), w, max(1, h-3))
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
	a.status = ""
	a.setActiveTab(len(a.tabs))
	a.setActiveSession(len(a.sessions) - 1)
	a.resetCursorBlink()
	return nil
}

func (a *App) openRefPicker(ctx context.Context, title string, kind domain.DocumentKind, allowEmpty bool, onPick func(editorItem)) error {
	records, err := a.listRecords(ctx, kind)
	if err != nil {
		return err
	}
	options := make([]pickerOption, 0, len(records)+1)
	if allowEmpty {
		options = append(options, pickerOption{Label: "(none)", Value: ""})
	}
	for _, record := range records {
		options = append(options, pickerOption{
			ID:    record.ID,
			Label: record.Label,
			Value: record.ID,
			Kind:  kind,
		})
	}
	sortDocumentSummariesByLabel(options)
	a.pushModal(modalState{
		kind: modalKindPicker,
		picker: &pickerModal{
			title:   title,
			options: options,
			onPick: func(app *App, choice pickerOption) {
				onPick(editorItem{ID: choice.Value, Label: choice.Label, Value: choice.Value})
			},
		},
	})
	return nil
}

func (a *App) openRefListEditor(ctx context.Context, form *formModal, field *formField) {
	editor := &listEditorModal{
		title:    field.label,
		items:    cloneEditorItems(field.items),
		original: cloneEditorItems(field.items),
		onSave: func(app *App, items []editorItem) {
			field.items = cloneEditorItems(items)
			form.dirty = true
		},
		onAdd: func(app *App, editor *listEditorModal) {
			_ = app.openRefPicker(context.Background(), "Add "+field.label, field.refKind, false, func(item editorItem) {
				editor.items = append(editor.items, item)
			})
		},
		onEdit: func(app *App, editor *listEditorModal, index int) {
			_ = app.openRefPicker(context.Background(), "Replace "+field.label, field.refKind, false, func(item editorItem) {
				if index >= 0 && index < len(editor.items) {
					editor.items[index] = item
				}
			})
		},
	}
	a.pushModal(modalState{kind: modalKindListEditor, listEditor: editor})
}

func (a *App) openStringListEditor(form *formModal, field *formField) {
	editor := &listEditorModal{
		title:    field.label,
		items:    cloneEditorItems(field.items),
		original: cloneEditorItems(field.items),
		onSave: func(app *App, items []editorItem) {
			field.items = cloneEditorItems(items)
			form.dirty = true
		},
		onAdd: func(app *App, editor *listEditorModal) {
			app.pushModal(modalState{
				kind: modalKindTextInput,
				textInput: newTextInputModal("Add "+field.label, "", false, false, func(app *App, value string) {
					value = strings.TrimSpace(value)
					if value != "" {
						editor.items = append(editor.items, editorItem{Value: value, Label: value})
					}
				}),
			})
		},
		onEdit: func(app *App, editor *listEditorModal, index int) {
			if index < 0 || index >= len(editor.items) {
				return
			}
			app.pushModal(modalState{
				kind: modalKindTextInput,
				textInput: newTextInputModal("Edit "+field.label, editor.items[index].Value, false, false, func(app *App, value string) {
					value = strings.TrimSpace(value)
					if value == "" {
						return
					}
					editor.items[index] = editorItem{Value: value, Label: value}
				}),
			})
		},
	}
	a.pushModal(modalState{kind: modalKindListEditor, listEditor: editor})
}

func (a *App) openMethodListEditor(ctx context.Context, form *formModal, field *formField) {
	editor := &listEditorModal{
		title:    field.label,
		items:    cloneEditorItems(field.items),
		original: cloneEditorItems(field.items),
		onSave: func(app *App, items []editorItem) {
			field.items = cloneEditorItems(items)
			form.dirty = true
		},
		onAdd: func(app *App, editor *listEditorModal) {
			app.pushModal(modalState{kind: modalKindForm, form: buildAuthMethodForm(ctx, app, nil, func(method domain.AuthMethod) {
				editor.items = append(editor.items, editorItem{Method: &method, Label: authMethodLabel(ctx, app, method)})
			})})
		},
		onEdit: func(app *App, editor *listEditorModal, index int) {
			if index < 0 || index >= len(editor.items) {
				return
			}
			var existing *domain.AuthMethod
			if editor.items[index].Method != nil {
				copyMethod := *editor.items[index].Method
				existing = &copyMethod
			}
			app.pushModal(modalState{kind: modalKindForm, form: buildAuthMethodForm(ctx, app, existing, func(method domain.AuthMethod) {
				editor.items[index] = editorItem{Method: &method, Label: authMethodLabel(ctx, app, method)}
			})})
		},
	}
	a.pushModal(modalState{kind: modalKindListEditor, listEditor: editor})
}

func buildAuthMethodForm(ctx context.Context, app *App, existing *domain.AuthMethod, onApply func(domain.AuthMethod)) *formModal {
	method := &domain.AuthMethod{Type: domain.AuthMethodAgent}
	if existing != nil {
		method = existing
	}
	form := &formModal{
		title: "Auth Method",
		kind:  domain.KindIdentity,
		isNew: existing == nil,
		fields: []*formField{
			{key: "type", label: "Type", kind: fieldKindEnum, required: true, value: string(method.Type), options: []string{string(domain.AuthMethodPassword), string(domain.AuthMethodKey), string(domain.AuthMethodAgent)}},
			{key: "password", label: "Password", kind: fieldKindSecret, value: method.Password, secret: true, visible: visibleWhenMethodPassword},
			{key: "key_id", label: "Key", kind: fieldKindSingleRef, refKind: domain.KindKey, refValue: app.refItem(ctx, domain.KindKey, method.KeyID), visible: visibleWhenMethodKey},
			{key: "agent_socket", label: "Agent Socket", kind: fieldKindText, value: method.AgentSocket, visible: visibleWhenMethodAgent},
			{key: "agent_forward", label: "Agent Forward", kind: fieldKindBool, boolValue: method.AgentForward, visible: visibleWhenMethodAgent},
		},
	}
	form.onSave = func(ctx context.Context, app *App, form *formModal) error {
		method := domain.AuthMethod{
			Type:         domain.AuthMethodType(formValue(form, "type")),
			Password:     formValue(form, "password"),
			KeyID:        formRefID(form, "key_id"),
			AgentSocket:  formValue(form, "agent_socket"),
			AgentForward: formBool(form, "agent_forward"),
		}
		onApply(method)
		app.popModal()
		return nil
	}
	return form
}

func (a *App) completeFormSave(ctx context.Context, form *formModal, id, label string) error {
	if err := a.reload(ctx); err != nil {
		return err
	}
	form.id = id
	form.dirty = false
	a.popModal()
	a.selectRecordByID(form.kind, id)
	a.status = fmt.Sprintf("Saved %s %q.", string(form.kind), label)
	if top := a.topModal(); top != nil && top.kind == modalKindDetail && top.detail != nil && top.detail.kind == form.kind {
		detail, err := a.buildDetailModal(ctx, form.kind, id)
		if err == nil {
			top.detail = detail
		}
	}
	return nil
}

func (a *App) selectRecordByID(kind domain.DocumentKind, id string) {
	if id == "" {
		return
	}
	if !a.inSessionTab() && a.currentKind() == kind {
		items := a.currentRecords()
		for i, item := range items {
			if item.ID == id {
				a.cursor = i
				return
			}
		}
	}
}

func (a *App) loadEditableHost(ctx context.Context, id string) (*domain.Host, error) {
	host, err := a.catalog.GetHost(ctx, id)
	if err != nil {
		return nil, err
	}
	if host.Password == "" && host.PasswordSecretID != "" {
		raw, err := a.catalog.OpenSecret(ctx, host.PasswordSecretID)
		if err == nil {
			host.Password = string(raw)
		}
	}
	if host.Route != nil && host.Route.OutboundProxy != nil && host.Route.OutboundProxy.Password == "" && host.Route.OutboundProxy.PasswordSecretID != "" {
		raw, err := a.catalog.OpenSecret(ctx, host.Route.OutboundProxy.PasswordSecretID)
		if err == nil {
			host.Route.OutboundProxy.Password = string(raw)
		}
	}
	return host, nil
}

func (a *App) loadEditableProfile(ctx context.Context, id string) (*domain.Profile, error) {
	profile, err := a.catalog.GetProfile(ctx, id)
	if err != nil {
		return nil, err
	}
	if profile.Route != nil && profile.Route.OutboundProxy != nil && profile.Route.OutboundProxy.Password == "" && profile.Route.OutboundProxy.PasswordSecretID != "" {
		raw, err := a.catalog.OpenSecret(ctx, profile.Route.OutboundProxy.PasswordSecretID)
		if err == nil {
			profile.Route.OutboundProxy.Password = string(raw)
		}
	}
	return profile, nil
}

func (a *App) loadEditableIdentity(ctx context.Context, id string) (*domain.Identity, error) {
	identity, err := a.catalog.GetIdentity(ctx, id)
	if err != nil {
		return nil, err
	}
	for i := range identity.Methods {
		if identity.Methods[i].Password == "" && identity.Methods[i].PasswordSecretID != "" {
			raw, err := a.catalog.OpenSecret(ctx, identity.Methods[i].PasswordSecretID)
			if err == nil {
				identity.Methods[i].Password = string(raw)
			}
		}
	}
	return identity, nil
}

func (a *App) loadEditableKey(ctx context.Context, id string) (*domain.Key, error) {
	key, err := a.catalog.GetKey(ctx, id)
	if err != nil {
		return nil, err
	}
	if key.PrivateKeyPEM == "" && key.PrivateKeySecretID != "" {
		raw, err := a.catalog.OpenSecret(ctx, key.PrivateKeySecretID)
		if err == nil {
			key.PrivateKeyPEM = string(raw)
		}
	}
	if key.Passphrase == "" && key.PassphraseSecretID != "" {
		raw, err := a.catalog.OpenSecret(ctx, key.PassphraseSecretID)
		if err == nil {
			key.Passphrase = string(raw)
		}
	}
	return key, nil
}

func maskHostForDisplay(host *domain.Host) *domain.Host {
	if host == nil {
		return nil
	}
	copyHost := *host
	if copyHost.Password != "" {
		copyHost.Password = maskedSecret(copyHost.Password)
	}
	if copyHost.Route != nil && copyHost.Route.OutboundProxy != nil && copyHost.Route.OutboundProxy.Password != "" {
		copyProxy := *copyHost.Route.OutboundProxy
		copyProxy.Password = maskedSecret(copyProxy.Password)
		copyHost.Route = &domain.Route{ProxyJump: append([]string(nil), copyHost.Route.ProxyJump...), OutboundProxy: &copyProxy}
	}
	return &copyHost
}

func maskProfileForDisplay(profile *domain.Profile) *domain.Profile {
	if profile == nil {
		return nil
	}
	copyProfile := *profile
	if copyProfile.Route != nil && copyProfile.Route.OutboundProxy != nil && copyProfile.Route.OutboundProxy.Password != "" {
		copyProxy := *copyProfile.Route.OutboundProxy
		copyProxy.Password = maskedSecret(copyProxy.Password)
		copyProfile.Route = &domain.Route{ProxyJump: append([]string(nil), copyProfile.Route.ProxyJump...), OutboundProxy: &copyProxy}
	}
	return &copyProfile
}

func maskIdentityForDisplay(identity *domain.Identity) *domain.Identity {
	if identity == nil {
		return nil
	}
	copyIdentity := *identity
	copyIdentity.Methods = append([]domain.AuthMethod(nil), identity.Methods...)
	for i := range copyIdentity.Methods {
		if copyIdentity.Methods[i].Password != "" {
			copyIdentity.Methods[i].Password = maskedSecret(copyIdentity.Methods[i].Password)
		}
	}
	return &copyIdentity
}

func maskKeyForDisplay(key *domain.Key) *domain.Key {
	if key == nil {
		return nil
	}
	copyKey := *key
	if copyKey.PrivateKeyPEM != "" {
		copyKey.PrivateKeyPEM = maskedSecret(copyKey.PrivateKeyPEM)
	}
	if copyKey.Passphrase != "" {
		copyKey.Passphrase = maskedSecret(copyKey.Passphrase)
	}
	return &copyKey
}

func newTextInputModal(title, value string, multiline, secret bool, onSave func(*App, string)) *textInputModal {
	lines := strings.Split(value, "\n")
	if len(lines) == 0 {
		lines = []string{""}
	}
	cursorY := len(lines) - 1
	cursorX := len(lines[cursorY])
	return &textInputModal{
		title:     title,
		lines:     lines,
		cursorX:   cursorX,
		cursorY:   cursorY,
		multiline: multiline,
		secret:    secret,
		onSave:    onSave,
	}
}

func (a *App) drawModalBox(x, y, w, h int, title, footer string) {
	style := tcell.StyleDefault.Background(tcell.ColorBlack).Foreground(tcell.ColorWhite)
	border := tcell.StyleDefault.Background(tcell.ColorBlack).Foreground(tcell.ColorTeal)
	for row := 0; row < h; row++ {
		for col := 0; col < w; col++ {
			ch := ' '
			cellStyle := style
			if row == 0 || row == h-1 || col == 0 || col == w-1 {
				cellStyle = border
				switch {
				case (row == 0 || row == h-1) && (col == 0 || col == w-1):
					ch = '+'
				case row == 0 || row == h-1:
					ch = '-'
				default:
					ch = '|'
				}
			}
			a.screen.SetContent(x+col, y+row, ch, nil, cellStyle)
		}
	}
	drawText(a.screen, x+2, y, border, truncate(" "+title+" ", w-4))
	drawText(a.screen, x+2, y+h-1, border, truncate(" "+footer+" ", w-4))
}

func (a *App) modalRect(preferredW, preferredH int) (int, int, int, int) {
	w, h := a.screen.Size()
	boxW := clampInt(preferredW, 40, max(40, w-4))
	boxH := clampInt(preferredH, 8, max(8, h-2))
	if boxW > w-2 {
		boxW = max(20, w-2)
	}
	if boxH > h-2 {
		boxH = max(6, h-2)
	}
	return max(1, (w-boxW)/2), max(1, (h-boxH)/2), boxW, boxH
}

func (a *App) pushDiscardConfirm(title string, onConfirm func(*App)) {
	a.pushModal(modalState{
		kind: modalKindConfirm,
		confirm: &confirmModal{
			title: title,
			lines: []string{"Unsaved changes will be lost."},
			onConfirm: func(ctx context.Context, app *App) error {
				onConfirm(app)
				return nil
			},
		},
	})
}

func visibleFieldIndexes(form *formModal) []int {
	indexes := make([]int, 0, len(form.fields))
	for i, field := range form.fields {
		if field.visible == nil || field.visible(form) {
			indexes = append(indexes, i)
		}
	}
	return indexes
}

func filteredPickerOptions(modal *pickerModal) []pickerOption {
	query := strings.ToLower(strings.TrimSpace(modal.query))
	if query == "" {
		return modal.options
	}
	out := make([]pickerOption, 0, len(modal.options))
	for _, item := range modal.options {
		if strings.Contains(strings.ToLower(item.Label), query) || strings.Contains(strings.ToLower(item.ID), query) {
			out = append(out, item)
		}
	}
	return out
}

func formFieldDisplayValue(field *formField) string {
	switch field.kind {
	case fieldKindBool:
		if field.boolValue {
			return "true"
		}
		return "false"
	case fieldKindSingleRef:
		if field.refValue.ID == "" {
			return "(none)"
		}
		if field.refValue.Label != "" {
			return field.refValue.Label + " (" + field.refValue.ID + ")"
		}
		return field.refValue.ID
	case fieldKindRefList, fieldKindStringList, fieldKindMethodList:
		if len(field.items) == 0 {
			return "(empty)"
		}
		parts := make([]string, 0, len(field.items))
		for _, item := range field.items {
			parts = append(parts, itemDisplayValue(item))
		}
		return strings.Join(parts, ", ")
	default:
		if field.secret && field.value != "" {
			return maskedSecret(field.value)
		}
		if field.value == "" {
			if field.placeholder != "" {
				return field.placeholder
			}
			return "(empty)"
		}
		return strings.ReplaceAll(field.value, "\n", `\n`)
	}
}

func itemDisplayValue(item editorItem) string {
	switch {
	case item.Label != "":
		return item.Label
	case item.Value != "":
		return item.Value
	case item.ID != "":
		return item.ID
	default:
		return "(empty)"
	}
}

func cloneEditorItems(items []editorItem) []editorItem {
	out := make([]editorItem, len(items))
	copy(out, items)
	return out
}

func stringItems(values []string) []editorItem {
	out := make([]editorItem, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		out = append(out, editorItem{Value: value, Label: value})
	}
	return out
}

func itemIDs(items []editorItem) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if item.ID != "" {
			out = append(out, item.ID)
		}
	}
	return out
}

func itemValues(items []editorItem) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		value := strings.TrimSpace(item.Value)
		if value == "" && item.Label != "" && item.ID == "" {
			value = strings.TrimSpace(item.Label)
		}
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func itemMethods(items []editorItem) []domain.AuthMethod {
	out := make([]domain.AuthMethod, 0, len(items))
	for _, item := range items {
		if item.Method != nil {
			out = append(out, *item.Method)
		}
	}
	return out
}

func methodItems(ctx context.Context, app *App, methods []domain.AuthMethod) []editorItem {
	out := make([]editorItem, 0, len(methods))
	for _, method := range methods {
		copyMethod := method
		out = append(out, editorItem{
			Method: &copyMethod,
			Label:  authMethodLabel(ctx, app, method),
		})
	}
	return out
}

func authMethodLabel(ctx context.Context, app *App, method domain.AuthMethod) string {
	switch method.Type {
	case domain.AuthMethodPassword:
		return "password"
	case domain.AuthMethodKey:
		label := method.KeyID
		if app != nil && method.KeyID != "" {
			if item := app.refItem(ctx, domain.KindKey, method.KeyID); item.Label != "" {
				label = item.Label
			}
		}
		return "key: " + label
	case domain.AuthMethodAgent:
		label := "agent"
		if method.AgentSocket != "" {
			label += " (" + method.AgentSocket + ")"
		}
		if method.AgentForward {
			label += " forward"
		}
		return label
	default:
		return string(method.Type)
	}
}

func (a *App) refItems(ctx context.Context, kind domain.DocumentKind, ids []string) []editorItem {
	out := make([]editorItem, 0, len(ids))
	for _, id := range ids {
		if strings.TrimSpace(id) == "" {
			continue
		}
		out = append(out, a.refItem(ctx, kind, id))
	}
	return out
}

func (a *App) refItem(ctx context.Context, kind domain.DocumentKind, id string) editorItem {
	id = strings.TrimSpace(id)
	if id == "" {
		return editorItem{}
	}
	rec, err := a.catalog.ResolveDocument(ctx, kind, id)
	if err == nil {
		return editorItem{ID: rec.ID, Label: rec.Label, Value: rec.ID}
	}
	return editorItem{ID: id, Label: id, Value: id}
}

func formFieldByKey(form *formModal, key string) *formField {
	for _, field := range form.fields {
		if field.key == key {
			return field
		}
	}
	return nil
}

func formValue(form *formModal, key string) string {
	if field := formFieldByKey(form, key); field != nil {
		return field.value
	}
	return ""
}

func formBool(form *formModal, key string) bool {
	if field := formFieldByKey(form, key); field != nil {
		return field.boolValue
	}
	return false
}

func formItems(form *formModal, key string) []editorItem {
	if field := formFieldByKey(form, key); field != nil {
		return cloneEditorItems(field.items)
	}
	return nil
}

func formRefID(form *formModal, key string) string {
	if field := formFieldByKey(form, key); field != nil {
		return strings.TrimSpace(field.refValue.ID)
	}
	return ""
}

func parseOptionalStringPtr(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return &value
}

func parseOptionalRefPtr(field *formField) *string {
	if field == nil {
		return nil
	}
	value := strings.TrimSpace(field.refValue.ID)
	if value == "" {
		return nil
	}
	return &value
}

func parseOptionalIntPtr(value string) *int {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return nil
	}
	return &n
}

func parseOptionalInt(value string) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	n, _ := strconv.Atoi(value)
	return n
}

func parseRequiredInt(value, label string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("%s is required", label)
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be a number", label)
	}
	return n, nil
}

func intPtrString(value *int) string {
	if value == nil {
		return ""
	}
	return strconv.Itoa(*value)
}

func optionalIntString(value int) string {
	if value == 0 {
		return ""
	}
	return strconv.Itoa(value)
}

func stringPtrValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func knownHostsPolicyValue(cfg *domain.KnownHostsConfig) string {
	if cfg == nil {
		return ""
	}
	return string(cfg.Policy)
}

func knownHostsBackendValue(cfg *domain.KnownHostsConfig) string {
	if cfg == nil {
		return ""
	}
	return string(cfg.Backend)
}

func knownHostsPathValue(cfg *domain.KnownHostsConfig) string {
	if cfg == nil {
		return ""
	}
	return cfg.Path
}

func buildKnownHostsConfigFromForm(form *formModal) *domain.KnownHostsConfig {
	policy := strings.TrimSpace(formValue(form, "kh_policy"))
	backend := strings.TrimSpace(formValue(form, "kh_backend"))
	path := strings.TrimSpace(formValue(form, "kh_path"))
	if policy == "" && backend == "" && path == "" {
		return nil
	}
	cfg := &domain.KnownHostsConfig{
		Policy:  domain.KnownHostsPolicy(policy),
		Backend: domain.KnownHostsBackend(backend),
		Path:    path,
	}
	return cfg
}

func buildRouteFromForm(form *formModal) *domain.Route {
	jumps := itemValues(formItems(form, "jump"))
	proxyType := strings.TrimSpace(formValue(form, "proxy_type"))
	address := strings.TrimSpace(formValue(form, "proxy_address"))
	username := strings.TrimSpace(formValue(form, "proxy_username"))
	password := formValue(form, "proxy_password")
	if len(jumps) == 0 && proxyType == "" && address == "" && username == "" && password == "" {
		return nil
	}
	route := &domain.Route{
		ProxyJump: jumps,
	}
	if proxyType != "" || address != "" || username != "" || password != "" {
		route.OutboundProxy = &domain.OutboundProxy{
			Type:     domain.ProxyType(proxyType),
			Address:  address,
			Username: username,
			Password: password,
		}
	}
	return route
}

func routeProxyJumps(route *domain.Route) []string {
	if route == nil {
		return nil
	}
	return append([]string(nil), route.ProxyJump...)
}

func routeProxyType(route *domain.Route) string {
	if route == nil || route.OutboundProxy == nil {
		return ""
	}
	return string(route.OutboundProxy.Type)
}

func routeProxyAddress(route *domain.Route) string {
	if route == nil || route.OutboundProxy == nil {
		return ""
	}
	return route.OutboundProxy.Address
}

func routeProxyUsername(route *domain.Route) string {
	if route == nil || route.OutboundProxy == nil {
		return ""
	}
	return route.OutboundProxy.Username
}

func routeProxyPassword(route *domain.Route) string {
	if route == nil || route.OutboundProxy == nil {
		return ""
	}
	return route.OutboundProxy.Password
}

func visibleWhenProxyType(form *formModal) bool {
	return strings.TrimSpace(formValue(form, "proxy_type")) != ""
}

func visibleWhenKeyPrivate(form *formModal) bool {
	return formValue(form, "kind") == string(domain.KeyKindPrivateKey)
}

func visibleWhenKeyAgent(form *formModal) bool {
	return formValue(form, "kind") == string(domain.KeyKindAgent)
}

func visibleWhenForwardTarget(form *formModal) bool {
	value := formValue(form, "type")
	return value == string(domain.ForwardLocal) || value == string(domain.ForwardRemote)
}

func visibleWhenMethodPassword(form *formModal) bool {
	return formValue(form, "type") == string(domain.AuthMethodPassword)
}

func visibleWhenMethodKey(form *formModal) bool {
	return formValue(form, "type") == string(domain.AuthMethodKey)
}

func visibleWhenMethodAgent(form *formModal) bool {
	return formValue(form, "type") == string(domain.AuthMethodAgent)
}

func maskedSecret(value string) string {
	if value == "" {
		return ""
	}
	return fmt.Sprintf("<hidden:%d>", len(value))
}

func insertText(modal *textInputModal, value string) {
	if len(modal.lines) == 0 {
		modal.lines = []string{""}
	}
	for _, r := range value {
		if r == '\r' {
			continue
		}
		if r == '\n' {
			left := modal.lines[modal.cursorY][:modal.cursorX]
			right := modal.lines[modal.cursorY][modal.cursorX:]
			modal.lines[modal.cursorY] = left
			insertAt := modal.cursorY + 1
			modal.lines = append(modal.lines[:insertAt], append([]string{right}, modal.lines[insertAt:]...)...)
			modal.cursorY++
			modal.cursorX = 0
			continue
		}
		line := modal.lines[modal.cursorY]
		modal.lines[modal.cursorY] = line[:modal.cursorX] + string(r) + line[modal.cursorX:]
		modal.cursorX++
	}
}

func moveTextCursorLeft(modal *textInputModal) {
	if modal.cursorX > 0 {
		modal.cursorX--
		return
	}
	if modal.cursorY > 0 {
		modal.cursorY--
		modal.cursorX = len(modal.lines[modal.cursorY])
	}
}

func moveTextCursorRight(modal *textInputModal) {
	if modal.cursorX < len(modal.lines[modal.cursorY]) {
		modal.cursorX++
		return
	}
	if modal.cursorY < len(modal.lines)-1 {
		modal.cursorY++
		modal.cursorX = 0
	}
}

func deleteTextLeft(modal *textInputModal) {
	if modal.cursorX > 0 {
		line := modal.lines[modal.cursorY]
		modal.lines[modal.cursorY] = line[:modal.cursorX-1] + line[modal.cursorX:]
		modal.cursorX--
		return
	}
	if modal.cursorY == 0 {
		return
	}
	prev := modal.lines[modal.cursorY-1]
	current := modal.lines[modal.cursorY]
	modal.cursorX = len(prev)
	modal.lines[modal.cursorY-1] = prev + current
	modal.lines = append(modal.lines[:modal.cursorY], modal.lines[modal.cursorY+1:]...)
	modal.cursorY--
}

func deleteTextRight(modal *textInputModal) {
	line := modal.lines[modal.cursorY]
	if modal.cursorX < len(line) {
		modal.lines[modal.cursorY] = line[:modal.cursorX] + line[modal.cursorX+1:]
		return
	}
	if modal.cursorY >= len(modal.lines)-1 {
		return
	}
	modal.lines[modal.cursorY] += modal.lines[modal.cursorY+1]
	modal.lines = append(modal.lines[:modal.cursorY+1], modal.lines[modal.cursorY+2:]...)
}

func sortDocumentSummariesByLabel(items []pickerOption) {
	sort.Slice(items, func(i, j int) bool {
		if !strings.EqualFold(items[i].Label, items[j].Label) {
			return strings.ToLower(items[i].Label) < strings.ToLower(items[j].Label)
		}
		return items[i].ID < items[j].ID
	})
}
