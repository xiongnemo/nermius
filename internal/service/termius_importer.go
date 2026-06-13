package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/nermius/nermius/internal/domain"
	"github.com/nermius/nermius/internal/termius"
)

type TermiusConflictMode string

const (
	TermiusConflictSkip      TermiusConflictMode = "skip"
	TermiusConflictRename    TermiusConflictMode = "rename"
	TermiusConflictOverwrite TermiusConflictMode = "overwrite"
)

type TermiusImportOptions struct {
	DryRun   bool
	Conflict TermiusConflictMode
}

type TermiusImportReport struct {
	Hosts      int      `json:"hosts"`
	Groups     int      `json:"groups,omitempty"`
	Identities int      `json:"identities"`
	Keys       int      `json:"keys"`
	Skipped    int      `json:"skipped"`
	DryRun     bool     `json:"dry_run,omitempty"`
	Errors     []string `json:"errors,omitempty"`
}

type TermiusImporter struct {
	catalog *Catalog
}

func NewTermiusImporter(catalog *Catalog) *TermiusImporter {
	return &TermiusImporter{catalog: catalog}
}

func (i *TermiusImporter) Import(ctx context.Context, bundle termius.Bundle, opts TermiusImportOptions) (TermiusImportReport, error) {
	if opts.Conflict == "" {
		opts.Conflict = TermiusConflictRename
	}
	report := TermiusImportReport{DryRun: opts.DryRun}
	groupIDsByName := map[string]string{}
	keyIDs := map[string]string{}
	keyIDsByName := map[string]string{}
	identityIDsByUsername := map[string]string{}

	for _, item := range bundle.Normalized.Groups {
		groupID, skipped, err := i.importGroup(ctx, item, opts)
		if err != nil {
			return report, err
		}
		if skipped {
			report.Skipped++
			continue
		}
		report.Groups++
		if item.Name != "" {
			groupIDsByName[strings.ToLower(item.Name)] = groupID
		}
	}

	for _, item := range bundle.Normalized.Keys {
		keyID, skipped, err := i.importKey(ctx, item, opts)
		if err != nil {
			return report, err
		}
		if skipped {
			report.Skipped++
			continue
		}
		report.Keys++
		if item.TermiusID != "" {
			keyIDs[item.TermiusID] = keyID
		}
		if item.Name != "" {
			keyIDsByName[strings.ToLower(item.Name)] = keyID
		}
	}

	for _, item := range bundle.Normalized.Identities {
		identityID, skipped, err := i.importIdentity(ctx, item, opts)
		if err != nil {
			return report, err
		}
		if skipped {
			report.Skipped++
			continue
		}
		report.Identities++
		if item.Username != "" {
			identityIDsByUsername[strings.ToLower(item.Username)] = identityID
		}
	}

	for _, item := range bundle.Normalized.Hosts {
		skipped, err := i.importHost(ctx, item, opts, groupIDsByName, keyIDs, keyIDsByName, identityIDsByUsername)
		if err != nil {
			return report, err
		}
		if skipped {
			report.Skipped++
			continue
		}
		report.Hosts++
	}

	return report, nil
}

func (i *TermiusImporter) importGroup(ctx context.Context, item termius.Group, opts TermiusImportOptions) (string, bool, error) {
	name := strings.TrimSpace(item.Name)
	if name == "" {
		return "", true, nil
	}
	name, existingID, skipped, err := i.resolveImportLabel(ctx, domain.KindGroup, name, opts.Conflict)
	if err != nil || skipped {
		return "", skipped, err
	}
	group := domain.Group{
		ID:   existingID,
		Name: name,
	}
	if opts.DryRun {
		return dryRunID(domain.KindGroup, name), false, nil
	}
	if err := i.catalog.SaveGroup(ctx, &group); err != nil {
		return "", false, err
	}
	return group.ID, false, nil
}

func (i *TermiusImporter) importKey(ctx context.Context, item termius.Key, opts TermiusImportOptions) (string, bool, error) {
	if strings.TrimSpace(item.Name) == "" || strings.TrimSpace(item.PrivateKeyPEM) == "" {
		return "", true, nil
	}
	name, existingID, skipped, err := i.resolveImportLabel(ctx, domain.KindKey, item.Name, opts.Conflict)
	if err != nil || skipped {
		return "", skipped, err
	}
	key := domain.Key{
		ID:            existingID,
		Name:          name,
		Kind:          domain.KeyKindPrivateKey,
		PrivateKeyPEM: item.PrivateKeyPEM,
		Passphrase:    item.Passphrase,
	}
	if opts.DryRun {
		return dryRunID(domain.KindKey, name), false, nil
	}
	if err := i.catalog.SaveKey(ctx, &key); err != nil {
		return "", false, err
	}
	return key.ID, false, nil
}

func (i *TermiusImporter) importIdentity(ctx context.Context, item termius.Identity, opts TermiusImportOptions) (string, bool, error) {
	username := strings.TrimSpace(item.Username)
	if username == "" {
		return "", true, nil
	}
	name := strings.TrimSpace(item.Name)
	if name == "" {
		name = username
	}
	name, existingID, skipped, err := i.resolveImportLabel(ctx, domain.KindIdentity, name, opts.Conflict)
	if err != nil || skipped {
		return "", skipped, err
	}
	methods := []domain.AuthMethod{}
	if item.Password != "" {
		methods = append(methods, domain.AuthMethod{Type: domain.AuthMethodPassword, Password: item.Password})
	}
	if len(methods) == 0 {
		methods = append(methods, domain.AuthMethod{Type: domain.AuthMethodAgent})
	}
	identity := domain.Identity{
		ID:       existingID,
		Name:     name,
		Username: username,
		Methods:  methods,
	}
	if opts.DryRun {
		return dryRunID(domain.KindIdentity, name), false, nil
	}
	if err := i.catalog.SaveIdentity(ctx, &identity); err != nil {
		return "", false, err
	}
	return identity.ID, false, nil
}

func (i *TermiusImporter) importHost(ctx context.Context, item termius.Host, opts TermiusImportOptions, groupIDsByName map[string]string, keyIDs map[string]string, keyIDsByName map[string]string, identityIDsByUsername map[string]string) (bool, error) {
	hostname := strings.TrimSpace(item.Host)
	if hostname == "" {
		return true, nil
	}
	label := strings.TrimSpace(item.Label)
	if label == "" {
		label = hostname
	}
	label, existingID, skipped, err := i.resolveImportLabel(ctx, domain.KindHost, label, opts.Conflict)
	if err != nil || skipped {
		return skipped, err
	}
	host := domain.Host{
		ID:       existingID,
		Title:    label,
		Hostname: hostname,
		Password: item.Password,
	}
	if item.Port > 0 {
		host.Port = intPtr(item.Port)
	}
	for _, groupName := range item.GroupNames {
		if groupID := groupIDsByName[strings.ToLower(strings.TrimSpace(groupName))]; groupID != "" {
			host.GroupIDs = append(host.GroupIDs, groupID)
		}
	}
	if username := strings.TrimSpace(item.Username); username != "" {
		host.Username = stringPtr(username)
		if identityID := identityIDsByUsername[strings.ToLower(username)]; identityID != "" {
			host.IdentityRef = &identityID
		}
	}
	if item.KeyID != "" {
		if keyID := keyIDs[item.KeyID]; keyID != "" {
			host.KeyRef = &keyID
		}
	}
	if host.KeyRef == nil && item.KeyName != "" {
		if keyID := keyIDsByName[strings.ToLower(item.KeyName)]; keyID != "" {
			host.KeyRef = &keyID
		}
	}
	if opts.DryRun {
		return false, nil
	}
	return false, i.catalog.SaveHost(ctx, &host)
}

func (i *TermiusImporter) resolveImportLabel(ctx context.Context, kind domain.DocumentKind, label string, mode TermiusConflictMode) (string, string, bool, error) {
	label = strings.TrimSpace(label)
	if label == "" {
		return "", "", false, errors.New("label is required")
	}
	existingID, exists, err := i.existingID(ctx, kind, label)
	if err != nil {
		return "", "", false, err
	}
	if !exists {
		return label, "", false, nil
	}
	switch mode {
	case TermiusConflictSkip:
		return "", "", true, nil
	case TermiusConflictOverwrite:
		return label, existingID, false, nil
	case TermiusConflictRename:
		for n := 1; ; n++ {
			candidate := label + " (termius)"
			if n > 1 {
				candidate = label + " (termius " + strconv.Itoa(n) + ")"
			}
			if _, exists, err := i.existingID(ctx, kind, candidate); err != nil {
				return "", "", false, err
			} else if !exists {
				return candidate, "", false, nil
			}
		}
	default:
		return "", "", false, fmt.Errorf("unsupported Termius conflict mode %q", mode)
	}
}

func (i *TermiusImporter) existingID(ctx context.Context, kind domain.DocumentKind, label string) (string, bool, error) {
	rec, err := i.catalog.ResolveDocument(ctx, kind, label)
	if err == nil {
		return rec.ID, true, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return "", false, err
}

func dryRunID(kind domain.DocumentKind, label string) string {
	return "dry-run:" + string(kind) + ":" + label
}

func stringPtr(value string) *string {
	return &value
}
