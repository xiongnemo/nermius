package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/nermius/nermius/internal/domain"
	"github.com/nermius/nermius/internal/store"
)

type WriteKeyProvider func(context.Context) ([]byte, error)

type Catalog struct {
	store            *store.Store
	readKey          []byte
	writeKeyProvider WriteKeyProvider

	mu        sync.RWMutex
	loaded    bool
	documents map[string]store.DocumentRecord
	secrets   map[string]store.SecretRecord
}

var ErrAmbiguousReference = errors.New("reference is ambiguous")

type DocumentReference struct {
	Kind  domain.DocumentKind `json:"kind"`
	ID    string              `json:"id"`
	Label string              `json:"label"`
	Field string              `json:"field"`
}

func NewCatalog(st *store.Store, readKey []byte) *Catalog {
	return NewCatalogWithWriteKeyProvider(st, readKey, nil)
}

func NewCatalogWithWriteKeyProvider(st *store.Store, readKey []byte, provider WriteKeyProvider) *Catalog {
	return &Catalog{
		store:            st,
		readKey:          append([]byte(nil), readKey...),
		writeKeyProvider: provider,
	}
}

func (c *Catalog) SaveHost(ctx context.Context, host *domain.Host) error {
	if strings.TrimSpace(host.Hostname) == "" {
		return errors.New("hostname is required")
	}
	return c.withWriteKey(ctx, func(writeKey []byte) error {
		if err := c.ensureLoaded(ctx); err != nil {
			return err
		}
		if err := c.normalizeHost(ctx, writeKey, host); err != nil {
			return err
		}
		if err := c.normalizeRoute(ctx, writeKey, host.Route); err != nil {
			return err
		}
		return c.saveEntityWithKey(ctx, writeKey, domain.KindHost, host.ID, host.Label(), host, func(id string) { host.ID = id }, func(now time.Time) {
			touchCreatedUpdated(&host.CreatedAt, &host.UpdatedAt, now)
		})
	})
}

func (c *Catalog) SaveGroup(ctx context.Context, group *domain.Group) error {
	if strings.TrimSpace(group.Name) == "" {
		return errors.New("name is required")
	}
	return c.withWriteKey(ctx, func(writeKey []byte) error {
		if err := c.ensureLoaded(ctx); err != nil {
			return err
		}
		return c.saveEntityWithKey(ctx, writeKey, domain.KindGroup, group.ID, group.Label(), group, func(id string) { group.ID = id }, func(now time.Time) {
			touchCreatedUpdated(&group.CreatedAt, &group.UpdatedAt, now)
		})
	})
}

func (c *Catalog) SaveProfile(ctx context.Context, profile *domain.Profile) error {
	if strings.TrimSpace(profile.Name) == "" {
		return errors.New("name is required")
	}
	return c.withWriteKey(ctx, func(writeKey []byte) error {
		if err := c.ensureLoaded(ctx); err != nil {
			return err
		}
		if err := c.normalizeRoute(ctx, writeKey, profile.Route); err != nil {
			return err
		}
		return c.saveEntityWithKey(ctx, writeKey, domain.KindProfile, profile.ID, profile.Label(), profile, func(id string) { profile.ID = id }, func(now time.Time) {
			touchCreatedUpdated(&profile.CreatedAt, &profile.UpdatedAt, now)
		})
	})
}

func (c *Catalog) SaveIdentity(ctx context.Context, identity *domain.Identity) error {
	if strings.TrimSpace(identity.Name) == "" || strings.TrimSpace(identity.Username) == "" {
		return errors.New("identity requires both name and username")
	}
	if len(identity.Methods) == 0 {
		return errors.New("identity requires at least one auth method")
	}
	return c.withWriteKey(ctx, func(writeKey []byte) error {
		if err := c.ensureLoaded(ctx); err != nil {
			return err
		}
		if err := c.normalizeIdentity(ctx, writeKey, identity); err != nil {
			return err
		}
		return c.saveEntityWithKey(ctx, writeKey, domain.KindIdentity, identity.ID, identity.Label(), identity, func(id string) { identity.ID = id }, func(now time.Time) {
			touchCreatedUpdated(&identity.CreatedAt, &identity.UpdatedAt, now)
		})
	})
}

func (c *Catalog) SaveKey(ctx context.Context, key *domain.Key) error {
	if strings.TrimSpace(key.Name) == "" {
		return errors.New("name is required")
	}
	if key.Kind == "" {
		key.Kind = domain.KeyKindPrivateKey
	}
	return c.withWriteKey(ctx, func(writeKey []byte) error {
		if err := c.ensureLoaded(ctx); err != nil {
			return err
		}
		if err := c.normalizeKey(ctx, writeKey, key); err != nil {
			return err
		}
		return c.saveEntityWithKey(ctx, writeKey, domain.KindKey, key.ID, key.Label(), key, func(id string) { key.ID = id }, func(now time.Time) {
			touchCreatedUpdated(&key.CreatedAt, &key.UpdatedAt, now)
		})
	})
}

func (c *Catalog) SaveForward(ctx context.Context, forward *domain.Forward) error {
	if strings.TrimSpace(forward.Name) == "" {
		return errors.New("name is required")
	}
	if forward.Type == "" {
		return errors.New("forward type is required")
	}
	if forward.ListenPort == 0 {
		return errors.New("listen_port is required")
	}
	if forward.Type == domain.ForwardLocal || forward.Type == domain.ForwardRemote {
		if strings.TrimSpace(forward.TargetHost) == "" {
			return errors.New("target_host is required")
		}
		if forward.TargetPort == 0 {
			return errors.New("target_port is required")
		}
	}
	if strings.TrimSpace(forward.HostRef) != "" {
		hostID, err := c.ResolveDocumentID(ctx, domain.KindHost, forward.HostRef)
		if err != nil {
			return fmt.Errorf("host_ref: %w", err)
		}
		forward.HostRef = hostID
	}
	return c.withWriteKey(ctx, func(writeKey []byte) error {
		if err := c.ensureLoaded(ctx); err != nil {
			return err
		}
		return c.saveEntityWithKey(ctx, writeKey, domain.KindForward, forward.ID, forward.Label(), forward, func(id string) { forward.ID = id }, func(now time.Time) {
			touchCreatedUpdated(&forward.CreatedAt, &forward.UpdatedAt, now)
		})
	})
}

func (c *Catalog) SaveKnownHost(ctx context.Context, knownHost *domain.KnownHost) error {
	if len(knownHost.Hosts) == 0 {
		return errors.New("known host requires at least one host pattern")
	}
	if strings.TrimSpace(knownHost.PublicKey) == "" {
		return errors.New("known host requires public_key")
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(knownHost.PublicKey)))
	if err != nil {
		return err
	}
	knownHost.Algorithm = key.Type()
	knownHost.PublicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	label := knownHostDocumentLabel(knownHost.Hosts, knownHost.Algorithm)
	fingerprint, err := fingerprintAuthorizedKey(knownHost.PublicKey)
	if err != nil {
		return err
	}
	knownHost.FingerprintSHA256 = fingerprint
	if knownHost.Source == "" {
		knownHost.Source = string(domain.KnownHostsBackendVault)
	}
	return c.withWriteKey(ctx, func(writeKey []byte) error {
		if err := c.ensureLoaded(ctx); err != nil {
			return err
		}
		if existing := c.findDocumentByLabel(domain.KindKnownHost, label); existing != nil {
			knownHost.ID = existing.ID
		}
		return c.saveEntityWithKey(ctx, writeKey, domain.KindKnownHost, knownHost.ID, label, knownHost, func(id string) { knownHost.ID = id }, func(now time.Time) {
			touchCreatedUpdated(&knownHost.CreatedAt, &knownHost.UpdatedAt, now)
		})
	})
}

func (c *Catalog) SaveBackend(ctx context.Context, backend *domain.Backend) error {
	if strings.TrimSpace(backend.Name) == "" {
		return errors.New("name is required")
	}
	if backend.Type == "" {
		backend.Type = domain.BackendTypeTermix
	}
	if backend.Type != domain.BackendTypeTermix {
		return fmt.Errorf("unsupported backend type %q", backend.Type)
	}
	normalizedURL, err := normalizeBackendURL(backend.URL)
	if err != nil {
		return err
	}
	backend.URL = normalizedURL
	if strings.TrimSpace(backend.TargetProfileRef) != "" {
		profileID, err := c.ResolveDocumentID(ctx, domain.KindProfile, backend.TargetProfileRef)
		if err != nil {
			return fmt.Errorf("target_profile_ref: %w", err)
		}
		backend.TargetProfileRef = profileID
	}
	return c.withWriteKey(ctx, func(writeKey []byte) error {
		if err := c.ensureLoaded(ctx); err != nil {
			return err
		}
		if backend.Token != "" {
			id, err := c.putSecretWithKey(ctx, writeKey, domain.SecretKindBackendToken, backend.TokenSecretID, []byte(backend.Token))
			if err != nil {
				return err
			}
			backend.TokenSecretID = id
			backend.Token = ""
		}
		return c.saveEntityWithKey(ctx, writeKey, domain.KindBackend, backend.ID, backend.Label(), backend, func(id string) { backend.ID = id }, func(now time.Time) {
			touchCreatedUpdated(&backend.CreatedAt, &backend.UpdatedAt, now)
		})
	})
}

func (c *Catalog) SaveWorkspace(ctx context.Context, workspace *domain.Workspace) error {
	if workspace == nil {
		return errors.New("workspace is required")
	}
	if strings.TrimSpace(workspace.Name) == "" {
		return errors.New("name is required")
	}
	if workspace.Root == nil {
		workspace.Root = &domain.WorkspaceNode{Pane: &domain.WorkspacePane{Type: domain.WorkspacePaneEmpty}}
	}
	if countWorkspaceLeaves(workspace.Root) > 16 {
		return errors.New("workspace supports at most 16 panes")
	}
	if err := c.normalizeWorkspaceNode(ctx, workspace.Root); err != nil {
		return err
	}
	return c.withWriteKey(ctx, func(writeKey []byte) error {
		if err := c.ensureLoaded(ctx); err != nil {
			return err
		}
		return c.saveEntityWithKey(ctx, writeKey, domain.KindWorkspace, workspace.ID, workspace.Label(), workspace, func(id string) { workspace.ID = id }, func(now time.Time) {
			touchCreatedUpdated(&workspace.CreatedAt, &workspace.UpdatedAt, now)
		})
	})
}

func (c *Catalog) GetHost(ctx context.Context, id string) (*domain.Host, error) {
	var out domain.Host
	if err := c.loadEntity(ctx, id, domain.KindHost, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Catalog) GetGroup(ctx context.Context, id string) (*domain.Group, error) {
	var out domain.Group
	if err := c.loadEntity(ctx, id, domain.KindGroup, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Catalog) GetProfile(ctx context.Context, id string) (*domain.Profile, error) {
	var out domain.Profile
	if err := c.loadEntity(ctx, id, domain.KindProfile, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Catalog) GetIdentity(ctx context.Context, id string) (*domain.Identity, error) {
	var out domain.Identity
	if err := c.loadEntity(ctx, id, domain.KindIdentity, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Catalog) GetKey(ctx context.Context, id string) (*domain.Key, error) {
	var out domain.Key
	if err := c.loadEntity(ctx, id, domain.KindKey, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Catalog) GetForward(ctx context.Context, id string) (*domain.Forward, error) {
	var out domain.Forward
	if err := c.loadEntity(ctx, id, domain.KindForward, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Catalog) GetKnownHost(ctx context.Context, id string) (*domain.KnownHost, error) {
	var out domain.KnownHost
	if err := c.loadEntity(ctx, id, domain.KindKnownHost, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Catalog) GetBackend(ctx context.Context, id string) (*domain.Backend, error) {
	var out domain.Backend
	if err := c.loadEntity(ctx, id, domain.KindBackend, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Catalog) GetWorkspace(ctx context.Context, id string) (*domain.Workspace, error) {
	var out domain.Workspace
	if err := c.loadEntity(ctx, id, domain.KindWorkspace, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Catalog) Delete(ctx context.Context, id string) error {
	return c.withWriteKey(ctx, func(writeKey []byte) error {
		if err := c.ensureLoaded(ctx); err != nil {
			return err
		}
		if err := c.store.DeleteRecord(ctx, id); err != nil {
			return err
		}
		c.mu.Lock()
		delete(c.documents, id)
		delete(c.secrets, id)
		c.mu.Unlock()
		return nil
	})
}

func (c *Catalog) FindReferences(ctx context.Context, targetID string) ([]DocumentReference, error) {
	targetID = strings.TrimSpace(targetID)
	if targetID == "" {
		return nil, errors.New("target id is required")
	}
	if err := c.ensureLoaded(ctx); err != nil {
		return nil, err
	}
	refs := []DocumentReference{}

	hosts, err := c.listHosts(ctx)
	if err != nil {
		return nil, err
	}
	for _, host := range hosts {
		for _, id := range host.GroupIDs {
			if id == targetID {
				refs = append(refs, DocumentReference{Kind: domain.KindHost, ID: host.ID, Label: host.Label(), Field: "group_ids"})
			}
		}
		for _, id := range host.ProfileIDs {
			if id == targetID {
				refs = append(refs, DocumentReference{Kind: domain.KindHost, ID: host.ID, Label: host.Label(), Field: "profile_ids"})
			}
		}
		if host.IdentityRef != nil && *host.IdentityRef == targetID {
			refs = append(refs, DocumentReference{Kind: domain.KindHost, ID: host.ID, Label: host.Label(), Field: "identity_ref"})
		}
		if host.KeyRef != nil && *host.KeyRef == targetID {
			refs = append(refs, DocumentReference{Kind: domain.KindHost, ID: host.ID, Label: host.Label(), Field: "key_ref"})
		}
		for _, id := range host.ForwardIDs {
			if id == targetID {
				refs = append(refs, DocumentReference{Kind: domain.KindHost, ID: host.ID, Label: host.Label(), Field: "forward_ids"})
			}
		}
		if host.External != nil && host.External.BackendRef == targetID {
			refs = append(refs, DocumentReference{Kind: domain.KindHost, ID: host.ID, Label: host.Label(), Field: "external.backend_ref"})
		}
	}

	groups, err := c.listGroups(ctx)
	if err != nil {
		return nil, err
	}
	for _, group := range groups {
		if group.External != nil && group.External.BackendRef == targetID {
			refs = append(refs, DocumentReference{Kind: domain.KindGroup, ID: group.ID, Label: group.Label(), Field: "external.backend_ref"})
		}
	}

	profiles, err := c.listProfiles(ctx)
	if err != nil {
		return nil, err
	}
	for _, profile := range profiles {
		if profile.IdentityRef != nil && *profile.IdentityRef == targetID {
			refs = append(refs, DocumentReference{Kind: domain.KindProfile, ID: profile.ID, Label: profile.Label(), Field: "identity_ref"})
		}
		for _, id := range profile.ForwardIDs {
			if id == targetID {
				refs = append(refs, DocumentReference{Kind: domain.KindProfile, ID: profile.ID, Label: profile.Label(), Field: "forward_ids"})
			}
		}
	}

	identities, err := c.listIdentities(ctx)
	if err != nil {
		return nil, err
	}
	for _, identity := range identities {
		for _, method := range identity.Methods {
			if method.Type == domain.AuthMethodKey && method.KeyID == targetID {
				refs = append(refs, DocumentReference{Kind: domain.KindIdentity, ID: identity.ID, Label: identity.Label(), Field: "methods.key_id"})
			}
		}
		if identity.External != nil && identity.External.BackendRef == targetID {
			refs = append(refs, DocumentReference{Kind: domain.KindIdentity, ID: identity.ID, Label: identity.Label(), Field: "external.backend_ref"})
		}
	}

	keys, err := c.listKeys(ctx)
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		if key.External != nil && key.External.BackendRef == targetID {
			refs = append(refs, DocumentReference{Kind: domain.KindKey, ID: key.ID, Label: key.Label(), Field: "external.backend_ref"})
		}
	}

	forwards, err := c.listForwards(ctx)
	if err != nil {
		return nil, err
	}
	for _, forward := range forwards {
		if forward.HostRef == targetID {
			refs = append(refs, DocumentReference{Kind: domain.KindForward, ID: forward.ID, Label: forward.Label(), Field: "host_ref"})
		}
		if forward.External != nil && forward.External.BackendRef == targetID {
			refs = append(refs, DocumentReference{Kind: domain.KindForward, ID: forward.ID, Label: forward.Label(), Field: "external.backend_ref"})
		}
	}

	backends, err := c.listBackends(ctx)
	if err != nil {
		return nil, err
	}
	for _, backend := range backends {
		if backend.TargetProfileRef == targetID {
			refs = append(refs, DocumentReference{Kind: domain.KindBackend, ID: backend.ID, Label: backend.Label(), Field: "target_profile_ref"})
		}
	}

	workspaces, err := c.listWorkspaces(ctx)
	if err != nil {
		return nil, err
	}
	for _, workspace := range workspaces {
		for _, field := range workspaceHostRefFields(workspace.Root, targetID) {
			refs = append(refs, DocumentReference{Kind: domain.KindWorkspace, ID: workspace.ID, Label: workspace.Label(), Field: field})
		}
	}

	slices.SortFunc(refs, func(left, right DocumentReference) int {
		if left.Kind != right.Kind {
			return strings.Compare(string(left.Kind), string(right.Kind))
		}
		if !strings.EqualFold(left.Label, right.Label) {
			return strings.Compare(strings.ToLower(left.Label), strings.ToLower(right.Label))
		}
		if left.Field != right.Field {
			return strings.Compare(left.Field, right.Field)
		}
		return strings.Compare(left.ID, right.ID)
	})
	return refs, nil
}

func (c *Catalog) List(ctx context.Context, kind domain.DocumentKind) ([]store.DocumentSummary, error) {
	if err := c.ensureLoaded(ctx); err != nil {
		return nil, err
	}
	return c.listDocumentSummaries(kind), nil
}

func (c *Catalog) ListKnownHosts(ctx context.Context) ([]domain.KnownHost, error) {
	if err := c.ensureLoaded(ctx); err != nil {
		return nil, err
	}
	recs := c.documentRecordsByKind(domain.KindKnownHost)
	out := make([]domain.KnownHost, 0, len(recs))
	for _, rec := range recs {
		var knownHost domain.KnownHost
		if err := json.Unmarshal(rec.Body, &knownHost); err != nil {
			return nil, err
		}
		out = append(out, knownHost)
	}
	return out, nil
}

func (c *Catalog) ListBackends(ctx context.Context) ([]domain.Backend, error) {
	return c.listBackends(ctx)
}

func (c *Catalog) ListWorkspaces(ctx context.Context) ([]domain.Workspace, error) {
	return c.listWorkspaces(ctx)
}

func (c *Catalog) LoadKindByID(ctx context.Context, id string) (store.DocumentRecord, error) {
	if err := c.ensureLoaded(ctx); err != nil {
		return store.DocumentRecord{}, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	rec, ok := c.documents[id]
	if !ok {
		return store.DocumentRecord{}, sql.ErrNoRows
	}
	return cloneDocumentRecord(rec), nil
}

func (c *Catalog) ResolveDocument(ctx context.Context, kind domain.DocumentKind, spec string) (store.DocumentRecord, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return store.DocumentRecord{}, errors.New("reference is required")
	}
	if err := c.ensureLoaded(ctx); err != nil {
		return store.DocumentRecord{}, err
	}
	c.mu.RLock()
	if rec, ok := c.documents[spec]; ok {
		c.mu.RUnlock()
		if rec.Kind != string(kind) {
			return store.DocumentRecord{}, fmt.Errorf("%s is %s, not %s", spec, rec.Kind, kind)
		}
		return cloneDocumentRecord(rec), nil
	}
	c.mu.RUnlock()
	if rec := c.findDocumentByLabel(kind, spec); rec != nil {
		return cloneDocumentRecord(*rec), nil
	}
	items := c.listDocumentSummaries(kind)
	labelMatches := make([]store.DocumentSummary, 0, 2)
	for _, item := range items {
		if strings.EqualFold(item.Label, spec) {
			labelMatches = append(labelMatches, item)
		}
	}
	switch len(labelMatches) {
	case 1:
		return c.LoadKindByID(ctx, labelMatches[0].ID)
	case 0:
	default:
		parts := make([]string, 0, len(labelMatches))
		for _, match := range labelMatches {
			parts = append(parts, fmt.Sprintf("%s(%s)", match.Label, match.ID))
		}
		return store.DocumentRecord{}, fmt.Errorf("%w: %s", ErrAmbiguousReference, strings.Join(parts, ", "))
	}
	matches := make([]store.DocumentSummary, 0, 2)
	for _, item := range items {
		if strings.HasPrefix(strings.ToLower(item.ID), strings.ToLower(spec)) {
			matches = append(matches, item)
		}
	}
	switch len(matches) {
	case 0:
		return store.DocumentRecord{}, sql.ErrNoRows
	case 1:
		return c.LoadKindByID(ctx, matches[0].ID)
	default:
		parts := make([]string, 0, len(matches))
		for _, match := range matches {
			parts = append(parts, fmt.Sprintf("%s(%s)", match.Label, match.ID))
		}
		return store.DocumentRecord{}, fmt.Errorf("%w: %s", ErrAmbiguousReference, strings.Join(parts, ", "))
	}
}

func (c *Catalog) ResolveDocumentID(ctx context.Context, kind domain.DocumentKind, spec string) (string, error) {
	rec, err := c.ResolveDocument(ctx, kind, spec)
	if err != nil {
		return "", err
	}
	return rec.ID, nil
}

func (c *Catalog) FindHost(ctx context.Context, spec string) (*domain.Host, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, errors.New("host spec is required")
	}
	if rec, err := c.ResolveDocument(ctx, domain.KindHost, spec); err == nil {
		var host domain.Host
		if err := json.Unmarshal(rec.Body, &host); err != nil {
			return nil, err
		}
		return &host, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	hosts, err := c.listHosts(ctx)
	if err != nil {
		return nil, err
	}
	for _, host := range hosts {
		if strings.EqualFold(host.ID, spec) || strings.EqualFold(host.Title, spec) || strings.EqualFold(host.Hostname, spec) {
			h := host
			return &h, nil
		}
	}
	return nil, sql.ErrNoRows
}

func (c *Catalog) ResolveHost(ctx context.Context, spec string) (domain.ResolvedConfig, error) {
	host, err := c.FindHost(ctx, spec)
	if err != nil {
		return domain.ResolvedConfig{}, err
	}
	profiles := make([]domain.Profile, 0, len(host.ProfileIDs))
	for _, id := range host.ProfileIDs {
		profile, err := c.GetProfile(ctx, id)
		if err != nil {
			return domain.ResolvedConfig{}, fmt.Errorf("load profile %s: %w", id, err)
		}
		profiles = append(profiles, *profile)
	}
	var identity *domain.Identity
	identityRef := deref(host.IdentityRef)
	if identityRef == "" {
		for i := len(profiles) - 1; i >= 0; i-- {
			if profiles[i].IdentityRef != nil && *profiles[i].IdentityRef != "" {
				identityRef = *profiles[i].IdentityRef
				break
			}
		}
	}
	if identityRef != "" {
		identity, err = c.GetIdentity(ctx, identityRef)
		if err != nil {
			return domain.ResolvedConfig{}, fmt.Errorf("load identity %s: %w", identityRef, err)
		}
	}
	forwardMap := map[string]domain.Forward{}
	for _, id := range collectForwardIDs(*host, profiles) {
		forward, err := c.GetForward(ctx, id)
		if err != nil {
			continue
		}
		forwardMap[id] = *forward
	}
	resolved, err := domain.ResolveHost(domain.ResolveInputs{
		Host:     *host,
		Profiles: profiles,
		Identity: identity,
		Forwards: forwardMap,
	})
	if identity != nil && resolved.IdentityRef == identity.ID {
		resolved.Identity = identity
	}
	if err == nil || !errors.Is(err, domain.ErrHostNotConnectable) {
		return resolved, err
	}
	return resolved, nil
}

func (c *Catalog) PutSecret(ctx context.Context, kind domain.SecretKind, existingID string, plaintext []byte) (string, error) {
	if len(plaintext) == 0 {
		return existingID, nil
	}
	var out string
	err := c.withWriteKey(ctx, func(writeKey []byte) error {
		if err := c.ensureLoaded(ctx); err != nil {
			return err
		}
		id, err := c.putSecretWithKey(ctx, writeKey, kind, existingID, plaintext)
		if err != nil {
			return err
		}
		out = id
		return nil
	})
	return out, err
}

func (c *Catalog) OpenSecret(ctx context.Context, id string) ([]byte, error) {
	if err := c.ensureLoaded(ctx); err != nil {
		return nil, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	rec, ok := c.secrets[id]
	if !ok {
		return nil, sql.ErrNoRows
	}
	return append([]byte(nil), rec.Payload...), nil
}

func (c *Catalog) ensureLoaded(ctx context.Context) error {
	c.mu.RLock()
	if c.loaded {
		c.mu.RUnlock()
		return nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.loaded {
		return nil
	}
	records, err := c.store.ListRecords(ctx)
	if err != nil {
		return err
	}
	if len(records) > 0 && len(c.readKey) == 0 {
		return errors.New("catalog read key is unavailable")
	}
	documents := map[string]store.DocumentRecord{}
	secrets := map[string]store.SecretRecord{}
	for _, rec := range records {
		payload, err := openRecordPayload(c.readKey, rec)
		if err != nil {
			return err
		}
		switch payload.Class {
		case store.RecordClassDocument:
			documents[rec.ID] = store.DocumentRecord{
				ID:        rec.ID,
				Kind:      payload.Kind,
				Label:     payload.Label,
				Body:      append([]byte(nil), payload.Body...),
				CreatedAt: payload.CreatedAt,
				UpdatedAt: payload.UpdatedAt,
			}
		case store.RecordClassSecret:
			secrets[rec.ID] = store.SecretRecord{
				ID:        rec.ID,
				Kind:      payload.Kind,
				Payload:   append([]byte(nil), payload.Body...),
				CreatedAt: payload.CreatedAt,
				UpdatedAt: payload.UpdatedAt,
			}
		default:
			return fmt.Errorf("unsupported record class %q", payload.Class)
		}
	}
	c.documents = documents
	c.secrets = secrets
	c.loaded = true
	return nil
}

func (c *Catalog) saveEntityWithKey(ctx context.Context, writeKey []byte, kind domain.DocumentKind, id, label string, value any, setID func(string), touch func(time.Time)) error {
	if id == "" {
		setID(uuid.NewString())
	}
	if strings.TrimSpace(label) == "" {
		return errors.New("label is required")
	}
	if existing := c.findDocumentByLabel(kind, label); existing != nil && existing.ID != id && existing.ID != currentID(value) {
		return fmt.Errorf("%s name %q already exists", kind, label)
	}
	now := time.Now().UTC()
	touch(now)
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	entityID := currentID(value)
	rec := store.DocumentRecord{
		ID:        entityID,
		Kind:      string(kind),
		Label:     label,
		Body:      body,
		UpdatedAt: now,
	}
	if existing, ok := c.documents[entityID]; ok {
		rec.CreatedAt = existing.CreatedAt
	}
	return c.persistDocumentWithKey(ctx, writeKey, rec)
}

func (c *Catalog) loadEntity(ctx context.Context, id string, kind domain.DocumentKind, out any) error {
	rec, err := c.LoadKindByID(ctx, id)
	if err != nil {
		return err
	}
	if rec.Kind != string(kind) {
		return fmt.Errorf("document %s is %s, not %s", id, rec.Kind, kind)
	}
	return json.Unmarshal(rec.Body, out)
}

func (c *Catalog) normalizeIdentity(ctx context.Context, writeKey []byte, identity *domain.Identity) error {
	for i := range identity.Methods {
		method := &identity.Methods[i]
		if method.Type == domain.AuthMethodPassword && method.Password != "" {
			id, err := c.putSecretWithKey(ctx, writeKey, domain.SecretKindPassword, method.PasswordSecretID, []byte(method.Password))
			if err != nil {
				return err
			}
			method.PasswordSecretID = id
			method.Password = ""
		}
	}
	return nil
}

func (c *Catalog) normalizeHost(ctx context.Context, writeKey []byte, host *domain.Host) error {
	if host == nil || host.Password == "" {
		return nil
	}
	id, err := c.putSecretWithKey(ctx, writeKey, domain.SecretKindPassword, host.PasswordSecretID, []byte(host.Password))
	if err != nil {
		return err
	}
	host.PasswordSecretID = id
	host.Password = ""
	return nil
}

func (c *Catalog) normalizeKey(ctx context.Context, writeKey []byte, key *domain.Key) error {
	if key.PrivateKeyPEM != "" {
		id, err := c.putSecretWithKey(ctx, writeKey, domain.SecretKindPrivateKey, key.PrivateKeySecretID, []byte(key.PrivateKeyPEM))
		if err != nil {
			return err
		}
		key.PrivateKeySecretID = id
		key.PrivateKeyPEM = ""
	}
	if key.Passphrase != "" {
		id, err := c.putSecretWithKey(ctx, writeKey, domain.SecretKindPassphrase, key.PassphraseSecretID, []byte(key.Passphrase))
		if err != nil {
			return err
		}
		key.PassphraseSecretID = id
		key.Passphrase = ""
	}
	if key.Kind == domain.KeyKindPrivateKey && key.PrivateKeySecretID == "" && key.SourcePath == "" {
		return errors.New("private key requires either source_path or private_key_pem")
	}
	return nil
}

func (c *Catalog) normalizeRoute(ctx context.Context, writeKey []byte, route *domain.Route) error {
	if route == nil || route.OutboundProxy == nil || route.OutboundProxy.Password == "" {
		return nil
	}
	id, err := c.putSecretWithKey(ctx, writeKey, domain.SecretKindProxyAuth, route.OutboundProxy.PasswordSecretID, []byte(route.OutboundProxy.Password))
	if err != nil {
		return err
	}
	route.OutboundProxy.PasswordSecretID = id
	route.OutboundProxy.Password = ""
	return nil
}

func (c *Catalog) normalizeWorkspaceNode(ctx context.Context, node *domain.WorkspaceNode) error {
	if node == nil {
		return errors.New("workspace node is required")
	}
	switch {
	case node.Pane != nil && node.Split != nil:
		return errors.New("workspace node cannot be both pane and split")
	case node.Pane != nil:
		pane := node.Pane
		if pane.Type == "" {
			pane.Type = domain.WorkspacePaneEmpty
		}
		switch pane.Type {
		case domain.WorkspacePaneEmpty:
			pane.HostRef = ""
		case domain.WorkspacePaneSSH:
			hostID, err := c.ResolveDocumentID(ctx, domain.KindHost, pane.HostRef)
			if err != nil {
				return fmt.Errorf("workspace pane host_ref: %w", err)
			}
			pane.HostRef = hostID
		default:
			return fmt.Errorf("unsupported workspace pane type %q", pane.Type)
		}
		return nil
	case node.Split != nil:
		split := node.Split
		if split.Axis == "" {
			split.Axis = domain.WorkspaceSplitHorizontal
		}
		if split.Axis != domain.WorkspaceSplitHorizontal && split.Axis != domain.WorkspaceSplitVertical {
			return fmt.Errorf("unsupported workspace split axis %q", split.Axis)
		}
		if split.Ratio == 0 {
			split.Ratio = 0.5
		}
		if split.Ratio < 0.2 {
			split.Ratio = 0.2
		}
		if split.Ratio > 0.8 {
			split.Ratio = 0.8
		}
		if err := c.normalizeWorkspaceNode(ctx, split.First); err != nil {
			return fmt.Errorf("first: %w", err)
		}
		if err := c.normalizeWorkspaceNode(ctx, split.Second); err != nil {
			return fmt.Errorf("second: %w", err)
		}
		return nil
	default:
		node.Pane = &domain.WorkspacePane{Type: domain.WorkspacePaneEmpty}
		return nil
	}
}

func (c *Catalog) listHosts(ctx context.Context) ([]domain.Host, error) {
	if err := c.ensureLoaded(ctx); err != nil {
		return nil, err
	}
	recs := c.documentRecordsByKind(domain.KindHost)
	out := make([]domain.Host, 0, len(recs))
	for _, rec := range recs {
		var host domain.Host
		if err := json.Unmarshal(rec.Body, &host); err != nil {
			return nil, err
		}
		out = append(out, host)
	}
	return out, nil
}

func (c *Catalog) listGroups(ctx context.Context) ([]domain.Group, error) {
	if err := c.ensureLoaded(ctx); err != nil {
		return nil, err
	}
	recs := c.documentRecordsByKind(domain.KindGroup)
	out := make([]domain.Group, 0, len(recs))
	for _, rec := range recs {
		var group domain.Group
		if err := json.Unmarshal(rec.Body, &group); err != nil {
			return nil, err
		}
		out = append(out, group)
	}
	return out, nil
}

func (c *Catalog) listProfiles(ctx context.Context) ([]domain.Profile, error) {
	if err := c.ensureLoaded(ctx); err != nil {
		return nil, err
	}
	recs := c.documentRecordsByKind(domain.KindProfile)
	out := make([]domain.Profile, 0, len(recs))
	for _, rec := range recs {
		var profile domain.Profile
		if err := json.Unmarshal(rec.Body, &profile); err != nil {
			return nil, err
		}
		out = append(out, profile)
	}
	return out, nil
}

func (c *Catalog) listIdentities(ctx context.Context) ([]domain.Identity, error) {
	if err := c.ensureLoaded(ctx); err != nil {
		return nil, err
	}
	recs := c.documentRecordsByKind(domain.KindIdentity)
	out := make([]domain.Identity, 0, len(recs))
	for _, rec := range recs {
		var identity domain.Identity
		if err := json.Unmarshal(rec.Body, &identity); err != nil {
			return nil, err
		}
		out = append(out, identity)
	}
	return out, nil
}

func (c *Catalog) listKeys(ctx context.Context) ([]domain.Key, error) {
	if err := c.ensureLoaded(ctx); err != nil {
		return nil, err
	}
	recs := c.documentRecordsByKind(domain.KindKey)
	out := make([]domain.Key, 0, len(recs))
	for _, rec := range recs {
		var key domain.Key
		if err := json.Unmarshal(rec.Body, &key); err != nil {
			return nil, err
		}
		out = append(out, key)
	}
	return out, nil
}

func (c *Catalog) listForwards(ctx context.Context) ([]domain.Forward, error) {
	if err := c.ensureLoaded(ctx); err != nil {
		return nil, err
	}
	recs := c.documentRecordsByKind(domain.KindForward)
	out := make([]domain.Forward, 0, len(recs))
	for _, rec := range recs {
		var forward domain.Forward
		if err := json.Unmarshal(rec.Body, &forward); err != nil {
			return nil, err
		}
		out = append(out, forward)
	}
	return out, nil
}

func (c *Catalog) listBackends(ctx context.Context) ([]domain.Backend, error) {
	if err := c.ensureLoaded(ctx); err != nil {
		return nil, err
	}
	recs := c.documentRecordsByKind(domain.KindBackend)
	out := make([]domain.Backend, 0, len(recs))
	for _, rec := range recs {
		var backend domain.Backend
		if err := json.Unmarshal(rec.Body, &backend); err != nil {
			return nil, err
		}
		out = append(out, backend)
	}
	return out, nil
}

func (c *Catalog) listWorkspaces(ctx context.Context) ([]domain.Workspace, error) {
	if err := c.ensureLoaded(ctx); err != nil {
		return nil, err
	}
	recs := c.documentRecordsByKind(domain.KindWorkspace)
	out := make([]domain.Workspace, 0, len(recs))
	for _, rec := range recs {
		var workspace domain.Workspace
		if err := json.Unmarshal(rec.Body, &workspace); err != nil {
			return nil, err
		}
		out = append(out, workspace)
	}
	return out, nil
}

func (c *Catalog) documentRecordsByKind(kind domain.DocumentKind) []store.DocumentRecord {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]store.DocumentRecord, 0)
	for _, rec := range c.documents {
		if rec.Kind != string(kind) {
			continue
		}
		out = append(out, cloneDocumentRecord(rec))
	}
	slices.SortFunc(out, func(left, right store.DocumentRecord) int {
		if !strings.EqualFold(left.Label, right.Label) {
			return strings.Compare(strings.ToLower(left.Label), strings.ToLower(right.Label))
		}
		return strings.Compare(left.ID, right.ID)
	})
	return out
}

func (c *Catalog) listDocumentSummaries(kind domain.DocumentKind) []store.DocumentSummary {
	recs := c.documentRecordsByKind(kind)
	out := make([]store.DocumentSummary, 0, len(recs))
	for _, rec := range recs {
		out = append(out, store.DocumentSummary{
			ID:        rec.ID,
			Kind:      rec.Kind,
			Label:     rec.Label,
			UpdatedAt: rec.UpdatedAt,
		})
	}
	return out
}

func (c *Catalog) findDocumentByLabel(kind domain.DocumentKind, label string) *store.DocumentRecord {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, rec := range c.documents {
		if rec.Kind == string(kind) && rec.Label == label {
			copyRec := cloneDocumentRecord(rec)
			return &copyRec
		}
	}
	return nil
}

func countWorkspaceLeaves(node *domain.WorkspaceNode) int {
	if node == nil {
		return 0
	}
	if node.Split != nil {
		return countWorkspaceLeaves(node.Split.First) + countWorkspaceLeaves(node.Split.Second)
	}
	return 1
}

func workspaceHostRefFields(node *domain.WorkspaceNode, targetID string) []string {
	var fields []string
	collectWorkspaceHostRefFields(node, targetID, "root", &fields)
	return fields
}

func collectWorkspaceHostRefFields(node *domain.WorkspaceNode, targetID, path string, fields *[]string) {
	if node == nil {
		return
	}
	if node.Pane != nil && node.Pane.Type == domain.WorkspacePaneSSH && node.Pane.HostRef == targetID {
		*fields = append(*fields, path+".pane.host_ref")
		return
	}
	if node.Split == nil {
		return
	}
	collectWorkspaceHostRefFields(node.Split.First, targetID, path+".split.first", fields)
	collectWorkspaceHostRefFields(node.Split.Second, targetID, path+".split.second", fields)
}

func (c *Catalog) putSecretWithKey(ctx context.Context, writeKey []byte, kind domain.SecretKind, existingID string, plaintext []byte) (string, error) {
	if len(plaintext) == 0 {
		return existingID, nil
	}
	id := existingID
	if id == "" {
		id = uuid.NewString()
	}
	rec := store.SecretRecord{
		ID:      id,
		Kind:    string(kind),
		Payload: append([]byte(nil), plaintext...),
	}
	if existing, ok := c.secrets[id]; ok {
		rec.CreatedAt = existing.CreatedAt
	}
	if err := c.persistSecretWithKey(ctx, writeKey, rec); err != nil {
		return "", err
	}
	return id, nil
}

func (c *Catalog) persistDocumentWithKey(ctx context.Context, writeKey []byte, rec store.DocumentRecord) error {
	now := time.Now().UTC()
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = now
	}
	if rec.UpdatedAt.IsZero() {
		rec.UpdatedAt = now
	}
	encrypted, err := sealPayloadWithKey(writeKey, rec.ID, vaultRecordPayload{
		Class:     store.RecordClassDocument,
		Kind:      rec.Kind,
		Label:     rec.Label,
		Body:      rec.Body,
		CreatedAt: rec.CreatedAt,
		UpdatedAt: rec.UpdatedAt,
	})
	if err != nil {
		return err
	}
	if err := c.store.PutRecord(ctx, encrypted); err != nil {
		return err
	}
	c.mu.Lock()
	c.documents[rec.ID] = cloneDocumentRecord(rec)
	c.mu.Unlock()
	return nil
}

func (c *Catalog) persistSecretWithKey(ctx context.Context, writeKey []byte, rec store.SecretRecord) error {
	now := time.Now().UTC()
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = now
	}
	if rec.UpdatedAt.IsZero() {
		rec.UpdatedAt = now
	}
	encrypted, err := sealPayloadWithKey(writeKey, rec.ID, vaultRecordPayload{
		Class:     store.RecordClassSecret,
		Kind:      rec.Kind,
		Body:      rec.Payload,
		CreatedAt: rec.CreatedAt,
		UpdatedAt: rec.UpdatedAt,
	})
	if err != nil {
		return err
	}
	if err := c.store.PutRecord(ctx, encrypted); err != nil {
		return err
	}
	c.mu.Lock()
	c.secrets[rec.ID] = store.SecretRecord{
		ID:        rec.ID,
		Kind:      rec.Kind,
		Payload:   append([]byte(nil), rec.Payload...),
		CreatedAt: rec.CreatedAt,
		UpdatedAt: rec.UpdatedAt,
	}
	c.mu.Unlock()
	return nil
}

func (c *Catalog) withWriteKey(ctx context.Context, fn func([]byte) error) error {
	writeKey, err := c.resolveWriteKey(ctx)
	if err != nil {
		return err
	}
	defer zeroBytes(writeKey)
	return fn(writeKey)
}

func (c *Catalog) resolveWriteKey(ctx context.Context) ([]byte, error) {
	if c.writeKeyProvider != nil {
		return c.writeKeyProvider(ctx)
	}
	if len(c.readKey) == 0 {
		return nil, errors.New("catalog write key is unavailable")
	}
	return append([]byte(nil), c.readKey...), nil
}

func cloneDocumentRecord(in store.DocumentRecord) store.DocumentRecord {
	out := in
	out.Body = append([]byte(nil), in.Body...)
	return out
}

func collectForwardIDs(host domain.Host, profiles []domain.Profile) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(host.ForwardIDs)+len(profiles))
	for _, profile := range profiles {
		for _, id := range profile.ForwardIDs {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	for _, id := range host.ForwardIDs {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func deref(in *string) string {
	if in == nil {
		return ""
	}
	return *in
}

func touchCreatedUpdated(createdAt, updatedAt *time.Time, now time.Time) {
	if createdAt.IsZero() {
		*createdAt = now
	}
	*updatedAt = now
}

func currentID(v any) string {
	switch value := v.(type) {
	case *domain.Host:
		return value.ID
	case *domain.Group:
		return value.ID
	case *domain.Profile:
		return value.ID
	case *domain.Identity:
		return value.ID
	case *domain.Key:
		return value.ID
	case *domain.Forward:
		return value.ID
	case *domain.KnownHost:
		return value.ID
	case *domain.Backend:
		return value.ID
	case *domain.Workspace:
		return value.ID
	default:
		return ""
	}
}

func normalizeBackendURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("url is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("backend url must use http or https: %s", raw)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("backend url must include a host: %s", raw)
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func knownHostDocumentLabel(hosts []string, algorithm string) string {
	items := make([]string, 0, len(hosts))
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		items = append(items, host)
	}
	slices.Sort(items)
	return strings.Join(items, ",") + "|" + strings.TrimSpace(algorithm)
}

func fingerprintAuthorizedKey(publicKey string) (string, error) {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(publicKey)))
	if err != nil {
		return "", err
	}
	return ssh.FingerprintSHA256(key), nil
}
