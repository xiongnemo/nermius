package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/nermius/nermius/internal/domain"
	"github.com/nermius/nermius/internal/secret"
	"github.com/nermius/nermius/internal/store"
)

type Catalog struct {
	store     *store.Store
	masterKey []byte
}

var ErrAmbiguousReference = errors.New("reference is ambiguous")

type DocumentReference struct {
	Kind  domain.DocumentKind `json:"kind"`
	ID    string              `json:"id"`
	Label string              `json:"label"`
	Field string              `json:"field"`
}

func NewCatalog(st *store.Store, masterKey []byte) *Catalog {
	return &Catalog{store: st, masterKey: masterKey}
}

func (c *Catalog) SaveHost(ctx context.Context, host *domain.Host) error {
	if strings.TrimSpace(host.Hostname) == "" {
		return errors.New("hostname is required")
	}
	if err := c.normalizeHost(ctx, host); err != nil {
		return err
	}
	if err := c.normalizeRoute(ctx, host.Route); err != nil {
		return err
	}
	return c.saveEntity(ctx, domain.KindHost, host.ID, host.Label(), host, func(id string) { host.ID = id }, func(now time.Time) {
		touchCreatedUpdated(&host.CreatedAt, &host.UpdatedAt, now)
	})
}

func (c *Catalog) SaveGroup(ctx context.Context, group *domain.Group) error {
	if strings.TrimSpace(group.Name) == "" {
		return errors.New("name is required")
	}
	return c.saveEntity(ctx, domain.KindGroup, group.ID, group.Label(), group, func(id string) { group.ID = id }, func(now time.Time) {
		touchCreatedUpdated(&group.CreatedAt, &group.UpdatedAt, now)
	})
}

func (c *Catalog) SaveProfile(ctx context.Context, profile *domain.Profile) error {
	if strings.TrimSpace(profile.Name) == "" {
		return errors.New("name is required")
	}
	if err := c.normalizeRoute(ctx, profile.Route); err != nil {
		return err
	}
	return c.saveEntity(ctx, domain.KindProfile, profile.ID, profile.Label(), profile, func(id string) { profile.ID = id }, func(now time.Time) {
		touchCreatedUpdated(&profile.CreatedAt, &profile.UpdatedAt, now)
	})
}

func (c *Catalog) SaveIdentity(ctx context.Context, identity *domain.Identity) error {
	if strings.TrimSpace(identity.Name) == "" || strings.TrimSpace(identity.Username) == "" {
		return errors.New("identity requires both name and username")
	}
	if len(identity.Methods) == 0 {
		return errors.New("identity requires at least one auth method")
	}
	if err := c.normalizeIdentity(ctx, identity); err != nil {
		return err
	}
	return c.saveEntity(ctx, domain.KindIdentity, identity.ID, identity.Label(), identity, func(id string) { identity.ID = id }, func(now time.Time) {
		touchCreatedUpdated(&identity.CreatedAt, &identity.UpdatedAt, now)
	})
}

func (c *Catalog) SaveKey(ctx context.Context, key *domain.Key) error {
	if strings.TrimSpace(key.Name) == "" {
		return errors.New("name is required")
	}
	if key.Kind == "" {
		key.Kind = domain.KeyKindPrivateKey
	}
	if err := c.normalizeKey(ctx, key); err != nil {
		return err
	}
	return c.saveEntity(ctx, domain.KindKey, key.ID, key.Label(), key, func(id string) { key.ID = id }, func(now time.Time) {
		touchCreatedUpdated(&key.CreatedAt, &key.UpdatedAt, now)
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
	return c.saveEntity(ctx, domain.KindForward, forward.ID, forward.Label(), forward, func(id string) { forward.ID = id }, func(now time.Time) {
		touchCreatedUpdated(&forward.CreatedAt, &forward.UpdatedAt, now)
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
	if existing, err := c.store.FindDocumentByLabel(ctx, string(domain.KindKnownHost), label); err == nil {
		knownHost.ID = existing.ID
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if knownHost.Source == "" {
		knownHost.Source = string(domain.KnownHostsBackendVault)
	}
	fingerprint, err := fingerprintAuthorizedKey(knownHost.PublicKey)
	if err != nil {
		return err
	}
	knownHost.FingerprintSHA256 = fingerprint
	return c.saveEntity(ctx, domain.KindKnownHost, knownHost.ID, label, knownHost, func(id string) { knownHost.ID = id }, func(now time.Time) {
		touchCreatedUpdated(&knownHost.CreatedAt, &knownHost.UpdatedAt, now)
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

func (c *Catalog) Delete(ctx context.Context, id string) error {
	return c.store.DeleteDocument(ctx, id)
}

func (c *Catalog) FindReferences(ctx context.Context, targetID string) ([]DocumentReference, error) {
	targetID = strings.TrimSpace(targetID)
	if targetID == "" {
		return nil, errors.New("target id is required")
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
	}

	profileRecs, err := c.store.AllDocuments(ctx, string(domain.KindProfile))
	if err != nil {
		return nil, err
	}
	for _, rec := range profileRecs {
		var profile domain.Profile
		if err := json.Unmarshal(rec.Body, &profile); err != nil {
			return nil, err
		}
		if profile.IdentityRef != nil && *profile.IdentityRef == targetID {
			refs = append(refs, DocumentReference{Kind: domain.KindProfile, ID: profile.ID, Label: profile.Label(), Field: "identity_ref"})
		}
		for _, id := range profile.ForwardIDs {
			if id == targetID {
				refs = append(refs, DocumentReference{Kind: domain.KindProfile, ID: profile.ID, Label: profile.Label(), Field: "forward_ids"})
			}
		}
	}

	identityRecs, err := c.store.AllDocuments(ctx, string(domain.KindIdentity))
	if err != nil {
		return nil, err
	}
	for _, rec := range identityRecs {
		var identity domain.Identity
		if err := json.Unmarshal(rec.Body, &identity); err != nil {
			return nil, err
		}
		for _, method := range identity.Methods {
			if method.Type == domain.AuthMethodKey && method.KeyID == targetID {
				refs = append(refs, DocumentReference{Kind: domain.KindIdentity, ID: identity.ID, Label: identity.Label(), Field: "methods.key_id"})
			}
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
	return c.store.ListDocuments(ctx, string(kind))
}

func (c *Catalog) ListKnownHosts(ctx context.Context) ([]domain.KnownHost, error) {
	recs, err := c.store.AllDocuments(ctx, string(domain.KindKnownHost))
	if err != nil {
		return nil, err
	}
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

func (c *Catalog) LoadKindByID(ctx context.Context, id string) (store.DocumentRecord, error) {
	return c.store.GetDocument(ctx, id)
}

func (c *Catalog) ResolveDocument(ctx context.Context, kind domain.DocumentKind, spec string) (store.DocumentRecord, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return store.DocumentRecord{}, errors.New("reference is required")
	}
	rec, err := c.store.GetDocument(ctx, spec)
	if err == nil {
		if rec.Kind != string(kind) {
			return store.DocumentRecord{}, fmt.Errorf("%s is %s, not %s", spec, rec.Kind, kind)
		}
		return rec, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return store.DocumentRecord{}, err
	}
	if rec, err := c.store.FindDocumentByLabel(ctx, string(kind), spec); err == nil {
		return rec, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return store.DocumentRecord{}, err
	}
	items, err := c.store.ListDocuments(ctx, string(kind))
	if err != nil {
		return store.DocumentRecord{}, err
	}
	labelMatches := make([]store.DocumentSummary, 0, 2)
	for _, item := range items {
		if strings.EqualFold(item.Label, spec) {
			labelMatches = append(labelMatches, item)
		}
	}
	switch len(labelMatches) {
	case 1:
		return c.store.GetDocument(ctx, labelMatches[0].ID)
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
		return c.store.GetDocument(ctx, matches[0].ID)
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
	id := existingID
	if id == "" {
		id = uuid.NewString()
	}
	env, err := secret.SealEnvelope(c.masterKey, plaintext)
	if err != nil {
		return "", err
	}
	err = c.store.PutSecret(ctx, store.SecretRecord{
		ID:                   id,
		Kind:                 string(kind),
		WrappedKeyNonce:      env.WrappedKeyNonce,
		WrappedKeyCiphertext: env.WrappedKeyCiphertext,
		PayloadNonce:         env.PayloadNonce,
		PayloadCiphertext:    env.PayloadCiphertext,
	})
	return id, err
}

func (c *Catalog) OpenSecret(ctx context.Context, id string) ([]byte, error) {
	rec, err := c.store.GetSecret(ctx, id)
	if err != nil {
		return nil, err
	}
	return secret.OpenEnvelope(c.masterKey, secret.EnvelopeSecret{
		WrappedKeyNonce:      rec.WrappedKeyNonce,
		WrappedKeyCiphertext: rec.WrappedKeyCiphertext,
		PayloadNonce:         rec.PayloadNonce,
		PayloadCiphertext:    rec.PayloadCiphertext,
	})
}

func (c *Catalog) saveEntity(ctx context.Context, kind domain.DocumentKind, id, label string, value any, setID func(string), touch func(time.Time)) error {
	if id == "" {
		setID(uuid.NewString())
	}
	if strings.TrimSpace(label) == "" {
		return errors.New("label is required")
	}
	if existing, err := c.store.FindDocumentByLabel(ctx, string(kind), label); err == nil && existing.ID != id && existing.ID != currentID(value) {
		return fmt.Errorf("%s name %q already exists", kind, label)
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	now := time.Now().UTC()
	touch(now)
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	entityID := currentID(value)
	return c.store.PutDocument(ctx, store.DocumentRecord{
		ID:        entityID,
		Kind:      string(kind),
		Label:     label,
		Body:      body,
		UpdatedAt: now,
	})
}

func (c *Catalog) loadEntity(ctx context.Context, id string, kind domain.DocumentKind, out any) error {
	rec, err := c.store.GetDocument(ctx, id)
	if err != nil {
		return err
	}
	if rec.Kind != string(kind) {
		return fmt.Errorf("document %s is %s, not %s", id, rec.Kind, kind)
	}
	return json.Unmarshal(rec.Body, out)
}

func (c *Catalog) normalizeIdentity(ctx context.Context, identity *domain.Identity) error {
	for i := range identity.Methods {
		method := &identity.Methods[i]
		if method.Type == domain.AuthMethodPassword && method.Password != "" {
			id, err := c.PutSecret(ctx, domain.SecretKindPassword, method.PasswordSecretID, []byte(method.Password))
			if err != nil {
				return err
			}
			method.PasswordSecretID = id
			method.Password = ""
		}
	}
	return nil
}

func (c *Catalog) normalizeHost(ctx context.Context, host *domain.Host) error {
	if host == nil || host.Password == "" {
		return nil
	}
	id, err := c.PutSecret(ctx, domain.SecretKindPassword, host.PasswordSecretID, []byte(host.Password))
	if err != nil {
		return err
	}
	host.PasswordSecretID = id
	host.Password = ""
	return nil
}

func (c *Catalog) normalizeKey(ctx context.Context, key *domain.Key) error {
	if key.PrivateKeyPEM != "" {
		id, err := c.PutSecret(ctx, domain.SecretKindPrivateKey, key.PrivateKeySecretID, []byte(key.PrivateKeyPEM))
		if err != nil {
			return err
		}
		key.PrivateKeySecretID = id
		key.PrivateKeyPEM = ""
	}
	if key.Passphrase != "" {
		id, err := c.PutSecret(ctx, domain.SecretKindPassphrase, key.PassphraseSecretID, []byte(key.Passphrase))
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

func (c *Catalog) normalizeRoute(ctx context.Context, route *domain.Route) error {
	if route == nil || route.OutboundProxy == nil || route.OutboundProxy.Password == "" {
		return nil
	}
	id, err := c.PutSecret(ctx, domain.SecretKindProxyAuth, route.OutboundProxy.PasswordSecretID, []byte(route.OutboundProxy.Password))
	if err != nil {
		return err
	}
	route.OutboundProxy.PasswordSecretID = id
	route.OutboundProxy.Password = ""
	return nil
}

func (c *Catalog) listHosts(ctx context.Context) ([]domain.Host, error) {
	recs, err := c.store.AllDocuments(ctx, string(domain.KindHost))
	if err != nil {
		return nil, err
	}
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
	default:
		return ""
	}
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
