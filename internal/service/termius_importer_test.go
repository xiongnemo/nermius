package service

import (
	"context"
	"testing"

	"github.com/nermius/nermius/internal/domain"
	"github.com/nermius/nermius/internal/termius"
)

func TestTermiusImporterStoresSecretsAndLinksCredentials(t *testing.T) {
	catalog, cleanup := newTestCatalog(t)
	defer cleanup()
	ctx := context.Background()
	bundle := termius.Bundle{
		Source:        termius.SourceName,
		FormatVersion: termius.BundleFormatVersion,
		Normalized: termius.Normalized{
			Groups: []termius.Group{{
				Name: "prod-group",
			}},
			Keys: []termius.Key{{
				TermiusID:     "key-1",
				Name:          "deploy",
				PrivateKeyPEM: "PRIVATE",
				Passphrase:    "phrase",
			}},
			Identities: []termius.Identity{{
				Name:     "ops",
				Username: "root",
				Password: "identity-password",
			}},
			Hosts: []termius.Host{{
				Label:      "prod",
				Host:       "prod.example.com",
				Port:       2222,
				Username:   "root",
				Password:   "host-password",
				KeyID:      "key-1",
				GroupNames: []string{"prod-group"},
			}},
		},
	}

	report, err := NewTermiusImporter(catalog).Import(ctx, bundle, TermiusImportOptions{Conflict: TermiusConflictRename})
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}
	if report.Groups != 1 || report.Keys != 1 || report.Identities != 1 || report.Hosts != 1 || report.Skipped != 0 {
		t.Fatalf("unexpected report: %+v", report)
	}

	keyRec, err := catalog.ResolveDocument(ctx, domain.KindKey, "deploy")
	if err != nil {
		t.Fatalf("ResolveDocument key failed: %v", err)
	}
	key, err := catalog.GetKey(ctx, keyRec.ID)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}
	keySecret, err := catalog.OpenSecret(ctx, key.PrivateKeySecretID)
	if err != nil {
		t.Fatalf("OpenSecret key failed: %v", err)
	}
	if string(keySecret) != "PRIVATE" {
		t.Fatalf("unexpected key secret %q", string(keySecret))
	}
	passphrase, err := catalog.OpenSecret(ctx, key.PassphraseSecretID)
	if err != nil {
		t.Fatalf("OpenSecret passphrase failed: %v", err)
	}
	if string(passphrase) != "phrase" {
		t.Fatalf("unexpected passphrase secret %q", string(passphrase))
	}

	identityRec, err := catalog.ResolveDocument(ctx, domain.KindIdentity, "ops")
	if err != nil {
		t.Fatalf("ResolveDocument identity failed: %v", err)
	}
	identity, err := catalog.GetIdentity(ctx, identityRec.ID)
	if err != nil {
		t.Fatalf("GetIdentity failed: %v", err)
	}
	if len(identity.Methods) != 1 || identity.Methods[0].PasswordSecretID == "" {
		t.Fatalf("expected identity password to be stored as a secret, got %+v", identity.Methods)
	}

	hostRec, err := catalog.ResolveDocument(ctx, domain.KindHost, "prod")
	if err != nil {
		t.Fatalf("ResolveDocument host failed: %v", err)
	}
	host, err := catalog.GetHost(ctx, hostRec.ID)
	if err != nil {
		t.Fatalf("GetHost failed: %v", err)
	}
	groupRec, err := catalog.ResolveDocument(ctx, domain.KindGroup, "prod-group")
	if err != nil {
		t.Fatalf("ResolveDocument group failed: %v", err)
	}
	if host.Port == nil || *host.Port != 2222 || host.KeyRef == nil || *host.KeyRef != key.ID || host.IdentityRef == nil || *host.IdentityRef != identity.ID {
		t.Fatalf("expected host to link imported credentials, got %+v", host)
	}
	if len(host.GroupIDs) != 1 || host.GroupIDs[0] != groupRec.ID {
		t.Fatalf("expected host to link imported group, got %+v", host.GroupIDs)
	}
	hostSecret, err := catalog.OpenSecret(ctx, host.PasswordSecretID)
	if err != nil {
		t.Fatalf("OpenSecret host failed: %v", err)
	}
	if string(hostSecret) != "host-password" {
		t.Fatalf("unexpected host secret %q", string(hostSecret))
	}
}

func TestTermiusImporterDryRunDoesNotWrite(t *testing.T) {
	catalog, cleanup := newTestCatalog(t)
	defer cleanup()
	ctx := context.Background()
	bundle := termius.Bundle{
		Source:        termius.SourceName,
		FormatVersion: termius.BundleFormatVersion,
		Normalized: termius.Normalized{
			Hosts: []termius.Host{{Label: "prod", Host: "prod.example.com"}},
		},
	}

	report, err := NewTermiusImporter(catalog).Import(ctx, bundle, TermiusImportOptions{DryRun: true})
	if err != nil {
		t.Fatalf("Import dry-run failed: %v", err)
	}
	if report.Hosts != 1 || !report.DryRun {
		t.Fatalf("unexpected dry-run report: %+v", report)
	}
	if _, err := catalog.ResolveDocument(ctx, domain.KindHost, "prod"); err == nil {
		t.Fatal("expected dry-run to avoid writing host")
	}
}
