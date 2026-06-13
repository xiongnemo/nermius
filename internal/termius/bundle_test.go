package termius

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/secretbox"
)

func TestBuildBundleKeepsRawObjectsAndNormalizesKnownTypes(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	blobs := []EncryptedBlob{
		{Value: sealTestBlob(t, key, `{"host":"prod.example.com","user_name":"root","password":"pw","connection_type":"ssh","title":"prod","port":2222,"key_id":"key-1","tags":["prod-group"]}`), SourceFile: "000001.log"},
		{Value: sealTestBlob(t, key, `{"id":"key-1","label":"deploy","private_key":"PRIVATE","passphrase":"phrase"}`), SourceFile: "000002.ldb"},
		{Value: sealTestBlob(t, key, `[{"label":"script","script":"echo hello"}]`), SourceFile: "000003.ldb"},
		{Value: sealTestBlob(t, key, `{"unexpected":true}`), SourceFile: "000004.ldb"},
	}
	decrypted := DecryptBlobs(blobs, key)
	bundle := BuildBundle(blobs, decrypted, true, false)

	if bundle.Stats.EncryptedBlobs != 4 || bundle.Stats.DecryptedBlobs != 4 || bundle.Stats.JSONObjects != 4 {
		t.Fatalf("unexpected stats: %+v", bundle.Stats)
	}
	if len(bundle.RawObjects) != 4 {
		t.Fatalf("expected all JSON objects in raw_objects, got %d", len(bundle.RawObjects))
	}
	if len(bundle.Normalized.Hosts) != 1 || bundle.Normalized.Hosts[0].Password != "pw" {
		t.Fatalf("expected normalized host with password, got %+v", bundle.Normalized.Hosts)
	}
	if bundle.Normalized.Hosts[0].KeyName != "deploy" {
		t.Fatalf("expected host key name to be linked, got %+v", bundle.Normalized.Hosts[0])
	}
	if len(bundle.Normalized.Groups) != 1 || bundle.Normalized.Groups[0].Name != "prod-group" {
		t.Fatalf("expected host tags to derive groups, got %+v", bundle.Normalized.Groups)
	}
	if len(bundle.Normalized.Keys) != 1 || bundle.Normalized.Keys[0].PrivateKeyPEM != "PRIVATE" || bundle.Normalized.Keys[0].Passphrase != "phrase" {
		t.Fatalf("expected normalized key with secrets, got %+v", bundle.Normalized.Keys)
	}
	if len(bundle.Normalized.Snippets) != 1 || bundle.Normalized.Snippets[0].Script != "echo hello" {
		t.Fatalf("expected normalized snippet with script, got %+v", bundle.Normalized.Snippets)
	}
	if bundle.Stats.UnknownObjects != 1 || len(bundle.Normalized.UnknownRefs) != 1 {
		t.Fatalf("expected one unknown object, got stats=%+v refs=%+v", bundle.Stats, bundle.Normalized.UnknownRefs)
	}
}

func TestBuildBundleOmitsSecretsWhenNotRequested(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	blob := EncryptedBlob{Value: sealTestBlob(t, key, `{"host":"prod.example.com","user_name":"root","password":"pw","connection_type":"ssh"}`)}
	decrypted := DecryptBlobs([]EncryptedBlob{blob}, key)
	bundle := BuildBundle([]EncryptedBlob{blob}, decrypted, false, false)

	if len(bundle.RawObjects) != 1 {
		t.Fatalf("expected raw object metadata")
	}
	if len(bundle.RawObjects[0].Value) != 0 {
		t.Fatalf("expected raw object value to be omitted without includeSecrets")
	}
	if bundle.Normalized.Hosts[0].Password != "" {
		t.Fatalf("expected normalized password to be omitted without includeSecrets")
	}
}

func TestBuildBundleKeepsNonJSONTextPayloads(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	blob := EncryptedBlob{Value: sealTestBlob(t, key, `plain-secret-or-key-material`), SourceFile: "Local Storage/leveldb/record:value"}
	decrypted := DecryptBlobs([]EncryptedBlob{blob}, key)
	bundle := BuildBundle([]EncryptedBlob{blob}, decrypted, false, false)

	if bundle.Stats.TextPayloads != 1 || len(bundle.RawObjects) != 1 {
		t.Fatalf("expected non-JSON text raw object, stats=%+v raw=%+v", bundle.Stats, bundle.RawObjects)
	}
	if bundle.RawObjects[0].Type != "secret_text" || len(bundle.RawObjects[0].Value) != 0 {
		t.Fatalf("expected redacted text metadata, got %+v", bundle.RawObjects[0])
	}

	full := BuildBundle([]EncryptedBlob{blob}, decrypted, true, false)
	if full.RawObjects[0].Type != "secret_text" || string(full.RawObjects[0].Value) != `"plain-secret-or-key-material"` {
		t.Fatalf("expected text value with includeSecrets, got %+v", full.RawObjects[0])
	}
}

func TestBuildBundleClassifiesPrivateKeysAndSnippetScripts(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	privateKey := "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"
	script := "sudo systemctl restart ssh\n"
	blobs := []EncryptedBlob{
		{Value: sealTestBlob(t, key, privateKey)},
		{Value: sealTestBlob(t, key, script)},
	}
	decrypted := DecryptBlobs(blobs, key)
	bundle := BuildBundle(blobs, decrypted, true, false)

	if len(bundle.Normalized.Keys) != 1 || bundle.Normalized.Keys[0].PrivateKeyPEM != privateKey {
		t.Fatalf("expected normalized private key, got %+v", bundle.Normalized.Keys)
	}
	if len(bundle.Normalized.Snippets) != 1 || bundle.Normalized.Snippets[0].Script != strings.TrimSpace(script) {
		t.Fatalf("expected normalized snippet script, got %+v", bundle.Normalized.Snippets)
	}
}

func TestBuildBundleBuildsIdentitiesFromRecordFields(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	source := "IndexedDB/file__0.indexeddb.leveldb/record:abc123:value"
	blobs := []EncryptedBlob{
		{Value: sealTestBlob(t, key, "Work login"), SourceFile: source, StoreName: "ssh_identities", Field: "label"},
		{Value: sealTestBlob(t, key, "deploy"), SourceFile: source, StoreName: "ssh_identities", Field: "username"},
		{Value: sealTestBlob(t, key, "123456"), SourceFile: source, StoreName: "ssh_identities", Field: "password"},
	}
	decrypted := DecryptBlobs(blobs, key)

	inventory := BuildBundle(blobs, decrypted, false, false)
	if len(inventory.Normalized.Identities) != 1 {
		t.Fatalf("expected one redacted identity, got %+v", inventory.Normalized.Identities)
	}
	if inventory.Normalized.Identities[0].Username != "" || inventory.Normalized.Identities[0].Password != "" {
		t.Fatalf("expected identity secrets to be redacted, got %+v", inventory.Normalized.Identities[0])
	}
	if len(inventory.Normalized.Passwords) != 1 || inventory.Normalized.Passwords[0].Value != "" {
		t.Fatalf("expected redacted password metadata, got %+v", inventory.Normalized.Passwords)
	}

	full := BuildBundle(blobs, decrypted, true, false)
	if len(full.Normalized.Identities) != 1 {
		t.Fatalf("expected one identity with secrets, got %+v", full.Normalized.Identities)
	}
	identity := full.Normalized.Identities[0]
	if identity.Name != "Work login" || identity.Username != "deploy" || identity.Password != "123456" {
		t.Fatalf("unexpected identity: %+v", identity)
	}
	if len(full.Normalized.Passwords) != 1 || full.Normalized.Passwords[0].Value != "123456" {
		t.Fatalf("expected password value with includeSecrets, got %+v", full.Normalized.Passwords)
	}
}

func TestBuildBundleBuildsGroupsFromIndexedDBStoreName(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	source := "IndexedDB/file__0.indexeddb.leveldb/record:def456:value"
	blob := EncryptedBlob{
		Value:      sealTestBlob(t, key, "Example Cluster"),
		SourceFile: source,
		StoreName:  "groups",
		Field:      "label",
	}
	decrypted := DecryptBlobs([]EncryptedBlob{blob}, key)

	inventory := BuildBundle([]EncryptedBlob{blob}, decrypted, false, false)
	if len(inventory.Normalized.Groups) != 1 || inventory.Normalized.Groups[0].Name == "Example Cluster" {
		t.Fatalf("expected one redacted group, got %+v", inventory.Normalized.Groups)
	}

	full := BuildBundle([]EncryptedBlob{blob}, decrypted, true, false)
	if len(full.Normalized.Groups) != 1 || full.Normalized.Groups[0].Name != "Example Cluster" {
		t.Fatalf("expected group label with includeSecrets, got %+v", full.Normalized.Groups)
	}
}

func TestScanEncryptedBlobsDeduplicatesLevelDBFiles(t *testing.T) {
	dir := t.TempDir()
	blob := "BAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := os.WriteFile(filepath.Join(dir, "000001.log"), []byte(blob+" "+blob), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "MANIFEST-000001"), []byte(blob), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	blobs, err := ScanEncryptedBlobs(dir)
	if err != nil {
		t.Fatalf("ScanEncryptedBlobs failed: %v", err)
	}
	if len(blobs) != 1 || blobs[0].Value != blob {
		t.Fatalf("unexpected blobs: %+v", blobs)
	}
}

func TestNearestStructuredFieldReadsIdentifierBeforeEncryptedBlob(t *testing.T) {
	raw := []byte(`".label"8BAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".username"@BA`)
	offset := strings.Index(string(raw), "BAaaaaaaaa")
	if offset < 0 {
		t.Fatal("test fixture is invalid")
	}
	if field := nearestStructuredField(raw, offset); field != "label" {
		t.Fatalf("expected label field, got %q", field)
	}
}

func TestBuildFileBackupIncludesMetadataAndOptionalContents(t *testing.T) {
	root := t.TempDir()
	leveldbDir := filepath.Join(root, "IndexedDB", "file__0.indexeddb.leveldb")
	if err := os.MkdirAll(leveldbDir, 0o700); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(leveldbDir, "000001.ldb"), []byte("leveldb-data"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "window-state.json"), []byte(`{"x":1}`), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	inventory, err := BuildFileBackup(root, false, "local-key")
	if err != nil {
		t.Fatalf("BuildFileBackup inventory failed: %v", err)
	}
	if inventory == nil || inventory.IncludesContents || inventory.LocalKey != "" || len(inventory.Files) != 2 {
		t.Fatalf("unexpected inventory backup: %+v", inventory)
	}
	full, err := BuildFileBackup(root, true, "local-key")
	if err != nil {
		t.Fatalf("BuildFileBackup full failed: %v", err)
	}
	if !full.IncludesContents || full.LocalKey != "local-key" {
		t.Fatalf("expected full backup to include local key, got %+v", full)
	}
	for _, file := range full.Files {
		if file.ContentBase64 == "" {
			t.Fatalf("expected file content for %+v", file)
		}
	}
}

func sealTestBlob(t *testing.T, key []byte, plaintext string) string {
	t.Helper()
	var fixedKey [32]byte
	var nonce [24]byte
	copy(fixedKey[:], key)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	ciphertext := secretbox.Seal(nil, []byte(plaintext), &nonce, &fixedKey)
	data := append([]byte{termiusEncryptedVersion, 0}, nonce[:]...)
	data = append(data, ciphertext...)
	return base64.StdEncoding.EncodeToString(data)
}
