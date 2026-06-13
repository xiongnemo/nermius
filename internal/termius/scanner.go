package termius

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode/utf16"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/comparer"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

var encryptedBlobPattern = regexp.MustCompile(`(?:BA|Ag|Aw|AQ)[A-Za-z0-9+/_=-]{30,}`)
var structuredFieldPattern = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)"`)

func ScanEncryptedBlobs(sourceDir string) ([]EncryptedBlob, error) {
	dirs, err := ResolveScanDirs(sourceDir)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	out := []EncryptedBlob{}
	for _, dir := range dirs {
		_ = scanLevelDBRecords(dir, seen, &out)
		if err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			if entry.Name() == "LOCK" || !isTermiusScanFile(entry.Name()) {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			sourceFile, err := filepath.Rel(dir, path)
			if err != nil {
				sourceFile = entry.Name()
			}
			sourceFile = filepath.ToSlash(filepath.Join(filepath.Base(filepath.Dir(dir)), filepath.Base(dir), sourceFile))
			addRawBlobCandidates(raw, sourceFile, "", true, seen, &out)
			return nil
		}); err != nil {
			return nil, err
		}
	}
	slices.SortFunc(out, func(left, right EncryptedBlob) int {
		if left.SourceFile != right.SourceFile {
			return strings.Compare(left.SourceFile, right.SourceFile)
		}
		return strings.Compare(left.Value, right.Value)
	})
	return out, nil
}

func scanLevelDBRecords(dir string, seen map[string]struct{}, out *[]EncryptedBlob) error {
	db, err := openTermiusLevelDB(dir)
	if err != nil {
		tempDir, copyErr := copyLevelDBDir(dir)
		if copyErr != nil {
			return err
		}
		defer os.RemoveAll(tempDir)
		db, err = openTermiusLevelDB(tempDir)
		if err != nil {
			return err
		}
	}
	defer db.Close()
	storeNames := indexedDBObjectStoreNames(db)
	iter := db.NewIterator(nil, nil)
	defer iter.Release()
	prefix := filepath.ToSlash(filepath.Join(filepath.Base(filepath.Dir(dir)), filepath.Base(dir)))
	for iter.Next() {
		key := append([]byte(nil), iter.Key()...)
		value := append([]byte(nil), iter.Value()...)
		keyHash := shortHash(key)
		source := prefix + "/record:" + keyHash
		storeName := indexedDBStoreNameForRecord(key, storeNames)
		addRawBlobCandidates(key, source+":key", storeName, false, seen, out)
		addRawBlobCandidates(value, source+":value", storeName, false, seen, out)
		if encoded, ok := encodeBinaryEncryptedFrame(value); ok {
			addBlobCandidate(encoded, source+":binary-value", storeName, "", nil, seen, out)
		}
		if encoded, ok := encodeBinaryEncryptedFrame(key); ok {
			addBlobCandidate(encoded, source+":binary-key", storeName, "", nil, seen, out)
		}
	}
	return iter.Error()
}

func indexedDBObjectStoreNames(db *leveldb.DB) map[indexedDBStoreKey]string {
	storeNames := map[indexedDBStoreKey]string{}
	iter := db.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		storeKey, storeName, ok := decodeIndexedDBObjectStoreMetadataName(iter.Key(), iter.Value())
		if ok {
			storeNames[storeKey] = storeName
		}
	}
	return storeNames
}

func indexedDBStoreNameForRecord(key []byte, storeNames map[indexedDBStoreKey]string) string {
	prefix, ok := decodeIndexedDBKeyPrefix(key)
	if !ok || prefix.ObjectStoreID == 0 || prefix.IndexID != indexedDBObjectStoreDataIndexID {
		return ""
	}
	return storeNames[indexedDBStoreKey{DatabaseID: prefix.DatabaseID, ObjectStoreID: prefix.ObjectStoreID}]
}

func openTermiusLevelDB(dir string) (*leveldb.DB, error) {
	db, err := leveldb.OpenFile(dir, &opt.Options{ReadOnly: true})
	if err == nil {
		return db, nil
	}
	db, idbErr := leveldb.OpenFile(dir, &opt.Options{ReadOnly: true, Comparer: indexedDBComparer{}})
	if idbErr == nil {
		return db, nil
	}
	return nil, err
}

type indexedDBComparer struct{}

func (indexedDBComparer) Compare(a, b []byte) int {
	return compareIndexedDBKeys(a, b)
}

func (indexedDBComparer) Name() string {
	return "idb_cmp1"
}

func (indexedDBComparer) Separator(dst, a, b []byte) []byte {
	return comparer.DefaultComparer.Separator(dst, a, b)
}

func (indexedDBComparer) Successor(dst, b []byte) []byte {
	return comparer.DefaultComparer.Successor(dst, b)
}

func copyLevelDBDir(dir string) (string, error) {
	tempDir, err := os.MkdirTemp("", "nermius-termius-leveldb-*")
	if err != nil {
		return "", err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		_ = os.RemoveAll(tempDir)
		return "", err
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == "LOCK" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		if err := os.WriteFile(filepath.Join(tempDir, entry.Name()), raw, 0o600); err != nil {
			_ = os.RemoveAll(tempDir)
			return "", err
		}
	}
	return tempDir, nil
}

func addBlobCandidates(values []string, sourceFile string, seen map[string]struct{}, out *[]EncryptedBlob) {
	for _, value := range values {
		addBlobCandidate(value, sourceFile, "", "", nil, seen, out)
	}
}

func addRawBlobCandidates(raw []byte, sourceFile string, storeName string, includeOffset bool, seen map[string]struct{}, out *[]EncryptedBlob) {
	matches := encryptedBlobPattern.FindAllIndex(raw, -1)
	for _, match := range matches {
		value := strings.Trim(string(raw[match[0]:match[1]]), "\"'")
		if len(value) < 40 {
			continue
		}
		candidateSource := sourceFile
		if includeOffset {
			candidateSource = fmt.Sprintf("%s:offset:%x", sourceFile, match[0])
		}
		addBlobCandidate(value, candidateSource, storeName, nearestStructuredField(raw, match[0]), nearbyStructuredFields(raw, match[0]), seen, out)
	}
}

func addBlobCandidate(value string, sourceFile string, storeName string, field string, contextFields []string, seen map[string]struct{}, out *[]EncryptedBlob) {
	if _, ok := seen[value]; ok {
		return
	}
	seen[value] = struct{}{}
	*out = append(*out, EncryptedBlob{
		Value:         value,
		SourceFile:    sourceFile,
		StoreName:     storeName,
		Field:         field,
		ContextFields: contextFields,
	})
}

func nearestStructuredField(raw []byte, offset int) string {
	left := offset - 128
	if left < 0 {
		left = 0
	}
	window := raw[left:offset]
	closing := bytesLastIndexByte(window, '"')
	if closing < 0 || len(window)-closing > 24 {
		return ""
	}
	start := closing - 1
	for start >= 0 {
		b := window[start]
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_' {
			start--
			continue
		}
		break
	}
	field := string(window[start+1 : closing])
	if field == "" {
		return ""
	}
	for _, r := range field {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			continue
		}
		return ""
	}
	return field
}

func nearbyStructuredFields(raw []byte, offset int) []string {
	left := offset - 2048
	if left < 0 {
		left = 0
	}
	right := offset + 2048
	if right > len(raw) {
		right = len(raw)
	}
	seen := map[string]struct{}{}
	for _, match := range structuredFieldPattern.FindAllSubmatch(raw[left:right], -1) {
		if len(match) != 2 {
			continue
		}
		field := string(match[1])
		if !isKnownTermiusField(field) {
			continue
		}
		seen[field] = struct{}{}
	}
	fields := mapsKeys(seen)
	slices.Sort(fields)
	return fields
}

func mapsKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

func isKnownTermiusField(field string) bool {
	switch field {
	case "address", "agent_forwarding", "cloud_instance_id", "cloud_instance_type", "credentials_mode", "encrypted_with", "group", "host", "hostname", "identity", "is_shared", "is_visible", "label", "local_id", "package", "parent_group", "passphrase", "password", "port", "private_key", "public_key", "script", "sharing_mode", "ssh_config", "ssh_key", "status", "telnet_config", "username":
		return true
	default:
		return false
	}
}

func bytesLastIndexByte(raw []byte, value byte) int {
	for i := len(raw) - 1; i >= 0; i-- {
		if raw[i] == value {
			return i
		}
	}
	return -1
}

func encodeBinaryEncryptedFrame(raw []byte) (string, bool) {
	if len(raw) < termiusHeaderSize+secretboxNonceSize+16 || raw[0] != termiusEncryptedVersion {
		return "", false
	}
	return base64.StdEncoding.EncodeToString(raw), true
}

func ResolveScanDirs(sourcePath string) ([]string, error) {
	sourcePath = filepath.Clean(sourcePath)
	info, err := os.Stat(sourcePath)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, nil
	}
	candidates := []string{}
	if isLevelDBDir(sourcePath) {
		candidates = append(candidates, sourcePath)
		if root := termiusRootFromLevelDB(sourcePath); root != "" {
			candidates = append(candidates, defaultLevelDBDirs(root)...)
		}
	} else {
		candidates = append(candidates, defaultLevelDBDirs(sourcePath)...)
		candidates = append(candidates, sourcePath)
	}
	seen := map[string]struct{}{}
	out := []string{}
	for _, candidate := range candidates {
		candidate = filepath.Clean(candidate)
		if _, ok := seen[strings.ToLower(candidate)]; ok {
			continue
		}
		seen[strings.ToLower(candidate)] = struct{}{}
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			out = append(out, candidate)
		}
	}
	return out, nil
}

func defaultLevelDBDirs(root string) []string {
	return []string{
		filepath.Join(root, "IndexedDB", "file__0.indexeddb.leveldb"),
		filepath.Join(root, "Local Storage", "leveldb"),
		filepath.Join(root, "Cache", "Cache_Data"),
	}
}

func termiusRootFromLevelDB(path string) string {
	clean := filepath.Clean(path)
	if filepath.Base(clean) == "leveldb" && filepath.Base(filepath.Dir(clean)) == "Local Storage" {
		return filepath.Dir(filepath.Dir(clean))
	}
	if filepath.Base(clean) == "file__0.indexeddb.leveldb" && filepath.Base(filepath.Dir(clean)) == "IndexedDB" {
		return filepath.Dir(filepath.Dir(clean))
	}
	return ""
}

func isLevelDBDir(path string) bool {
	base := filepath.Base(filepath.Clean(path))
	return base == "leveldb" || strings.HasSuffix(base, ".indexeddb.leveldb")
}

func ScanDirs(sourceDir string) ([]string, error) {
	dirs, err := ResolveScanDirs(sourceDir)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		out = append(out, filepath.ToSlash(dir))
	}
	return out, nil
}

func ExtractEncryptedBlobs(raw []byte) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, text := range extractTextViews(raw) {
		matches := encryptedBlobPattern.FindAllString(text, -1)
		for _, match := range matches {
			value := strings.Trim(match, "\"'")
			if len(value) < 40 {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			out = append(out, value)
		}
	}
	return out
}

func extractTextViews(raw []byte) []string {
	views := []string{string(raw)}
	if text, ok := decodeUTF16(raw, true); ok {
		views = append(views, text)
	}
	if text, ok := decodeUTF16(raw, false); ok {
		views = append(views, text)
	}
	return views
}

func decodeUTF16(raw []byte, littleEndian bool) (string, bool) {
	if len(raw) < 4 || len(raw)%2 != 0 {
		return "", false
	}
	asciiLike := 0
	words := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		var word uint16
		if littleEndian {
			word = uint16(raw[i]) | uint16(raw[i+1])<<8
		} else {
			word = uint16(raw[i])<<8 | uint16(raw[i+1])
		}
		if word >= 32 && word <= 126 {
			asciiLike++
		}
		words = append(words, word)
	}
	if asciiLike < len(words)/4 {
		return "", false
	}
	return string(utf16.Decode(words)), true
}

func hashBlob(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func shortHash(value []byte) string {
	sum := sha256.Sum256(value)
	return fmt.Sprintf("%x", sum[:6])
}

func isLevelDBScanFile(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".log", ".ldb", ".sst":
		return true
	default:
		return strings.HasPrefix(strings.ToUpper(name), "MANIFEST")
	}
}

func isTermiusScanFile(name string) bool {
	if isLevelDBScanFile(name) {
		return true
	}
	switch name {
	case "Local State", "Preferences", "Network Persistent State":
		return true
	default:
		return strings.HasPrefix(name, "f_")
	}
}
