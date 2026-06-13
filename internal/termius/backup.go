package termius

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

func BuildFileBackup(sourcePath string, includeContents bool, localKey string) (*FileBackup, error) {
	root := resolveBackupRoot(sourcePath)
	if root == "" {
		root = sourcePath
	}
	paths := []string{}
	for _, dir := range defaultLevelDBDirs(root) {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			paths = append(paths, dir)
		}
	}
	for _, extra := range []string{"window-state.json", "Preferences"} {
		path := filepath.Join(root, extra)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			paths = append(paths, path)
		}
	}
	if len(paths) == 0 {
		return nil, nil
	}
	backup := &FileBackup{
		IncludesContents: includeContents,
		Files:            []BackupFile{},
	}
	if includeContents {
		backup.LocalKey = localKey
	}
	for _, path := range paths {
		if err := appendBackupPath(backup, root, path, includeContents); err != nil {
			return nil, err
		}
	}
	slices.SortFunc(backup.Files, func(left, right BackupFile) int {
		return strings.Compare(left.Path, right.Path)
	})
	return backup, nil
}

func appendBackupPath(backup *FileBackup, root string, path string, includeContents bool) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return appendBackupFile(backup, root, path, includeContents)
	}
	return filepath.WalkDir(path, func(child string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || entry.Name() == "LOCK" {
			return nil
		}
		return appendBackupFile(backup, root, child, includeContents)
	})
}

func appendBackupFile(backup *FileBackup, root string, path string, includeContents bool) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(raw)
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = filepath.Base(path)
	}
	file := BackupFile{
		Path:   filepath.ToSlash(rel),
		Size:   int64(len(raw)),
		SHA256: hex.EncodeToString(sum[:]),
	}
	if includeContents {
		file.ContentBase64 = base64.StdEncoding.EncodeToString(raw)
	}
	backup.Files = append(backup.Files, file)
	return nil
}

func resolveBackupRoot(sourcePath string) string {
	if root := termiusRootFromLevelDB(sourcePath); root != "" {
		return root
	}
	return filepath.Clean(sourcePath)
}
