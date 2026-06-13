package termius

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

type LocalKeyReader interface {
	ReadLocalKey(context.Context) (string, error)
}

func ExportLocal(ctx context.Context, opts ExportOptions) (Bundle, error) {
	sourceDir := opts.SourceDir
	if sourceDir == "" {
		sourceDir = DefaultDataRoot()
	}
	if sourceDir == "" {
		return Bundle{}, errors.New("Termius data directory is unavailable; pass --source-dir")
	}
	encodedKey, err := defaultLocalKeyReader().ReadLocalKey(ctx)
	if err != nil {
		return Bundle{}, err
	}
	key, err := DecodeLocalKey(encodedKey)
	if err != nil {
		return Bundle{}, err
	}
	scanDirs, err := ScanDirs(sourceDir)
	if err != nil {
		return Bundle{}, err
	}
	blobs, err := ScanEncryptedBlobs(sourceDir)
	if err != nil {
		return Bundle{}, err
	}
	decrypted := DecryptBlobs(blobs, key)
	bundle := BuildBundle(blobs, decrypted, opts.IncludeSecrets, opts.RawOnly)
	bundle.ScanDirs = scanDirs
	backup, err := BuildFileBackup(sourceDir, opts.IncludeSecrets, encodedKey)
	if err != nil {
		return Bundle{}, err
	}
	bundle.Backup = backup
	return bundle, nil
}

func DefaultDataRoot() string {
	if runtime.GOOS == "windows" {
		if appData := os.Getenv("APPDATA"); appData != "" {
			return filepath.Join(appData, "Termius")
		}
	}
	if configDir, err := os.UserConfigDir(); err == nil && configDir != "" {
		return filepath.Join(configDir, "Termius")
	}
	return ""
}

func DefaultDataDir() string {
	if runtime.GOOS == "windows" {
		if appData := os.Getenv("APPDATA"); appData != "" {
			return filepath.Join(appData, "Termius", "IndexedDB", "file__0.indexeddb.leveldb")
		}
	}
	if configDir, err := os.UserConfigDir(); err == nil && configDir != "" {
		return filepath.Join(configDir, "Termius", "IndexedDB", "file__0.indexeddb.leveldb")
	}
	return ""
}
