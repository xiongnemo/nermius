//go:build windows

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/nermius/nermius/internal/config"
)

type windowsDPAPIStore struct {
	paths config.Paths
}

type windowsPromptAuthorizer struct{}

func defaultUnlockMaterialStore(paths config.Paths) UnlockMaterialStore {
	return &windowsDPAPIStore{paths: paths}
}

func defaultPresenceAuthorizer(paths config.Paths) PresenceAuthorizer {
	return &windowsPromptAuthorizer{}
}

func (s *windowsDPAPIStore) Kind() string { return "windows-dpapi" }

func (s *windowsDPAPIStore) Available(ctx context.Context) (bool, string) {
	return true, "Windows DPAPI"
}

func (s *windowsDPAPIStore) IsEnrolled(ctx context.Context, vaultID string) (bool, error) {
	_, err := os.Stat(unlockMaterialBlobPath(s.paths, vaultID))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func (s *windowsDPAPIStore) Store(ctx context.Context, vaultID string, vaultKey []byte) error {
	path := unlockMaterialBlobPath(s.paths, vaultID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	protected, err := cryptProtect(vaultKey, "Nermius vault "+vaultID)
	if err != nil {
		return err
	}
	return os.WriteFile(path, protected, 0o600)
}

func (s *windowsDPAPIStore) Load(ctx context.Context, vaultID string, intent vaultAccessIntent) ([]byte, error) {
	path := unlockMaterialBlobPath(s.paths, vaultID)
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return cryptUnprotect(raw, fmt.Sprintf("Authorize %s access to Nermius vault", intent))
}

func (s *windowsDPAPIStore) Delete(ctx context.Context, vaultID string) error {
	return config.RemoveIfExists(unlockMaterialBlobPath(s.paths, vaultID))
}

func (a *windowsPromptAuthorizer) Kind() string { return "windows-dpapi-prompt" }

func (a *windowsPromptAuthorizer) Available(ctx context.Context) (bool, string) {
	return true, "Windows protected-data prompt"
}

func (a *windowsPromptAuthorizer) UserPresence() bool { return true }

func (a *windowsPromptAuthorizer) Require(ctx context.Context, vaultID string, intent vaultAccessIntent) error {
	return nil
}

func cryptProtect(plaintext []byte, description string) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("plaintext is empty")
	}
	in := bytesToDataBlob(plaintext)
	var out windows.DataBlob
	descPtr, err := windows.UTF16PtrFromString(description)
	if err != nil {
		return nil, err
	}
	if err := windows.CryptProtectData(&in, descPtr, nil, 0, nil, 0, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return dataBlobBytes(out), nil
}

func cryptUnprotect(ciphertext []byte, prompt string) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, errors.New("ciphertext is empty")
	}
	in := bytesToDataBlob(ciphertext)
	var out windows.DataBlob
	promptText, err := windows.UTF16PtrFromString(prompt)
	if err != nil {
		return nil, err
	}
	promptStruct := windows.CryptProtectPromptStruct{
		Size:        uint32(unsafe.Sizeof(windows.CryptProtectPromptStruct{})),
		PromptFlags: windows.CRYPTPROTECT_PROMPT_ON_UNPROTECT | windows.CRYPTPROTECT_PROMPT_REQUIRE_STRONG,
		Prompt:      promptText,
	}
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, &promptStruct, 0, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return dataBlobBytes(out), nil
}

func bytesToDataBlob(data []byte) windows.DataBlob {
	return windows.DataBlob{
		Size: uint32(len(data)),
		Data: &data[0],
	}
}

func dataBlobBytes(blob windows.DataBlob) []byte {
	if blob.Data == nil || blob.Size == 0 {
		return nil
	}
	return append([]byte(nil), unsafe.Slice(blob.Data, blob.Size)...)
}
