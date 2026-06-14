//go:build windows

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/nermius/nermius/internal/config"
)

const (
	ncryptMSKeyStorageProvider = "Microsoft Software Key Storage Provider"
	ncryptRSAAlgorithm         = "RSA"
	ncryptSHA256Algorithm      = "SHA256"

	ncryptLengthProperty       = "Length"
	ncryptUIPolicyProperty     = "UI Policy"
	ncryptWindowHandleProperty = "HWND Handle"
	ncryptExportPolicyProperty = "Export Policy"
	ncryptKeyUsageProperty     = "Key Usage"

	ncryptPadOAEPFlag                          = 0x00000004
	ncryptOverwriteKeyFlag                     = 0x00000080
	ncryptAllowDecryptFlag                     = 0x00000001
	ncryptUIForceHighProtectionFlag            = 0x00000002
	ncryptStrongPresenceKeyLengthBits          = 3072
	ncryptStrongPresenceUIPolicyVersion        = 1
	ncryptStrongPresenceBlobFileSuffix         = ".cng"
	ncryptStrongPresenceKeyNamePrefix          = "Nermius Vault "
	ncryptStatusOK                      uint32 = 0
	nteNotFound                         uint32 = 0x80090011
	nteBadKeySet                        uint32 = 0x80090016
)

var (
	modNcrypt = windows.NewLazySystemDLL("ncrypt.dll")

	procNCryptOpenStorageProvider = modNcrypt.NewProc("NCryptOpenStorageProvider")
	procNCryptCreatePersistedKey  = modNcrypt.NewProc("NCryptCreatePersistedKey")
	procNCryptOpenKey             = modNcrypt.NewProc("NCryptOpenKey")
	procNCryptFinalizeKey         = modNcrypt.NewProc("NCryptFinalizeKey")
	procNCryptSetProperty         = modNcrypt.NewProc("NCryptSetProperty")
	procNCryptEncrypt             = modNcrypt.NewProc("NCryptEncrypt")
	procNCryptDecrypt             = modNcrypt.NewProc("NCryptDecrypt")
	procNCryptDeleteKey           = modNcrypt.NewProc("NCryptDeleteKey")
	procNCryptFreeObject          = modNcrypt.NewProc("NCryptFreeObject")
)

type windowsCNGPresenceStore struct {
	paths config.Paths
}

type ncryptUIPolicy struct {
	version       uint32
	flags         uint32
	creationTitle *uint16
	friendlyName  *uint16
	description   *uint16
}

type bcryptOAEPInfo struct {
	algID     *uint16
	label     *byte
	labelSize uint32
}

func defaultStrongPresenceMaterialStore(paths config.Paths) UnlockMaterialStore {
	return &windowsCNGPresenceStore{paths: paths}
}

func (s *windowsCNGPresenceStore) Kind() string { return "windows-cng-presence" }

func (s *windowsCNGPresenceStore) Available(ctx context.Context) (bool, string) {
	if err := findNCryptProcs(); err != nil {
		return false, err.Error()
	}
	return true, "Windows CNG high-protection key"
}

func (s *windowsCNGPresenceStore) IsEnrolled(ctx context.Context, vaultID string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if _, err := os.Stat(strongUnlockMaterialBlobPath(s.paths, vaultID)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	provider, err := ncryptOpenStorageProvider(ncryptMSKeyStorageProvider)
	if err != nil {
		return false, err
	}
	defer ncryptFreeObject(provider)
	key, err := ncryptOpenKey(provider, windowsCNGKeyName(vaultID))
	if err != nil {
		if errors.Is(err, errNCryptKeyNotFound) {
			return false, nil
		}
		return false, err
	}
	defer ncryptFreeObject(key)
	return true, nil
}

func (s *windowsCNGPresenceStore) Store(ctx context.Context, vaultID string, vaultKey []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(vaultKey) == 0 {
		return errors.New("vault key is empty")
	}
	if err := findNCryptProcs(); err != nil {
		return err
	}
	provider, err := ncryptOpenStorageProvider(ncryptMSKeyStorageProvider)
	if err != nil {
		return err
	}
	defer ncryptFreeObject(provider)
	key, err := ncryptCreateStrongPresenceKey(provider, vaultID)
	if err != nil {
		return err
	}
	keyDeleted := false
	defer func() {
		if !keyDeleted {
			ncryptFreeObject(key)
		}
	}()
	ciphertext, err := ncryptEncryptOAEP(key, vaultKey)
	if err != nil {
		return err
	}
	path := strongUnlockMaterialBlobPath(s.paths, vaultID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, ciphertext, 0o600); err != nil {
		if deleteErr := ncryptDeleteKey(key); deleteErr == nil {
			keyDeleted = true
		}
		return err
	}
	return nil
}

func (s *windowsCNGPresenceStore) Load(ctx context.Context, vaultID string, intent vaultAccessIntent) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := findNCryptProcs(); err != nil {
		return nil, err
	}
	ciphertext, err := os.ReadFile(strongUnlockMaterialBlobPath(s.paths, vaultID))
	if err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 {
		return nil, errors.New("CNG keychain blob is empty")
	}
	provider, err := ncryptOpenStorageProvider(ncryptMSKeyStorageProvider)
	if err != nil {
		return nil, err
	}
	defer ncryptFreeObject(provider)
	key, err := ncryptOpenKey(provider, windowsCNGKeyName(vaultID))
	if err != nil {
		return nil, err
	}
	defer ncryptFreeObject(key)
	return ncryptDecryptOAEP(key, ciphertext)
}

func (s *windowsCNGPresenceStore) Delete(ctx context.Context, vaultID string) error {
	if err := config.RemoveIfExists(strongUnlockMaterialBlobPath(s.paths, vaultID)); err != nil {
		return err
	}
	if err := findNCryptProcs(); err != nil {
		return nil
	}
	provider, err := ncryptOpenStorageProvider(ncryptMSKeyStorageProvider)
	if err != nil {
		return nil
	}
	defer ncryptFreeObject(provider)
	key, err := ncryptOpenKey(provider, windowsCNGKeyName(vaultID))
	if err != nil {
		if errors.Is(err, errNCryptKeyNotFound) {
			return nil
		}
		return err
	}
	return ncryptDeleteKey(key)
}

var errNCryptKeyNotFound = errors.New("CNG key not found")

func strongUnlockMaterialBlobPath(paths config.Paths, vaultID string) string {
	return filepath.Join(paths.CacheDir, "keychain", vaultID+ncryptStrongPresenceBlobFileSuffix)
}

func windowsCNGKeyName(vaultID string) string {
	return ncryptStrongPresenceKeyNamePrefix + vaultID
}

func findNCryptProcs() error {
	for _, proc := range []*windows.LazyProc{
		procNCryptOpenStorageProvider,
		procNCryptCreatePersistedKey,
		procNCryptOpenKey,
		procNCryptFinalizeKey,
		procNCryptSetProperty,
		procNCryptEncrypt,
		procNCryptDecrypt,
		procNCryptDeleteKey,
		procNCryptFreeObject,
	} {
		if err := proc.Find(); err != nil {
			return err
		}
	}
	return nil
}

func ncryptOpenStorageProvider(providerName string) (uintptr, error) {
	name, err := windows.UTF16PtrFromString(providerName)
	if err != nil {
		return 0, err
	}
	var provider uintptr
	status, _, _ := procNCryptOpenStorageProvider.Call(
		uintptr(unsafe.Pointer(&provider)),
		uintptr(unsafe.Pointer(name)),
		0,
	)
	runtime.KeepAlive(name)
	if ncryptFailed(status) {
		return 0, ncryptStatusError("NCryptOpenStorageProvider", status)
	}
	if provider == 0 {
		return 0, errors.New("NCryptOpenStorageProvider returned nil provider")
	}
	return provider, nil
}

func ncryptCreateStrongPresenceKey(provider uintptr, vaultID string) (uintptr, error) {
	alg, err := windows.UTF16PtrFromString(ncryptRSAAlgorithm)
	if err != nil {
		return 0, err
	}
	name, err := windows.UTF16PtrFromString(windowsCNGKeyName(vaultID))
	if err != nil {
		return 0, err
	}
	var key uintptr
	status, _, _ := procNCryptCreatePersistedKey.Call(
		provider,
		uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(alg)),
		uintptr(unsafe.Pointer(name)),
		0,
		ncryptOverwriteKeyFlag,
	)
	runtime.KeepAlive(alg)
	runtime.KeepAlive(name)
	if ncryptFailed(status) {
		return 0, ncryptStatusError("NCryptCreatePersistedKey", status)
	}
	if key == 0 {
		return 0, errors.New("NCryptCreatePersistedKey returned nil key")
	}
	if err := ncryptSetUint32Property(key, ncryptLengthProperty, ncryptStrongPresenceKeyLengthBits); err != nil {
		ncryptFreeObject(key)
		return 0, err
	}
	if err := ncryptSetUint32Property(key, ncryptKeyUsageProperty, ncryptAllowDecryptFlag); err != nil {
		ncryptFreeObject(key)
		return 0, err
	}
	if err := ncryptSetUint32Property(key, ncryptExportPolicyProperty, 0); err != nil {
		ncryptFreeObject(key)
		return 0, err
	}
	if err := ncryptSetStrongUIPolicy(key, vaultID); err != nil {
		ncryptFreeObject(key)
		return 0, err
	}
	if err := ncryptSetWindowHandle(key); err != nil {
		ncryptFreeObject(key)
		return 0, err
	}
	status, _, _ = procNCryptFinalizeKey.Call(key, 0)
	if ncryptFailed(status) {
		ncryptFreeObject(key)
		return 0, ncryptStatusError("NCryptFinalizeKey", status)
	}
	return key, nil
}

func ncryptOpenKey(provider uintptr, keyName string) (uintptr, error) {
	name, err := windows.UTF16PtrFromString(keyName)
	if err != nil {
		return 0, err
	}
	var key uintptr
	status, _, _ := procNCryptOpenKey.Call(
		provider,
		uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(name)),
		0,
		0,
	)
	runtime.KeepAlive(name)
	if ncryptKeyNotFound(status) {
		return 0, errNCryptKeyNotFound
	}
	if ncryptFailed(status) {
		return 0, ncryptStatusError("NCryptOpenKey", status)
	}
	if key == 0 {
		return 0, errors.New("NCryptOpenKey returned nil key")
	}
	return key, nil
}

func ncryptSetUint32Property(key uintptr, property string, value uint32) error {
	return ncryptSetProperty(key, property, unsafe.Pointer(&value), uint32(unsafe.Sizeof(value)), 0)
}

func ncryptSetStrongUIPolicy(key uintptr, vaultID string) error {
	creationTitle, err := windows.UTF16PtrFromString("Create Nermius vault unlock key")
	if err != nil {
		return err
	}
	friendlyName, err := windows.UTF16PtrFromString("Nermius vault " + shortVaultID(vaultID))
	if err != nil {
		return err
	}
	description, err := windows.UTF16PtrFromString("Authorize use of this Windows-protected key to unlock the Nermius vault.")
	if err != nil {
		return err
	}
	policy := ncryptUIPolicy{
		version:       ncryptStrongPresenceUIPolicyVersion,
		flags:         ncryptUIForceHighProtectionFlag,
		creationTitle: creationTitle,
		friendlyName:  friendlyName,
		description:   description,
	}
	err = ncryptSetProperty(key, ncryptUIPolicyProperty, unsafe.Pointer(&policy), uint32(unsafe.Sizeof(policy)), 0)
	runtime.KeepAlive(creationTitle)
	runtime.KeepAlive(friendlyName)
	runtime.KeepAlive(description)
	runtime.KeepAlive(policy)
	return err
}

func ncryptSetWindowHandle(key uintptr) error {
	hwnd := windowsConsoleWindow()
	if hwnd == 0 {
		return nil
	}
	return ncryptSetProperty(key, ncryptWindowHandleProperty, unsafe.Pointer(&hwnd), uint32(unsafe.Sizeof(hwnd)), 0)
}

func ncryptSetProperty(key uintptr, property string, data unsafe.Pointer, size uint32, flags uintptr) error {
	name, err := windows.UTF16PtrFromString(property)
	if err != nil {
		return err
	}
	status, _, _ := procNCryptSetProperty.Call(
		key,
		uintptr(unsafe.Pointer(name)),
		uintptr(data),
		uintptr(size),
		flags,
	)
	runtime.KeepAlive(name)
	if ncryptFailed(status) {
		return ncryptStatusError("NCryptSetProperty("+property+")", status)
	}
	return nil
}

func ncryptEncryptOAEP(key uintptr, plaintext []byte) ([]byte, error) {
	padding, err := ncryptOAEPInfo()
	if err != nil {
		return nil, err
	}
	defer runtime.KeepAlive(padding)
	var size uint32
	status, _, _ := procNCryptEncrypt.Call(
		key,
		bytesPointer(plaintext),
		uintptr(len(plaintext)),
		uintptr(unsafe.Pointer(padding)),
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		ncryptPadOAEPFlag,
	)
	runtime.KeepAlive(plaintext)
	runtime.KeepAlive(padding)
	if ncryptFailed(status) {
		return nil, ncryptStatusError("NCryptEncrypt(size)", status)
	}
	if size == 0 {
		return nil, errors.New("NCryptEncrypt returned zero output size")
	}
	ciphertext := make([]byte, size)
	status, _, _ = procNCryptEncrypt.Call(
		key,
		bytesPointer(plaintext),
		uintptr(len(plaintext)),
		uintptr(unsafe.Pointer(padding)),
		bytesPointer(ciphertext),
		uintptr(len(ciphertext)),
		uintptr(unsafe.Pointer(&size)),
		ncryptPadOAEPFlag,
	)
	runtime.KeepAlive(plaintext)
	runtime.KeepAlive(ciphertext)
	runtime.KeepAlive(padding)
	if ncryptFailed(status) {
		return nil, ncryptStatusError("NCryptEncrypt", status)
	}
	return ciphertext[:size], nil
}

func ncryptDecryptOAEP(key uintptr, ciphertext []byte) ([]byte, error) {
	padding, err := ncryptOAEPInfo()
	if err != nil {
		return nil, err
	}
	defer runtime.KeepAlive(padding)
	var size uint32
	status, _, _ := procNCryptDecrypt.Call(
		key,
		bytesPointer(ciphertext),
		uintptr(len(ciphertext)),
		uintptr(unsafe.Pointer(padding)),
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		ncryptPadOAEPFlag,
	)
	runtime.KeepAlive(ciphertext)
	runtime.KeepAlive(padding)
	if ncryptFailed(status) {
		return nil, ncryptStatusError("NCryptDecrypt(size)", status)
	}
	if size == 0 {
		return nil, errors.New("NCryptDecrypt returned zero output size")
	}
	plaintext := make([]byte, size)
	status, _, _ = procNCryptDecrypt.Call(
		key,
		bytesPointer(ciphertext),
		uintptr(len(ciphertext)),
		uintptr(unsafe.Pointer(padding)),
		bytesPointer(plaintext),
		uintptr(len(plaintext)),
		uintptr(unsafe.Pointer(&size)),
		ncryptPadOAEPFlag,
	)
	runtime.KeepAlive(ciphertext)
	runtime.KeepAlive(plaintext)
	runtime.KeepAlive(padding)
	if ncryptFailed(status) {
		return nil, ncryptStatusError("NCryptDecrypt", status)
	}
	return plaintext[:size], nil
}

func ncryptOAEPInfo() (*bcryptOAEPInfo, error) {
	alg, err := windows.UTF16PtrFromString(ncryptSHA256Algorithm)
	if err != nil {
		return nil, err
	}
	return &bcryptOAEPInfo{algID: alg}, nil
}

func ncryptDeleteKey(key uintptr) error {
	status, _, _ := procNCryptDeleteKey.Call(key, 0)
	if ncryptFailed(status) && !ncryptKeyNotFound(status) {
		return ncryptStatusError("NCryptDeleteKey", status)
	}
	return nil
}

func ncryptFreeObject(handle uintptr) {
	if handle != 0 {
		_, _, _ = procNCryptFreeObject.Call(handle)
	}
}

func bytesPointer(data []byte) uintptr {
	if len(data) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(&data[0]))
}

func ncryptFailed(status uintptr) bool {
	return uint32(status) != ncryptStatusOK
}

func ncryptKeyNotFound(status uintptr) bool {
	code := uint32(status)
	return code == nteNotFound || code == nteBadKeySet
}

func ncryptStatusError(operation string, status uintptr) error {
	return fmt.Errorf("%s failed: SECURITY_STATUS 0x%08x", operation, uint32(status))
}

func shortVaultID(vaultID string) string {
	if len(vaultID) > 8 {
		return vaultID[:8]
	}
	return vaultID
}
