//go:build windows

package termius

import (
	"context"
	"errors"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const credentialTypeGeneric = 1

var (
	advapi32      = windows.NewLazySystemDLL("advapi32.dll")
	procCredReadW = advapi32.NewProc("CredReadW")
	procCredFree  = advapi32.NewProc("CredFree")
)

type windowsLocalKeyReader struct{}

type credentialW struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

func defaultLocalKeyReader() LocalKeyReader {
	return windowsLocalKeyReader{}
}

func (windowsLocalKeyReader) ReadLocalKey(ctx context.Context) (string, error) {
	candidates := []string{
		"Termius/localKey",
		"Termius:localKey",
		"Termius",
	}
	var lastErr error
	for _, target := range candidates {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}
		secret, username, err := readGenericCredential(target)
		if err != nil {
			lastErr = err
			continue
		}
		if target == "Termius" && username != "" && !strings.EqualFold(username, "localKey") {
			continue
		}
		if strings.TrimSpace(secret) != "" {
			return secret, nil
		}
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", errors.New("Termius localKey credential was not found")
}

func readGenericCredential(target string) (string, string, error) {
	targetPtr, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return "", "", err
	}
	var raw *credentialW
	ret, _, callErr := procCredReadW.Call(
		uintptr(unsafe.Pointer(targetPtr)),
		uintptr(credentialTypeGeneric),
		0,
		uintptr(unsafe.Pointer(&raw)),
	)
	if ret == 0 {
		if callErr != windows.ERROR_SUCCESS {
			return "", "", callErr
		}
		return "", "", errors.New("CredReadW returned no credential")
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(raw)))
	secret := credentialBlobString(raw.CredentialBlob, raw.CredentialBlobSize)
	username := utf16PtrString(raw.UserName)
	return secret, username, nil
}

func credentialBlobString(ptr *byte, size uint32) string {
	if ptr == nil || size == 0 {
		return ""
	}
	raw := unsafe.Slice(ptr, size)
	if looksUTF16LE(raw) {
		words := make([]uint16, 0, len(raw)/2)
		for i := 0; i+1 < len(raw); i += 2 {
			word := uint16(raw[i]) | uint16(raw[i+1])<<8
			if word == 0 {
				break
			}
			words = append(words, word)
		}
		return string(utf16.Decode(words))
	}
	return strings.TrimRight(string(raw), "\x00")
}

func looksUTF16LE(raw []byte) bool {
	if len(raw) < 2 || len(raw)%2 != 0 {
		return false
	}
	zeroOdd := 0
	for i := 1; i < len(raw); i += 2 {
		if raw[i] == 0 {
			zeroOdd++
		}
	}
	return zeroOdd >= len(raw)/4
}

func utf16PtrString(ptr *uint16) string {
	if ptr == nil {
		return ""
	}
	return windows.UTF16PtrToString(ptr)
}
