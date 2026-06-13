package termius

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/nacl/secretbox"
)

const (
	termiusEncryptedVersion = 4
	termiusHeaderSize       = 2
	secretboxKeySize        = 32
	secretboxNonceSize      = 24
)

func DecodeLocalKey(encoded string) ([]byte, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, errors.New("Termius localKey is empty")
	}
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode Termius localKey: %w", err)
	}
	if len(key) != secretboxKeySize {
		return nil, fmt.Errorf("Termius localKey must decode to %d bytes, got %d", secretboxKeySize, len(key))
	}
	return key, nil
}

func DecryptBlob(encoded string, key []byte) ([]byte, bool) {
	if len(key) != secretboxKeySize {
		return nil, false
	}
	data, err := decodeBase64Candidate(encoded)
	if err != nil {
		return nil, false
	}
	if len(data) < termiusHeaderSize+secretboxNonceSize+secretbox.Overhead || data[0] != termiusEncryptedVersion {
		return nil, false
	}
	var fixedKey [secretboxKeySize]byte
	var nonce [secretboxNonceSize]byte
	copy(fixedKey[:], key)
	copy(nonce[:], data[termiusHeaderSize:termiusHeaderSize+secretboxNonceSize])
	ciphertext := data[termiusHeaderSize+secretboxNonceSize:]
	plaintext, ok := secretbox.Open(nil, ciphertext, &nonce, &fixedKey)
	return plaintext, ok
}

func decodeBase64Candidate(encoded string) ([]byte, error) {
	encoded = strings.TrimSpace(encoded)
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	var lastErr error
	for _, encoding := range encodings {
		data, err := encoding.DecodeString(encoded)
		if err == nil {
			return data, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func DecryptBlobs(blobs []EncryptedBlob, key []byte) []DecryptedObject {
	out := []DecryptedObject{}
	for _, blob := range blobs {
		plaintext, ok := DecryptBlob(blob.Value, key)
		if !ok {
			continue
		}
		out = append(out, DecryptedObject{
			Hash:          hashBlob(blob.Value),
			SourceFile:    blob.SourceFile,
			StoreName:     blob.StoreName,
			Field:         blob.Field,
			ContextFields: blob.ContextFields,
			Plaintext:     plaintext,
		})
	}
	return out
}
