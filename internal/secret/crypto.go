package secret

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

type KDFParams struct {
	Salt    []byte `json:"salt"`
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
	KeyLen  uint32 `json:"key_len"`
}

type WrappedVaultKey struct {
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

type EnvelopeSecret struct {
	WrappedKeyNonce      []byte `json:"wrapped_key_nonce"`
	WrappedKeyCiphertext []byte `json:"wrapped_key_ciphertext"`
	PayloadNonce         []byte `json:"payload_nonce"`
	PayloadCiphertext    []byte `json:"payload_ciphertext"`
}

func DefaultKDFParams() KDFParams {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	return KDFParams{
		Salt:    salt,
		Time:    3,
		Memory:  64 * 1024,
		Threads: 4,
		KeyLen:  32,
	}
}

func DeriveKEK(password string, params KDFParams) []byte {
	return argon2.IDKey([]byte(password), params.Salt, params.Time, params.Memory, params.Threads, params.KeyLen)
}

func GenerateVaultKey() ([]byte, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	_, err := rand.Read(key)
	return key, err
}

func WrapVaultKey(kek, vaultKey []byte) (WrappedVaultKey, error) {
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return WrappedVaultKey{}, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return WrappedVaultKey{}, err
	}
	return WrappedVaultKey{
		Nonce:      nonce,
		Ciphertext: aead.Seal(nil, nonce, vaultKey, nil),
	}, nil
}

func UnwrapVaultKey(kek []byte, wrapped WrappedVaultKey) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, err
	}
	out, err := aead.Open(nil, wrapped.Nonce, wrapped.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid password or wrapped key: %w", err)
	}
	return out, nil
}

func SealEnvelope(masterKey, plaintext []byte) (EnvelopeSecret, error) {
	payloadKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(payloadKey); err != nil {
		return EnvelopeSecret{}, err
	}
	payloadAEAD, err := chacha20poly1305.NewX(payloadKey)
	if err != nil {
		return EnvelopeSecret{}, err
	}
	payloadNonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(payloadNonce); err != nil {
		return EnvelopeSecret{}, err
	}
	wrapperAEAD, err := chacha20poly1305.NewX(masterKey)
	if err != nil {
		return EnvelopeSecret{}, err
	}
	wrappedKeyNonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(wrappedKeyNonce); err != nil {
		return EnvelopeSecret{}, err
	}
	return EnvelopeSecret{
		WrappedKeyNonce:      wrappedKeyNonce,
		WrappedKeyCiphertext: wrapperAEAD.Seal(nil, wrappedKeyNonce, payloadKey, nil),
		PayloadNonce:         payloadNonce,
		PayloadCiphertext:    payloadAEAD.Seal(nil, payloadNonce, plaintext, nil),
	}, nil
}

func OpenEnvelope(masterKey []byte, in EnvelopeSecret) ([]byte, error) {
	wrapperAEAD, err := chacha20poly1305.NewX(masterKey)
	if err != nil {
		return nil, err
	}
	payloadKey, err := wrapperAEAD.Open(nil, in.WrappedKeyNonce, in.WrappedKeyCiphertext, nil)
	if err != nil {
		return nil, err
	}
	payloadAEAD, err := chacha20poly1305.NewX(payloadKey)
	if err != nil {
		return nil, err
	}
	return payloadAEAD.Open(nil, in.PayloadNonce, in.PayloadCiphertext, nil)
}

func EncodeJSONBase64[T any](in T) (string, error) {
	raw, err := json.Marshal(in)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

func DecodeJSONBase64[T any](in string, out *T) error {
	raw, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}
