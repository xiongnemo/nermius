package secret

import "testing"

func TestWrapAndUnwrapVaultKey(t *testing.T) {
	params := DefaultKDFParams()
	kek := DeriveKEK("hunter2", params)
	vaultKey, err := GenerateVaultKey()
	if err != nil {
		t.Fatalf("GenerateVaultKey failed: %v", err)
	}
	wrapped, err := WrapVaultKey(kek, vaultKey)
	if err != nil {
		t.Fatalf("WrapVaultKey failed: %v", err)
	}
	unwrapped, err := UnwrapVaultKey(kek, wrapped)
	if err != nil {
		t.Fatalf("UnwrapVaultKey failed: %v", err)
	}
	if string(unwrapped) != string(vaultKey) {
		t.Fatalf("unwrapped key does not match original")
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	masterKey, err := GenerateVaultKey()
	if err != nil {
		t.Fatalf("GenerateVaultKey failed: %v", err)
	}
	payload := []byte("super-secret")
	encrypted, err := SealEnvelope(masterKey, payload)
	if err != nil {
		t.Fatalf("SealEnvelope failed: %v", err)
	}
	opened, err := OpenEnvelope(masterKey, encrypted)
	if err != nil {
		t.Fatalf("OpenEnvelope failed: %v", err)
	}
	if string(opened) != string(payload) {
		t.Fatalf("unexpected plaintext: %q", string(opened))
	}
}
