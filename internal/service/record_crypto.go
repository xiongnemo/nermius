package service

import (
	"encoding/json"
	"time"

	"github.com/nermius/nermius/internal/secret"
	"github.com/nermius/nermius/internal/store"
)

type vaultRecordPayload struct {
	Class     store.RecordClass `json:"class"`
	Kind      string            `json:"kind"`
	Label     string            `json:"label,omitempty"`
	Body      []byte            `json:"body,omitempty"`
	CreatedAt time.Time         `json:"created_at,omitempty"`
	UpdatedAt time.Time         `json:"updated_at,omitempty"`
}

func openRecordPayload(key []byte, rec store.EncryptedRecord) (vaultRecordPayload, error) {
	raw, err := secret.OpenEnvelope(key, secret.EnvelopeSecret{
		WrappedKeyNonce:      rec.WrappedKeyNonce,
		WrappedKeyCiphertext: rec.WrappedKeyCiphertext,
		PayloadNonce:         rec.PayloadNonce,
		PayloadCiphertext:    rec.PayloadCiphertext,
	})
	if err != nil {
		return vaultRecordPayload{}, err
	}
	var payload vaultRecordPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return vaultRecordPayload{}, err
	}
	return payload, nil
}

func sealPayloadWithKey(writeKey []byte, id string, payload vaultRecordPayload) (store.EncryptedRecord, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return store.EncryptedRecord{}, err
	}
	env, err := secret.SealEnvelope(writeKey, raw)
	if err != nil {
		return store.EncryptedRecord{}, err
	}
	return store.EncryptedRecord{
		ID:                   id,
		WrappedKeyNonce:      env.WrappedKeyNonce,
		WrappedKeyCiphertext: env.WrappedKeyCiphertext,
		PayloadNonce:         env.PayloadNonce,
		PayloadCiphertext:    env.PayloadCiphertext,
		CreatedAt:            payload.CreatedAt,
		UpdatedAt:            payload.UpdatedAt,
	}, nil
}

func zeroBytes(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
