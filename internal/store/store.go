package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	_ "modernc.org/sqlite"
)

const CurrentSchemaVersion = "2"

type Store struct {
	db *sql.DB
}

type RecordClass string

const (
	RecordClassDocument RecordClass = "document"
	RecordClassSecret   RecordClass = "secret"
)

type DocumentRecord struct {
	ID        string
	Kind      string
	Label     string
	Body      []byte
	CreatedAt time.Time
	UpdatedAt time.Time
}

type DocumentSummary struct {
	ID        string
	Kind      string
	Label     string
	UpdatedAt time.Time
}

type SecretRecord struct {
	ID        string
	Kind      string
	Payload   []byte
	CreatedAt time.Time
	UpdatedAt time.Time
}

type EncryptedRecord struct {
	ID                   string
	WrappedKeyNonce      []byte
	WrappedKeyCiphertext []byte
	PayloadNonce         []byte
	PayloadCiphertext    []byte
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type LegacySecretRecord struct {
	ID                   string
	Kind                 string
	WrappedKeyNonce      []byte
	WrappedKeyCiphertext []byte
	PayloadNonce         []byte
	PayloadCiphertext    []byte
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) Migrate(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS vault_metadata (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS records (
			id TEXT PRIMARY KEY,
			wrapped_key_nonce BLOB NOT NULL,
			wrapped_key_ciphertext BLOB NOT NULL,
			payload_nonce BLOB NOT NULL,
			payload_ciphertext BLOB NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		// Legacy schema retained only as an explicit migration source.
		`CREATE TABLE IF NOT EXISTS documents (
			id TEXT PRIMARY KEY,
			kind TEXT NOT NULL,
			label TEXT NOT NULL,
			body BLOB NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_documents_kind_label ON documents(kind, label);`,
		`CREATE TABLE IF NOT EXISTS secrets (
			id TEXT PRIMARY KEY,
			kind TEXT NOT NULL,
			wrapped_key_nonce BLOB NOT NULL,
			wrapped_key_ciphertext BLOB NOT NULL,
			payload_nonce BLOB NOT NULL,
			payload_ciphertext BLOB NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) IsInitialized(ctx context.Context) (bool, error) {
	_, err := s.GetMeta(ctx, "vault.kdf")
	if err == nil {
		return true, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return false, err
}

func (s *Store) SetMeta(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO vault_metadata(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, key, value)
	return err
}

func (s *Store) DeleteMeta(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM vault_metadata WHERE key = ?`, key)
	return err
}

func (s *Store) GetMeta(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM vault_metadata WHERE key = ?`, key).Scan(&value)
	return value, err
}

func (s *Store) PutRecord(ctx context.Context, rec EncryptedRecord) error {
	now := time.Now().UTC()
	createdAt := rec.CreatedAt
	if createdAt.IsZero() {
		createdAt = now
	}
	updatedAt := rec.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = now
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO records(id, wrapped_key_nonce, wrapped_key_ciphertext, payload_nonce, payload_ciphertext, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			wrapped_key_nonce = excluded.wrapped_key_nonce,
			wrapped_key_ciphertext = excluded.wrapped_key_ciphertext,
			payload_nonce = excluded.payload_nonce,
			payload_ciphertext = excluded.payload_ciphertext,
			updated_at = excluded.updated_at
	`, rec.ID, rec.WrappedKeyNonce, rec.WrappedKeyCiphertext, rec.PayloadNonce, rec.PayloadCiphertext, createdAt.Format(time.RFC3339Nano), updatedAt.Format(time.RFC3339Nano))
	return err
}

func (s *Store) GetRecord(ctx context.Context, id string) (EncryptedRecord, error) {
	var rec EncryptedRecord
	var createdAt, updatedAt string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, wrapped_key_nonce, wrapped_key_ciphertext, payload_nonce, payload_ciphertext, created_at, updated_at
		FROM records
		WHERE id = ?
	`, id).Scan(&rec.ID, &rec.WrappedKeyNonce, &rec.WrappedKeyCiphertext, &rec.PayloadNonce, &rec.PayloadCiphertext, &createdAt, &updatedAt)
	if err != nil {
		return EncryptedRecord{}, err
	}
	rec.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	rec.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	return rec, nil
}

func (s *Store) ListRecords(ctx context.Context) ([]EncryptedRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, wrapped_key_nonce, wrapped_key_ciphertext, payload_nonce, payload_ciphertext, created_at, updated_at
		FROM records
		ORDER BY id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EncryptedRecord{}
	for rows.Next() {
		var rec EncryptedRecord
		var createdAt, updatedAt string
		if err := rows.Scan(&rec.ID, &rec.WrappedKeyNonce, &rec.WrappedKeyCiphertext, &rec.PayloadNonce, &rec.PayloadCiphertext, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		rec.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
		rec.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *Store) DeleteRecord(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM records WHERE id = ?`, id)
	return err
}

func (s *Store) ListLegacyDocuments(ctx context.Context) ([]DocumentRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, kind, label, body, created_at, updated_at
		FROM documents
		ORDER BY label ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DocumentRecord{}
	for rows.Next() {
		var rec DocumentRecord
		var createdAt, updatedAt string
		if err := rows.Scan(&rec.ID, &rec.Kind, &rec.Label, &rec.Body, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		rec.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
		rec.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *Store) GetLegacyDocument(ctx context.Context, id string) (DocumentRecord, error) {
	var rec DocumentRecord
	var createdAt, updatedAt string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, kind, label, body, created_at, updated_at
		FROM documents
		WHERE id = ?
	`, id).Scan(&rec.ID, &rec.Kind, &rec.Label, &rec.Body, &createdAt, &updatedAt)
	if err != nil {
		return DocumentRecord{}, err
	}
	rec.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	rec.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	return rec, nil
}

func (s *Store) PutLegacyDocument(ctx context.Context, rec DocumentRecord) error {
	now := time.Now().UTC()
	createdAt := rec.CreatedAt
	if createdAt.IsZero() {
		createdAt = now
	}
	updatedAt := rec.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = now
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO documents(id, kind, label, body, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			kind = excluded.kind,
			label = excluded.label,
			body = excluded.body,
			updated_at = excluded.updated_at
	`, rec.ID, rec.Kind, rec.Label, rec.Body, createdAt.Format(time.RFC3339Nano), updatedAt.Format(time.RFC3339Nano))
	return err
}

func (s *Store) ListLegacySecrets(ctx context.Context) ([]LegacySecretRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, kind, wrapped_key_nonce, wrapped_key_ciphertext, payload_nonce, payload_ciphertext, created_at, updated_at
		FROM secrets
		ORDER BY id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LegacySecretRecord{}
	for rows.Next() {
		var rec LegacySecretRecord
		var createdAt, updatedAt string
		if err := rows.Scan(&rec.ID, &rec.Kind, &rec.WrappedKeyNonce, &rec.WrappedKeyCiphertext, &rec.PayloadNonce, &rec.PayloadCiphertext, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		rec.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
		rec.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *Store) GetLegacySecret(ctx context.Context, id string) (LegacySecretRecord, error) {
	var rec LegacySecretRecord
	var createdAt, updatedAt string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, kind, wrapped_key_nonce, wrapped_key_ciphertext, payload_nonce, payload_ciphertext, created_at, updated_at
		FROM secrets
		WHERE id = ?
	`, id).Scan(&rec.ID, &rec.Kind, &rec.WrappedKeyNonce, &rec.WrappedKeyCiphertext, &rec.PayloadNonce, &rec.PayloadCiphertext, &createdAt, &updatedAt)
	if err != nil {
		return LegacySecretRecord{}, err
	}
	rec.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	rec.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	return rec, nil
}

func (s *Store) PutLegacySecret(ctx context.Context, rec LegacySecretRecord) error {
	now := time.Now().UTC()
	createdAt := rec.CreatedAt
	if createdAt.IsZero() {
		createdAt = now
	}
	updatedAt := rec.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = now
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO secrets(id, kind, wrapped_key_nonce, wrapped_key_ciphertext, payload_nonce, payload_ciphertext, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			kind = excluded.kind,
			wrapped_key_nonce = excluded.wrapped_key_nonce,
			wrapped_key_ciphertext = excluded.wrapped_key_ciphertext,
			payload_nonce = excluded.payload_nonce,
			payload_ciphertext = excluded.payload_ciphertext,
			updated_at = excluded.updated_at
	`, rec.ID, rec.Kind, rec.WrappedKeyNonce, rec.WrappedKeyCiphertext, rec.PayloadNonce, rec.PayloadCiphertext, createdAt.Format(time.RFC3339Nano), updatedAt.Format(time.RFC3339Nano))
	return err
}

func (s *Store) LegacyDataPresent(ctx context.Context) (bool, error) {
	for _, table := range []string{"documents", "secrets"} {
		var count int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM `+table).Scan(&count); err != nil {
			return false, err
		}
		if count > 0 {
			return true, nil
		}
	}
	return false, nil
}

func (s *Store) ClearLegacyData(ctx context.Context) error {
	for _, stmt := range []string{
		`DELETE FROM documents`,
		`DELETE FROM secrets`,
	} {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Vacuum(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `VACUUM`)
	return err
}
