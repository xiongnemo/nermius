package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

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

func (s *Store) GetMeta(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM vault_metadata WHERE key = ?`, key).Scan(&value)
	return value, err
}

func (s *Store) PutDocument(ctx context.Context, rec DocumentRecord) error {
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

func (s *Store) GetDocument(ctx context.Context, id string) (DocumentRecord, error) {
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

func (s *Store) FindDocumentByLabel(ctx context.Context, kind, label string) (DocumentRecord, error) {
	var rec DocumentRecord
	var createdAt, updatedAt string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, kind, label, body, created_at, updated_at
		FROM documents
		WHERE kind = ? AND label = ?
	`, kind, label).Scan(&rec.ID, &rec.Kind, &rec.Label, &rec.Body, &createdAt, &updatedAt)
	if err != nil {
		return DocumentRecord{}, err
	}
	rec.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	rec.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	return rec, nil
}

func (s *Store) ListDocuments(ctx context.Context, kind string) ([]DocumentSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, kind, label, updated_at
		FROM documents
		WHERE kind = ?
		ORDER BY label ASC
	`, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DocumentSummary{}
	for rows.Next() {
		var rec DocumentSummary
		var updatedAt string
		if err := rows.Scan(&rec.ID, &rec.Kind, &rec.Label, &updatedAt); err != nil {
			return nil, err
		}
		rec.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *Store) AllDocuments(ctx context.Context, kind string) ([]DocumentRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, kind, label, body, created_at, updated_at
		FROM documents
		WHERE kind = ?
		ORDER BY label ASC
	`, kind)
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

func (s *Store) DeleteDocument(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM documents WHERE id = ?`, id)
	return err
}

func (s *Store) PutSecret(ctx context.Context, rec SecretRecord) error {
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

func (s *Store) GetSecret(ctx context.Context, id string) (SecretRecord, error) {
	var rec SecretRecord
	var createdAt, updatedAt string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, kind, wrapped_key_nonce, wrapped_key_ciphertext, payload_nonce, payload_ciphertext, created_at, updated_at
		FROM secrets
		WHERE id = ?
	`, id).Scan(&rec.ID, &rec.Kind, &rec.WrappedKeyNonce, &rec.WrappedKeyCiphertext, &rec.PayloadNonce, &rec.PayloadCiphertext, &createdAt, &updatedAt)
	if err != nil {
		return SecretRecord{}, err
	}
	rec.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	rec.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	return rec, nil
}
