package termius

import "encoding/json"

const (
	SourceName          = "termius"
	BundleFormatVersion = 1
)

type ExportOptions struct {
	SourceDir      string
	IncludeSecrets bool
	RawOnly        bool
}

type Bundle struct {
	Source        string      `json:"source"`
	FormatVersion int         `json:"format_version"`
	Stats         Stats       `json:"stats"`
	ScanDirs      []string    `json:"scan_dirs,omitempty"`
	Backup        *FileBackup `json:"backup,omitempty"`
	RawObjects    []RawObject `json:"raw_objects"`
	Normalized    Normalized  `json:"normalized,omitempty"`
}

type Stats struct {
	EncryptedBlobs int `json:"encrypted_blobs"`
	DecryptedBlobs int `json:"decrypted_blobs"`
	JSONPayloads   int `json:"json_payloads"`
	TextPayloads   int `json:"text_payloads,omitempty"`
	JSONObjects    int `json:"json_objects"`
	JSONArrayItems int `json:"json_array_items,omitempty"`
	UnknownObjects int `json:"unknown_objects"`
}

type RawObject struct {
	Hash          string          `json:"hash"`
	SourceFile    string          `json:"source_file,omitempty"`
	StoreName     string          `json:"store_name,omitempty"`
	Type          string          `json:"type"`
	Field         string          `json:"field,omitempty"`
	ContextFields []string        `json:"context_fields,omitempty"`
	JSONPath      string          `json:"json_path,omitempty"`
	Fields        []string        `json:"fields,omitempty"`
	Value         json.RawMessage `json:"value,omitempty"`
}

type FileBackup struct {
	IncludesContents bool         `json:"includes_contents"`
	LocalKey         string       `json:"local_key,omitempty"`
	Files            []BackupFile `json:"files"`
}

type BackupFile struct {
	Path          string `json:"path"`
	Size          int64  `json:"size"`
	SHA256        string `json:"sha256"`
	ContentBase64 string `json:"content_base64,omitempty"`
}

type Normalized struct {
	Hosts       []Host       `json:"hosts,omitempty"`
	Groups      []Group      `json:"groups,omitempty"`
	Identities  []Identity   `json:"identities,omitempty"`
	Keys        []Key        `json:"keys,omitempty"`
	Forwards    []Forward    `json:"forwards,omitempty"`
	Snippets    []Snippet    `json:"snippets,omitempty"`
	Passwords   []Password   `json:"passwords,omitempty"`
	UnknownRefs []UnknownRef `json:"unknown_refs,omitempty"`
}

type Host struct {
	TermiusID  string   `json:"termius_id,omitempty"`
	RawHash    string   `json:"raw_hash,omitempty"`
	Label      string   `json:"label,omitempty"`
	Host       string   `json:"host"`
	Port       int      `json:"port,omitempty"`
	Username   string   `json:"username,omitempty"`
	Password   string   `json:"password,omitempty"`
	KeyID      string   `json:"key_id,omitempty"`
	KeyName    string   `json:"key_name,omitempty"`
	OS         string   `json:"os,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	GroupNames []string `json:"group_names,omitempty"`
}

type Group struct {
	TermiusID string `json:"termius_id,omitempty"`
	RawHash   string `json:"raw_hash,omitempty"`
	Name      string `json:"name"`
}

type Identity struct {
	TermiusID string `json:"termius_id,omitempty"`
	RawHash   string `json:"raw_hash,omitempty"`
	Name      string `json:"name,omitempty"`
	Username  string `json:"username,omitempty"`
	Password  string `json:"password,omitempty"`
}

type Key struct {
	TermiusID     string `json:"termius_id,omitempty"`
	RawHash       string `json:"raw_hash,omitempty"`
	Name          string `json:"name"`
	PrivateKeyPEM string `json:"private_key_pem,omitempty"`
	Passphrase    string `json:"passphrase,omitempty"`
	Fingerprint   string `json:"fingerprint,omitempty"`
	PublicKey     string `json:"public_key,omitempty"`
}

type Snippet struct {
	TermiusID string `json:"termius_id,omitempty"`
	RawHash   string `json:"raw_hash,omitempty"`
	Label     string `json:"label"`
	Script    string `json:"script,omitempty"`
}

type Password struct {
	RawHash    string `json:"raw_hash,omitempty"`
	SourceFile string `json:"source_file,omitempty"`
	Field      string `json:"field,omitempty"`
	Label      string `json:"label,omitempty"`
	Value      string `json:"value,omitempty"`
}

type Forward struct {
	TermiusID  string `json:"termius_id,omitempty"`
	RawHash    string `json:"raw_hash,omitempty"`
	Name       string `json:"name,omitempty"`
	HostID     string `json:"host_id,omitempty"`
	HostName   string `json:"host_name,omitempty"`
	Type       string `json:"type,omitempty"`
	ListenHost string `json:"listen_host,omitempty"`
	ListenPort int    `json:"listen_port,omitempty"`
	TargetHost string `json:"target_host,omitempty"`
	TargetPort int    `json:"target_port,omitempty"`
}

type UnknownRef struct {
	RawHash string   `json:"raw_hash"`
	Type    string   `json:"type"`
	Fields  []string `json:"fields,omitempty"`
}

type EncryptedBlob struct {
	Value         string
	SourceFile    string
	StoreName     string
	Field         string
	ContextFields []string
}

type DecryptedObject struct {
	Hash          string
	SourceFile    string
	StoreName     string
	Field         string
	ContextFields []string
	Plaintext     []byte
}
