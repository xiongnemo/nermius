package domain

import "time"

type DocumentKind string

const (
	KindHost      DocumentKind = "host"
	KindGroup     DocumentKind = "group"
	KindProfile   DocumentKind = "profile"
	KindIdentity  DocumentKind = "identity"
	KindKey       DocumentKind = "key"
	KindForward   DocumentKind = "forward"
	KindKnownHost DocumentKind = "known_host"
	KindBackend   DocumentKind = "backend"
	KindWorkspace DocumentKind = "workspace"
)

type KnownHostsPolicy string

const (
	KnownHostsStrict    KnownHostsPolicy = "strict"
	KnownHostsAcceptNew KnownHostsPolicy = "accept-new"
	KnownHostsOff       KnownHostsPolicy = "off"
)

type KnownHostsBackend string

const (
	KnownHostsBackendVault     KnownHostsBackend = "vault"
	KnownHostsBackendFile      KnownHostsBackend = "file"
	KnownHostsBackendVaultFile KnownHostsBackend = "vault+file"
	KnownHostsBackendFileVault KnownHostsBackend = "file+vault"
)

type ProxyType string

const (
	ProxySOCKS5 ProxyType = "socks5"
	ProxyHTTP   ProxyType = "http"
)

type ForwardType string

const (
	ForwardLocal   ForwardType = "local"
	ForwardRemote  ForwardType = "remote"
	ForwardDynamic ForwardType = "dynamic"
)

type AuthMethodType string

const (
	AuthMethodPassword AuthMethodType = "password"
	AuthMethodKey      AuthMethodType = "key"
	AuthMethodAgent    AuthMethodType = "agent"
)

type KeyKind string

const (
	KeyKindPrivateKey KeyKind = "private_key"
	KeyKindAgent      KeyKind = "agent"
)

type BackendType string

const (
	BackendTypeTermix BackendType = "termix"
)

type WorkspacePaneType string

const (
	WorkspacePaneEmpty WorkspacePaneType = "empty"
	WorkspacePaneSSH   WorkspacePaneType = "ssh"
)

type WorkspaceSplitAxis string

const (
	WorkspaceSplitHorizontal WorkspaceSplitAxis = "horizontal"
	WorkspaceSplitVertical   WorkspaceSplitAxis = "vertical"
)

type SecretKind string

const (
	SecretKindPassword     SecretKind = "password"
	SecretKindPrivateKey   SecretKind = "private_key"
	SecretKindPassphrase   SecretKind = "passphrase"
	SecretKindProxyAuth    SecretKind = "proxy_password"
	SecretKindBackendToken SecretKind = "backend_token"
)

type Host struct {
	ID               string            `json:"id"`
	Title            string            `json:"title,omitempty"`
	Hostname         string            `json:"hostname"`
	Port             *int              `json:"port,omitempty"`
	Username         *string           `json:"username,omitempty"`
	GroupIDs         []string          `json:"group_ids,omitempty"`
	ProfileIDs       []string          `json:"profile_ids,omitempty"`
	IdentityRef      *string           `json:"identity_ref,omitempty"`
	KeyRef           *string           `json:"key_ref,omitempty"`
	Password         string            `json:"password,omitempty"`
	PasswordSecretID string            `json:"password_secret_id,omitempty"`
	Route            *Route            `json:"route,omitempty"`
	KnownHosts       *KnownHostsConfig `json:"known_hosts,omitempty"`
	ForwardIDs       []string          `json:"forward_ids,omitempty"`
	External         *ExternalRef      `json:"external,omitempty"`
	CreatedAt        time.Time         `json:"created_at,omitempty"`
	UpdatedAt        time.Time         `json:"updated_at,omitempty"`
}

type Group struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	External    *ExternalRef `json:"external,omitempty"`
	CreatedAt   time.Time    `json:"created_at,omitempty"`
	UpdatedAt   time.Time    `json:"updated_at,omitempty"`
}

type Profile struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Port        *int              `json:"port,omitempty"`
	Username    *string           `json:"username,omitempty"`
	IdentityRef *string           `json:"identity_ref,omitempty"`
	Route       *Route            `json:"route,omitempty"`
	KnownHosts  *KnownHostsConfig `json:"known_hosts,omitempty"`
	ForwardIDs  []string          `json:"forward_ids,omitempty"`
	CreatedAt   time.Time         `json:"created_at,omitempty"`
	UpdatedAt   time.Time         `json:"updated_at,omitempty"`
}

type Identity struct {
	ID        string       `json:"id"`
	Name      string       `json:"name"`
	Username  string       `json:"username"`
	Methods   []AuthMethod `json:"methods"`
	External  *ExternalRef `json:"external,omitempty"`
	CreatedAt time.Time    `json:"created_at,omitempty"`
	UpdatedAt time.Time    `json:"updated_at,omitempty"`
}

type AuthMethod struct {
	Type             AuthMethodType `json:"type"`
	Password         string         `json:"password,omitempty"`
	PasswordSecretID string         `json:"password_secret_id,omitempty"`
	KeyID            string         `json:"key_id,omitempty"`
	AgentSocket      string         `json:"agent_socket,omitempty"`
	AgentForward     bool           `json:"agent_forward,omitempty"`
}

type Key struct {
	ID                 string       `json:"id"`
	Name               string       `json:"name"`
	Kind               KeyKind      `json:"kind"`
	SourcePath         string       `json:"source_path,omitempty"`
	PrivateKeyPEM      string       `json:"private_key_pem,omitempty"`
	PrivateKeySecretID string       `json:"private_key_secret_id,omitempty"`
	Passphrase         string       `json:"passphrase,omitempty"`
	PassphraseSecretID string       `json:"passphrase_secret_id,omitempty"`
	AgentSocket        string       `json:"agent_socket,omitempty"`
	External           *ExternalRef `json:"external,omitempty"`
	CreatedAt          time.Time    `json:"created_at,omitempty"`
	UpdatedAt          time.Time    `json:"updated_at,omitempty"`
}

type Forward struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	HostRef     string       `json:"host_ref,omitempty"`
	Type        ForwardType  `json:"type"`
	ListenHost  string       `json:"listen_host,omitempty"`
	ListenPort  int          `json:"listen_port"`
	TargetHost  string       `json:"target_host,omitempty"`
	TargetPort  int          `json:"target_port,omitempty"`
	AutoStart   bool         `json:"auto_start,omitempty"`
	Enabled     bool         `json:"enabled"`
	External    *ExternalRef `json:"external,omitempty"`
	CreatedAt   time.Time    `json:"created_at,omitempty"`
	UpdatedAt   time.Time    `json:"updated_at,omitempty"`
}

type Backend struct {
	ID                 string      `json:"id"`
	Name               string      `json:"name"`
	Type               BackendType `json:"type"`
	URL                string      `json:"url"`
	Token              string      `json:"token,omitempty"`
	TokenSecretID      string      `json:"token_secret_id,omitempty"`
	RemoteUserID       string      `json:"remote_user_id,omitempty"`
	RemoteUser         string      `json:"remote_user,omitempty"`
	InsecureSkipVerify bool        `json:"insecure_skip_verify,omitempty"`
	CAFile             string      `json:"ca_file,omitempty"`
	TargetProfileRef   string      `json:"target_profile_ref,omitempty"`
	LastConnectedAt    *time.Time  `json:"last_connected_at,omitempty"`
	LastSyncAt         *time.Time  `json:"last_sync_at,omitempty"`
	LastSyncError      string      `json:"last_sync_error,omitempty"`
	CreatedAt          time.Time   `json:"created_at,omitempty"`
	UpdatedAt          time.Time   `json:"updated_at,omitempty"`
}

type Workspace struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Root        *WorkspaceNode `json:"root,omitempty"`
	CreatedAt   time.Time      `json:"created_at,omitempty"`
	UpdatedAt   time.Time      `json:"updated_at,omitempty"`
}

type WorkspaceNode struct {
	ID    string          `json:"id,omitempty"`
	Split *WorkspaceSplit `json:"split,omitempty"`
	Pane  *WorkspacePane  `json:"pane,omitempty"`
}

type WorkspaceSplit struct {
	Axis   WorkspaceSplitAxis `json:"axis"`
	Ratio  float64            `json:"ratio"`
	First  *WorkspaceNode     `json:"first,omitempty"`
	Second *WorkspaceNode     `json:"second,omitempty"`
}

type WorkspacePane struct {
	Type    WorkspacePaneType `json:"type"`
	HostRef string            `json:"host_ref,omitempty"`
	Title   string            `json:"title,omitempty"`
}

type ExternalRef struct {
	BackendRef string    `json:"backend_ref"`
	Kind       string    `json:"kind"`
	ID         string    `json:"id"`
	ParentID   string    `json:"parent_id,omitempty"`
	Index      *int      `json:"index,omitempty"`
	UpdatedAt  time.Time `json:"updated_at,omitempty"`
	Checksum   string    `json:"checksum,omitempty"`
	ReadOnly   bool      `json:"read_only,omitempty"`
}

type KnownHostsConfig struct {
	Policy  KnownHostsPolicy  `json:"policy,omitempty"`
	Path    string            `json:"path,omitempty"`
	Backend KnownHostsBackend `json:"backend,omitempty"`
}

type Route struct {
	ProxyJump     []string       `json:"proxy_jump,omitempty"`
	OutboundProxy *OutboundProxy `json:"outbound_proxy,omitempty"`
}

type OutboundProxy struct {
	Type             ProxyType `json:"type"`
	Address          string    `json:"address"`
	Username         string    `json:"username,omitempty"`
	Password         string    `json:"password,omitempty"`
	PasswordSecretID string    `json:"password_secret_id,omitempty"`
}

type KnownHost struct {
	ID                string    `json:"id"`
	Hosts             []string  `json:"hosts"`
	Algorithm         string    `json:"algorithm"`
	PublicKey         string    `json:"public_key"`
	FingerprintSHA256 string    `json:"fingerprint_sha256,omitempty"`
	Source            string    `json:"source,omitempty"`
	CreatedAt         time.Time `json:"created_at,omitempty"`
	UpdatedAt         time.Time `json:"updated_at,omitempty"`
}

func (h Host) Label() string {
	if h.Title != "" {
		return h.Title
	}
	return h.Hostname
}

func (g Group) Label() string { return g.Name }

func (p Profile) Label() string { return p.Name }

func (i Identity) Label() string { return i.Name }

func (k Key) Label() string { return k.Name }

func (f Forward) Label() string { return f.Name }

func (b Backend) Label() string { return b.Name }

func (w Workspace) Label() string { return w.Name }

func (k KnownHost) Label() string {
	host := "<unknown>"
	if len(k.Hosts) > 0 && k.Hosts[0] != "" {
		host = k.Hosts[0]
	}
	if k.Algorithm == "" {
		return host
	}
	return host + " " + k.Algorithm
}
