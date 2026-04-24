# nermius

Portable SSH manager with a local encrypted SQLite vault, a Cobra CLI, and a tcell TUI.

## Current scope

- Local-first vault lifecycle: `vault init|keychain enable|keychain disable|keychain status|migrate|change-password`
- Build metadata reporting with `version`
- Self-install command: `install [--dir PATH]`
- CRUD for `host`, `group`, `profile`, `identity`, `key`, `forward`
- Saved host key inspection with `known-host list|delete`
- Resolved host inspection with `inspect <host>`
- OpenSSH import via `import openssh --config ~/.ssh/config`
- Host-level direct key/password auth overrides
- SSH connect flow with:
  - password, private key, and ssh-agent auth
  - built-in known-host storage in the vault by default, with optional file fallback
  - `ProxyJump` chains
  - outbound `SOCKS5` / `HTTP CONNECT` proxies
  - saved and one-shot `-L/-R/-D` forwards
  - SSH-style debug verbosity via `-v`, `-vv`, `-vvv`
  - remote command execution via `exec <host> <command>`
- TUI CRUD tabs for `host`, `group`, `profile`, `identity`, `key`, `forward`, `known-host`, plus embedded SSH session tabs

## Build

```powershell
$env:GOPROXY='https://goproxy.cn,direct'
go test ./...
go build ./...
```

`nermius version` prints a build string in the form `v{major}.{minor}.{patch}-{branch}-{commit}[-dirty]`. The current base version is `v0.0.1`.

## Quick start

```powershell
# 1. Initialize the local encrypted vault.
nermius vault init

# 2. Optionally inspect or enable system keychain enrollment.
nermius vault keychain status
nermius vault keychain enable

# 3. Optionally install the current binary into ~/.local/bin.
nermius install

# 4A. If you already have ~/.ssh/config, import it into the vault.
nermius import openssh --config ~/.ssh/config

# 4B. Or create records interactively instead of importing.
nermius key add -it
nermius identity add -it
nermius host add -it
nermius host add --title prod --hostname prod.example.com --identity ops --key deploy-key

# 5. Inspect the resolved host config before connecting.
nermius host list
nermius inspect my-host
nermius known-host list
nermius version

# 6. Open a shell or run a one-shot remote command.
nermius connect my-host
nermius -vv connect my-host
nermius exec my-host hostname

# 7. Open the TUI for browsing objects and sessions.
nermius tui
```

`import openssh` and the interactive `add -it` flow are alternative ways to populate the vault. Use whichever matches your setup.

Normal read/write commands now auto-unlock:

- first via the enrolled system keychain backend
- otherwise by prompting for the master password

There is no plaintext local session file anymore. On migrated/current vaults, object bodies and secrets are stored in encrypted `records`; legacy vaults must be upgraded explicitly with `nermius vault migrate`.

Inside the TUI object tabs:

- `HOST / GROUP / PROFILE / IDENTITY / KEY / FORWARD / KNOWN-HOST` all support in-screen CRUD modals
- `Enter` connects on `HOST`, but opens a read-only detail view on every other tab
- `d` opens detail, `e` opens edit, `a` opens a create form
- `Delete` or `x` opens delete confirmation; referenced objects are blocked and show who still depends on them
- `/` opens a filter prompt for the current tab, and `r` reloads the lists
- reference fields use searchable pickers, and ordered lists such as profiles, forwards, known-host host patterns, and identity auth methods use a dedicated list editor

Inside the TUI session view:

- connection prompts such as unknown host-key trust, password, username, and key passphrase stay inside the TUI as modals
- connection progress is shown in the status bar while resolving hosts, dialing, checking known hosts, authenticating, starting forwards, and opening the remote shell
- use the mouse wheel to scroll local shell history
- use `Shift+wheel` to force local scrollback when the remote app has mouse tracking enabled
- drag to select visible terminal text, including locally scrolled shell history
- use `Shift+drag` to force local selection when the remote app has mouse tracking enabled
- use `Ctrl+Shift+C` and `Ctrl+Shift+V` for local copy/paste
- alt-screen apps stay isolated from local shell scrollback
- remote `OSC 52`, focus reporting, bracketed paste, and cursor-shape changes are forwarded when the remote app enables them

Typical interactive path:

```powershell
nermius vault init
nermius vault keychain status
nermius key add -it
nermius identity add -it
nermius host add -it
nermius inspect my-host
nermius known-host list
nermius connect my-host
```

If you created a vault with an older Nermius build, migrate it once before using regular commands:

```powershell
nermius vault migrate
```

Host records can also pin how host keys are stored and read:

```powershell
# Keep host keys entirely inside the encrypted vault.
nermius host add --title prod --hostname prod.example.com --identity ops --known-hosts-backend vault

# Read from the vault first, then fall back to ~/.ssh/known_hosts.
nermius host add --title prod --hostname prod.example.com --identity ops --known-hosts strict --known-hosts-backend vault+file
```

Hosts can also override the selected identity's auth methods directly:

```powershell
# Reuse the identity username, but force this host to try a specific key first.
nermius host add --title prod --hostname prod.example.com --identity ops --key deploy-key

# Attach a host-specific password override.
nermius host add --title breakglass --hostname prod.example.com --identity ops --password super-secret
```

## Install

```powershell
nermius install
nermius install --dir ~/bin
nermius install --yes
```

`install` copies the currently running executable into `~/.local/bin` by default.

- If the target directory does not exist, it asks whether to create it.
- It reports whether that directory is already present in `PATH`.
- If a file with the same name already exists there, it compares size plus `SHA-256` and `SHA-512` before deciding whether a copy is needed.
- If the install directory is not reachable from `PATH`, it prints a shell-specific hint for adding it.

## Vault Security

`vault init` still bootstraps the vault with a master password. That master password derives a KEK which wraps the random `vaultKey`; the `vaultKey` is what encrypts the actual vault records.

Useful vault commands:

```powershell
nermius vault keychain status
nermius vault keychain enable
nermius vault keychain disable
nermius vault change-password
nermius vault migrate
```

Behavior notes:

- `vault keychain enable` stores the raw vault unlock material in the platform backend when supported.
- normal commands auto-try the enrolled keychain backend first, then fall back to the master password.
- `vault keychain status` reports both the unlock-material backend and the user-presence backend.
- on Windows, unlock material is DPAPI-protected, while read/write authorization uses Windows Hello when available, then the Windows credential prompt, then the master password fallback.
- current-schema vaults use whole-vault encrypted records, so hostnames, usernames, labels, known-host payloads, and secrets are no longer stored as plaintext rows in SQLite.
- `vault migrate` is explicit and creates a backup at `<vault>.bak.pre-schema-v2` before converting a legacy vault.

## Known Hosts

`nermius` no longer depends on the system `ssh` client for host key storage. By default, resolved hosts use `known_hosts.backend = vault+file`, which means:

- existing host keys are looked up in the vault first
- then `~/.ssh/known_hosts` is checked as a fallback
- newly accepted keys are written back into the vault

Useful commands:

```powershell
# Inspect all saved host keys from both backends.
nermius known-host list

# Only inspect the vault-backed host keys.
nermius known-host list --source vault

# Remove one host key by host, fingerprint, or file:<line> ID.
nermius known-host delete 192.168.1.202
```

You can override storage per host or profile through the `known_hosts` object:

```json
{
  "policy": "strict",
  "backend": "vault",
  "path": "~/.ssh/known_hosts"
}
```

Use `backend: "vault"` if you want the host to stay fully self-contained on machines that do not even have OpenSSH installed.

## Debug Logging

`connect`, `exec`, and `tui` accept a global verbosity flag modeled after `ssh`:

```powershell
nermius -v connect my-host
nermius -vv connect my-host
nermius -vvv exec my-host "uname -a"
```

`-v` prints high-level SSH decisions such as host key acceptance. `-vv` adds host key backend details and preferred host key algorithms. `-vvv` also includes low-level auth method selection.

## JSON examples

Host:

```json
{
  "title": "prod",
  "hostname": "prod.example.com",
  "profile_ids": ["profile-uuid"],
  "identity_ref": "identity-uuid",
  "key_ref": "key-uuid",
  "password": "super-secret",
  "forward_ids": ["forward-uuid"]
}
```

Identity:

```json
{
  "name": "ops",
  "username": "ubuntu",
  "methods": [
    {
      "type": "key",
      "key_id": "key-uuid"
    },
    {
      "type": "agent"
    }
  ]
}
```
