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
- Termius local export/import via `termius export|import`
- Termix backend registration via `backend termix add|list|show`
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

`nermius version` prints a build string in the form `v{major}.{minor}.{patch}-{branch}-{commit}[-dirty]`.

CI derives the base `v{major}.{minor}.{patch}` from `VERSION`: patch is `VERSION`'s patch plus the number of commits since `VERSION` was last changed. To reset patch for a new major/minor line, edit `VERSION` to the new epoch version, such as `v0.1.0`; that commit builds as `v0.1.0`, and the next commit builds as `v0.1.1`.

## Quick start

```powershell
# 1. Initialize the local encrypted vault.
nermius vault init

# 2. Optionally inspect or enable system keychain enrollment.
nermius vault keychain status
nermius vault keychain enable
nermius vault keychain enable --require-presence

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
nermius forward start prod-db

# 7. Open the TUI for browsing objects and sessions.
nermius tui
```

`import openssh` and the interactive `add -it` flow are alternative ways to populate the vault. Use whichever matches your setup.

If you are moving from Termius Desktop on Windows, export every locally decryptable object before importing the normalized credentials:

```powershell
nermius termius export --out termius-export.json --include-secrets
nermius termius import --file termius-export.json
```

If you have a self-hosted Termix instance, register it as an optional backend and bind future sync imports to a local profile:

```powershell
nermius backend termix add lab --url http://localhost:8080 --token tmx_xxx --profile termix-lab --create-profile
nermius backend termix list
```

Normal read/write commands now auto-unlock:

- first via the enrolled system keychain backend
- otherwise by prompting for the master password

There is no plaintext local session file anymore. On migrated/current vaults, object bodies and secrets are stored in encrypted `records`; legacy vaults must be upgraded explicitly with `nermius vault migrate`.

Inside the TUI object tabs:

- `HOST / GROUP / PROFILE / IDENTITY / KEY / FORWARD / KNOWN-HOST` all support in-screen CRUD modals
- `Enter` connects on `HOST`, toggles the selected tunnel on `FORWARD`, and opens a read-only detail view on every other tab
- `d` opens detail, `e` opens edit, `a` opens a create form
- `Delete` or `x` opens delete confirmation; referenced objects are blocked and show who still depends on them
- `/` opens a filter prompt for the current tab, and `r` reloads the lists
- reference fields use searchable pickers, and ordered lists such as profiles, forwards, known-host host patterns, and identity auth methods use a dedicated list editor
- `FORWARD` objects are reusable `-L`/`-R`/`-D` tunnel definitions with their own Host picker; `Enter` or `Space` starts/stops the selected tunnel for the lifetime of the current TUI process, and the list shows `STATUS` plus a separate `REASON`

Inside the TUI session view:

- connection prompts such as unknown host-key trust, password, username, and key passphrase stay inside the TUI as modals
- connection progress is shown in the status bar while resolving hosts, dialing, checking known hosts, authenticating, and opening the remote shell
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
nermius vault keychain enable --require-presence
nermius vault keychain disable
nermius vault change-password
nermius vault migrate
```

Behavior notes:

- `vault keychain enable` stores the raw vault unlock material in the platform backend when supported.
- by default, enrolled keychain unlocks do not require Windows Hello or another user-presence prompt, which keeps tests and normal commands non-interactive.
- on Windows, `vault keychain enable --require-presence` enrolls a Windows CNG high-protection key instead of the default DPAPI blob. The CNG private key is non-exportable, requires OS-mediated authorization when used, and wraps the vault unlock material with RSA-OAEP-SHA256.
- switching between default keychain enrollment and `--require-presence` re-enrolls the vault and removes the other local keychain blob.
- normal commands auto-try the enrolled keychain backend first, then fall back to the master password.
- `vault keychain status` reports both the unlock-material backend and the user-presence backend.
- on Windows, default unlock material is DPAPI-protected. `--require-presence` moves the protection boundary into Windows CNG, so changing Nermius' SQLite metadata alone cannot silently downgrade the existing strong enrollment into a DPAPI unlock.
- a malicious same-user process may still invoke Nermius or Windows APIs and cause an OS authorization prompt, deny access by deleting local key material, or wait for the user to approve a prompt. The strong mode is meant to prevent silent vault-key unwrap, not to defend against a fully compromised user session.
- current-schema vaults use whole-vault encrypted records, so hostnames, usernames, labels, known-host payloads, and secrets are no longer stored as plaintext rows in SQLite.
- `vault migrate` is explicit and creates a backup at `<vault>.bak.pre-schema-v2` before converting a legacy vault.

### Moving A Vault To Another Machine

The SQLite vault file is portable. The system keychain enrollment is not portable and must be recreated on each machine.

1. On the old machine, find the vault path:

   ```powershell
   nermius vault keychain status
   ```

   The default path is usually `%APPDATA%\nermius\vault.db` on Windows, `~/Library/Application Support/nermius/vault.db` on macOS, and `~/.config/nermius/vault.db` on Linux.

2. Copy `vault.db` to the new machine.

3. On the new machine, either place it at the default path or pass it explicitly:

   ```powershell
   nermius --vault C:\path\to\vault.db vault keychain enable
   ```

4. Enter the master password once to enroll the copied vault into the new machine's keychain.

After that, normal commands can auto-unlock through the new machine's keychain and fall back to the master password if needed.

Notes:

- imported private keys, passwords, identities, profiles, hosts, forwards, and vault-backed known hosts move with `vault.db`.
- agent-backed auth still depends on the new machine's SSH agent.
- external key file paths and `~/.ssh/known_hosts` file-backed entries are local machine state and must exist separately on the new machine.

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

## Termix Backend

`nermius backend termix add` stores a Termix URL plus API token as a local backend document. The token is moved into the encrypted secret store and the saved backend can be bound to a local profile with `--profile`; pass `--create-profile` to create that profile during registration.

```powershell
# Validate /health and /users/me before saving.
nermius backend termix add lab --url https://termix.example.com --token tmx_xxx --profile termix-lab --create-profile

# Save first when networking, reverse proxy, or certificate setup is not ready yet.
nermius backend termix add lab --url http://localhost:8080 --token tmx_xxx --no-validate

nermius backend termix show lab
nermius backend termix list
```

This is the first Termix integration slice: it models the remote backend and the local mapping boundary. Actual pull, seed, and two-way sync commands are intentionally separate future steps. Imported/synced objects will use `external.backend_ref` plus the remote Termix object kind and ID, while `backend.target_profile_ref` keeps Termix-owned hosts grouped under the selected local profile without putting URL or credentials directly in the profile.

## Termius Export And Import

`nermius termius export` reads the local Termius Desktop data directory, decrypts every locally decryptable payload, and writes a bundle with both parsed `raw_objects` and a normalized credentials view. Chromium IndexedDB records are read with an `idb_cmp1`-compatible comparator and decoded object-store metadata, so field-level encrypted values keep their record boundary, Termius table name in `raw_objects[].store_name`, and recoverable field name in `raw_objects[].field`. JSON payloads are parsed as objects or scalar values. Non-JSON decrypted text is still preserved and classified as passwords, passphrases, private keys, public keys, snippet scripts, secret text, or generic text. The bundle also includes a Termius file backup section so data that is not yet understood by Nermius is still preserved.

```powershell
# Inventory only: no decrypted secret values are written.
nermius termius export --out termius-inventory.json

# Full export: includes raw JSON values, the Termius localKey, and base64 copies of Termius data files.
nermius termius export --out termius-export.json --include-secrets

# Maximum fidelity backup: keep raw objects only, even if Nermius does not understand them yet.
nermius termius export --out termius-raw.json --raw-only --include-secrets

# Import normalized credentials into the encrypted Nermius vault.
nermius termius import --file termius-export.json

# Read local Termius and import directly without writing a plaintext bundle.
nermius termius import --from-local --dry-run
nermius termius import --from-local
```

The full export file is sensitive plaintext. Treat it like a password manager export and remove it after importing unless you intentionally keep it as a backup. The `backup` section contains `IndexedDB/file__0.indexeddb.leveldb`, `Local Storage/leveldb`, `Cache/Cache_Data`, `Preferences`, `window-state.json`, and the Termius `localKey` when `--include-secrets` is set.

Current Termius local key reading is implemented only for Windows Credential Manager and looks for the Termius `localKey`. Linux and macOS local Termius export, and `termius import --from-local`, are not supported yet. You can override the Termius data root or pass a specific LevelDB directory with `--source-dir`; the default is `%APPDATA%\Termius` on Windows. Close Termius before exporting for the cleanest backup. If Termius is still running, Nermius copies LevelDB directories to a temporary location before trying to read them.

Import only writes normalized credentials that Nermius can map safely today: hosts, groups, identities, private keys, and passphrases. Export reconstructs these from Termius stores such as `hosts`, `groups`, `tags`, `ssh_identities`, `keys`, and `snippets` using Termius' own encrypted field names. Standalone decrypted secrets without a recovered store and field remain in `raw_objects` as `secret_text` candidates instead of being guessed into password fields. Port forwards, snippets, activity history, known hosts, and unknown Termius objects remain preserved in `raw_objects` and the `backup` section so future import logic can be improved without re-reading Termius.

## Debug Logging

`connect`, `exec`, and `tui` accept a global verbosity flag modeled after `ssh`:

```powershell
nermius -v connect my-host
nermius -vv connect my-host
nermius -vvv exec my-host "uname -a"
```

`-v` prints high-level SSH decisions such as host key acceptance. `-vv` adds host key backend details and preferred host key algorithms. `-vvv` also includes low-level auth method selection.

## Port Forwarding

Saved `FORWARD` objects are standalone tunnels. Each one has a `host_ref`, which is the SSH transport/intermediate host used to establish the tunnel.

```powershell
nermius forward add -it
nermius forward start prod-db
```

`forward start` runs in the foreground and keeps the tunnel open until `Ctrl+C`. If an established tunnel disconnects unexpectedly, Nermius retries up to 5 times before surfacing the final error. TUI `FORWARD` toggles are also process-local; they close when the TUI exits. Saved `Host/Profile.forward_ids` remain visible in resolved config for organization and inspection, but saved forwards no longer auto-start when opening a shell. One-time CLI forwards still work with `connect`/`exec`:

```powershell
nermius connect my-host -L 15432:db.internal:5432
nermius connect my-host -D 1080
```

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

Forward:

```json
{
  "name": "prod-db",
  "host_ref": "host-uuid",
  "type": "local",
  "listen_host": "127.0.0.1",
  "listen_port": 15432,
  "target_host": "db.internal",
  "target_port": 5432,
  "enabled": true
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
