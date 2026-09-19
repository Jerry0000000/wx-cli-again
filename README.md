# wx-cli Safe Readonly

> A deliberately reduced, local-only fork of wx-cli for querying **your own** WeChat 4.x local data with a smaller technical attack surface.

This repository is a safety-focused derivative of `jackwener/wx-cli-again`, based on upstream commit
`077a54cbfe679bda963cd038d8440422907fc797`.

## What this fork changes

The project is intentionally **not** a WeChat automation framework.

It keeps one initial key-acquisition step and then limits normal operation to encrypted, read-only local database access.

### Allowed

- `wx init` — first-time key acquisition only
- `wx sessions`
- `wx history`
- `wx search`
- `wx contacts`
- `wx members`
- `wx stats`
- `wx timeline`
- `wx export`
- `wx doctor`
- `wx key list` — preview only; full secrets are blocked
- `wx daemon status|stop|logs`

### Blocked by code

- `wx init --force`
- `wx key extract`
- `wx key set`
- `wx key list --show-secrets`
- attachments / image extraction
- media export
- unread / new-messages / watch
- Favorites
- Moments / SNS
- official-account article helpers
- daemon config reload and other non-whitelisted IPC requests

## Read-only database model

Normal queries use SQLCipher directly against the original encrypted database with:

```text
SQLITE_OPEN_READ_ONLY
PRAGMA query_only = ON
```

If this encrypted read-only path fails, Safe Readonly **fails closed**.

It does **not** fall back to a plaintext full-database cache. On daemon startup, stale plaintext DB cache files left by older builds are removed.

On Windows, `all_keys.json` is stored as a current-user **DPAPI** envelope. The raw SQLCipher keys are not left as plaintext at rest. Legacy plaintext key files are automatically migrated on first successful read. The DPAPI blob is intended to be decryptable only by the same Windows user on the same machine.

The Windows daemon named pipe is created with a protected DACL granting access to the pipe owner and LocalSystem, rather than relying on the broader default named-pipe ACL.

## WeChat process interaction

On Windows, first-time `wx init` still needs to locate `Weixin.exe` and read process memory to recover the local SQLCipher keys.

Normal whitelisted query commands are designed not to re-open `Weixin.exe` for memory scanning.

The attachment/V2-image path that would otherwise scan Weixin memory again is blocked in this fork.

This reduces technical interaction with WeChat; it does **not** mean Tencent has approved this tool, and it is not a guarantee against future client-side detection or account-policy enforcement.

## Build

Requirements:

- Rust stable
- WeChat 4.x local data belonging to you
- Windows: Administrator privileges may be required for the first `wx init`

```powershell
git clone https://github.com/Jerry0000000/wx-cli-again.git
cd wx-cli-again
git checkout safe-readonly
cargo build --release
.\target\release\wx.exe --version
```

After the safe branch is merged, `git checkout safe-readonly` is no longer necessary.

## Basic use

```powershell
# First setup only
.\target\release\wx.exe init

# Routine local read-only queries
.\target\release\wx.exe doctor
.\target\release\wx.exe sessions
.\target\release\wx.exe history "工作群" -n 100
.\target\release\wx.exe search "K1+730" --json
```

Do not upload `all_keys.json`, WeChat databases, decrypted exports, or real chat content to GitHub.

## Security verification

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\verify-safe-readonly.ps1
cargo check
```

See [SAFE_READONLY.md](SAFE_READONLY.md) for the threat model and hard boundaries.

### Windows local-secret hardening

- current-user DPAPI protects the key store at rest
- legacy plaintext key stores are migrated automatically
- the daemon named pipe uses an explicit owner/System ACL
- no `Everyone` or anonymous ACE is intentionally granted

## Scope

This project is intended only for local analysis of data that the user owns or is authorized to access. It must not be used for unauthorized access to another person's device, account, messages, or keys.

## License and attribution

Apache License 2.0. The original license is retained.

See [NOTICE](NOTICE) for derivative-work attribution.
