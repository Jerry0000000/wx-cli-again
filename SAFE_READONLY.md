# Safe Readonly security model

## Goal

Reduce wx-cli to a narrow local-data reader:

```text
Weixin.exe
   |
   | first init only: PROCESS_VM_READ / ReadProcessMemory
   v
local SQLCipher keys
   |
   v
encrypted WeChat DB -- SQLCipher READ_ONLY --> wx-cli --> stdout / explicit export
```

## Hard boundaries

1. No WeChat message sending.
2. No input simulation.
3. No DLL injection.
4. No remote-thread creation.
5. No WeChat-memory writes.
6. No WeChat-database writes.
7. No attachment/V2-image secondary memory scan in normal safe operation.
8. No plaintext full-database cache.
9. Daemon IPC is a whitelist, not an open dispatcher.
10. Full key display and key mutation commands are blocked.

## Initial key acquisition

Safe Readonly still permits one first-time `wx init`.

On Windows this uses the upstream scanner's:

- `OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)`
- `VirtualQueryEx`
- `ReadProcessMemory`

That interaction is the irreducible part of the current design. It is not equivalent to official API access.

Repeated process-memory extraction is intentionally blocked by the CLI safety gate.

## Encrypted DB access

Allowed queries call `DbCache::open_query_conn()`.

The connection is opened with:

- `SQLITE_OPEN_READ_ONLY`
- `SQLITE_OPEN_NO_MUTEX`
- SQLCipher raw key
- `PRAGMA query_only = ON`

If online SQLCipher open fails, the process returns an error. It does not fall back to full plaintext decryption.

## Plaintext cache handling

At daemon startup in Safe Readonly mode:

- old files under the wx-cli cache directory are removed;
- persistent plaintext-cache metadata is not loaded;
- `DbCache::get()` and `get_with_mode()` refuse to materialize plaintext database files.

User-requested exports are still allowed because their output location is explicit and intentional.

## Disabled feature groups

The following remain in the source tree for upstream traceability but are unreachable through the Safe Readonly CLI and rejected by the daemon request whitelist:

- unread/new-message polling
- watch mode
- Favorites
- SNS/Moments
- official-account article helpers
- attachment extraction
- media extraction
- key re-extraction / key mutation

## Windows key protection

On Windows, the key document is serialized, protected with `CryptProtectData` in **current-user scope**, and stored inside a small JSON envelope. `CRYPTPROTECT_LOCAL_MACHINE` is intentionally not used.

This means the ciphertext is tied to the Windows user profile/credentials and normally to the same machine. A legacy plaintext key file is migrated to DPAPI on its first successful read.

## Windows local IPC ACL

The daemon named pipe is created with a protected DACL based on:

```text
D:P(A;;GA;;;OW)(A;;GA;;;SY)
```

That grants full pipe access to the object owner and LocalSystem, without deliberately granting `Everyone`, anonymous users, or the generic built-in Users group.

Administrators can still take ownership or otherwise override local OS security. This is a same-host user-isolation control, not a boundary against a machine administrator.

## What this does not promise

Safe Readonly reduces technical surface. It does not assert compliance with Tencent's platform rules and does not guarantee that future anti-tamper or anti-debug logic cannot detect the initial memory-read step.
