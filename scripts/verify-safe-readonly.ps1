$ErrorActionPreference = "Stop"

Write-Host "== wx-cli Safe Readonly static verification =="

$forbiddenApis = @(
    "WriteProcessMemory",
    "VirtualAllocEx",
    "CreateRemoteThread",
    "SetWindowsHookEx",
    "SendInput"
)

foreach ($term in $forbiddenApis) {
    $hit = Get-ChildItem -Recurse -File src |
        Select-String -SimpleMatch $term -ErrorAction SilentlyContinue
    if ($hit) {
        throw "Forbidden high-intrusion API found: $term"
    }
}

$main = Get-Content "src/main.rs" -Raw
if ($main -notmatch "SAFE_READONLY:\s*bool\s*=\s*true") {
    throw "SAFE_READONLY is not hard-enabled"
}

$cli = Get-Content "src/cli/mod.rs" -Raw
foreach ($needle in @(
    "ensure_safe_command",
    "Commands::Init { force: true",
    "show_secrets: true"
)) {
    if ($cli -notmatch [regex]::Escape($needle)) {
        throw "CLI safety gate missing: $needle"
    }
}

$server = Get-Content "src/daemon/server.rs" -Raw
foreach ($needle in @(
    "crate::SAFE_READONLY",
    "Request::Ping",
    "Request::History",
    "Request::Search",
    "Request::Timeline"
)) {
    if ($server -notmatch [regex]::Escape($needle)) {
        throw "Daemon request whitelist missing: $needle"
    }
}

foreach ($needle in @(
    "security_descriptor",
    "D:P(A;;GA;;;OW)(A;;GA;;;SY)",
    "safe_pipe_security_descriptor"
)) {
    if ($server -notmatch [regex]::Escape($needle)) {
        throw "Windows named-pipe ACL guard missing: $needle"
    }
}

$secrets = Get-Content "src/secret_store.rs" -Raw
foreach ($needle in @(
    "CryptProtectData",
    "CryptUnprotectData",
    "CRYPTPROTECT_UI_FORBIDDEN",
    "wx-cli-dpapi-v1",
    "current-user"
)) {
    if ($secrets -notmatch [regex]::Escape($needle)) {
        throw "DPAPI key-store guard missing: $needle"
    }
}

$cache = Get-Content "src/daemon/cache.rs" -Raw
foreach ($needle in @(
    "crate::SAFE_READONLY",
    "SQLCipher",
    "open_query_conn()",
    "plaintext DB cache path is disabled"
)) {
    if ($cache -notmatch [regex]::Escape($needle)) {
        throw "Plaintext-cache guard missing: $needle"
    }
}

$query = Get-Content "src/daemon/query.rs" -Raw
foreach ($needle in @(
    "open_query_conn",
    "session_last_timestamp",
    "load_names",
    "q_sessions",
    "load_group_nicknames",
    "load_group_nickname_maps",
    "q_members"
)) {
    if ($query -notmatch [regex]::Escape($needle)) {
        throw "Expected readonly query path missing: $needle"
    }
}

Write-Host "PASS: static Safe Readonly guards found."
