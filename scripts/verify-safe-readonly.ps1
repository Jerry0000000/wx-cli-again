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
    "禁止 --force",
    "禁止输出完整数据库密钥",
    "此命令已禁用"
)) {
    if ($cli -notmatch [regex]::Escape($needle)) {
        throw "CLI safety gate missing: $needle"
    }
}

$server = Get-Content "src/daemon/server.rs" -Raw
if ($server -notmatch [regex]::Escape("daemon 拒绝该请求")) {
    throw "Daemon request whitelist missing"
}

$cache = Get-Content "src/daemon/cache.rs" -Raw
foreach ($needle in @(
    "拒绝回退到明文解密缓存",
    "plaintext DB cache path is disabled",
    "禁止生成或读取明文数据库缓存"
)) {
    if ($cache -notmatch [regex]::Escape($needle)) {
        throw "Plaintext-cache guard missing: $needle"
    }
}

$query = Get-Content "src/daemon/query.rs" -Raw
$allowedFns = @(
    "session_last_timestamp",
    "load_names",
    "q_sessions",
    "load_group_nicknames",
    "load_group_nickname_maps",
    "q_members"
)
foreach ($fn in $allowedFns) {
    if ($query -notmatch $fn) {
        throw "Expected query function missing: $fn"
    }
}

Write-Host "PASS: static Safe Readonly guards found."
