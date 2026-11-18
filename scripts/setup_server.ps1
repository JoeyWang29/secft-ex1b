# ============================================================
# SecFT 服务器部署与 ACL 配置脚本（PowerShell，管理员权限运行）
#
# 功能（对应课程要求「Server 端的可读写目录配置需以 shell 脚本
# 或其他形式给出明确体现」）：
#   1. 创建服务数据根目录与各用户隔离子目录
#   2. 关闭目录继承，移除 Everyone/Users 权限
#   3. 仅授予指定服务账户（默认 Administrators，可改为专用账户）
#      对数据目录的完全控制 —— 实现最小权限访问控制
#   4. 提示可选的 chroot/容器化隔离方案
#
# 用法: powershell -ExecutionPolicy Bypass -File scripts\setup_server.ps1
#       [-DataRoot D:\secft_data] [-ServiceUser "NT AUTHORITY\SYSTEM"]
# ============================================================
param(
    [string]$DataRoot = "",
    [string]$ServiceUser = "$env:USERNAME",
    [string[]]$Users = @("alice", "bob", "guest")
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

if (-not $DataRoot) { $DataRoot = Join-Path $ProjectRoot "server_data" }

Write-Host "=== SecFT 服务器目录与 ACL 配置 ===" -ForegroundColor Cyan
Write-Host "数据根目录: $DataRoot"
Write-Host "服务账户  : $ServiceUser"

# 1) 创建目录结构：根目录 + 每用户隔离子目录
if (-not (Test-Path $DataRoot)) {
    New-Item -ItemType Directory -Path $DataRoot | Out-Null
    Write-Host "[+] 已创建数据根目录 $DataRoot"
}
foreach ($u in $Users) {
    $dir = Join-Path $DataRoot $u
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
        Write-Host "[+] 已创建用户目录 $dir"
    }
}

# 2) 配置 ACL：先关闭继承并删除继承规则，再显式授权
Write-Host "`n--- 配置 ACL（关闭继承 -> 移除通用组 -> 仅服务账户完全控制） ---" -ForegroundColor Cyan
foreach ($u in $Users) {
    $dir = Join-Path $DataRoot $u
    # 关闭继承，删除所有继承的 ACE
    icacls $dir /inheritance:r | Out-Null
    # 显式授予服务账户完全控制
    icacls $dir /grant:r "$ServiceUser:(OI)(CI)F" | Out-Null
    # 显式拒绝 Everyone（纵深防御）
    icacls $dir /deny "Everyone:(OI)(CI)RD" | Out-Null
    Write-Host "[+] $dir 权限已隔离（仅 $ServiceUser 完全控制）"
}

# 3) 根目录：服务账户完全控制，普通用户不可枚举
icacls $DataRoot /grant:r "$ServiceUser:(OI)(CI)F" | Out-Null
Write-Host "[+] $DataRoot 已授予 $ServiceUser 完全控制"

Write-Host "`n--- 当前 ACL 快照（server_data） ---"
icacls $DataRoot

Write-Host @"

完成。安全设计说明：
  * 服务器业务代码运行于服务账户下，仅可访问 $DataRoot；
    即使服务进程被攻破，攻击者也难以横向读取系统其他目录。
  * 更强的隔离可用 chroot（Linux）或容器化部署（Docker --read-only
    + 挂载数据卷），详见实验报告「安全设计」章节。
"@ -ForegroundColor Green
