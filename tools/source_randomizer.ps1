#Requires -Version 7.0
<#
.SYNOPSIS
    Source-level mutation engine for nanahira
    Randomizes identifiers in protocol.h before compilation
    Source: https://github.com/Kiy0w0/kernel-mmi

.DESCRIPTION
    Mutates shared memory names, magic values, and pool tags
    so every build produces different machine code.
    Original values are backed up and can be restored.
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("mutate", "restore")]
    [string]$Action = "mutate"
)

$ErrorActionPreference = "Stop"

# Paths
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
$ProtocolH = Join-Path $ProjectRoot "shared\protocol.h"
$BackupFile = Join-Path $ProjectRoot "shared\protocol.h.bak"

# ─────────────────────────────────────────────────────────
# Random generators
# ─────────────────────────────────────────────────────────

function New-RandomString {
    param([int]$Length = 8)
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $first = $chars[(Get-Random -Maximum $chars.Length)]
    $rest = -join ((1..($Length-1)) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
    return "$first$rest"
}

function New-RandomHex32 {
    $bytes = [byte[]]::new(4)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    return "0x" + [BitConverter]::ToString($bytes).Replace("-","")
}

function New-RandomPoolTag {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $tag = -join ((1..4) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
    return "'$tag'"
}

# ─────────────────────────────────────────────────────────
# Main logic
# ─────────────────────────────────────────────────────────

if ($Action -eq "restore") {
    if (Test-Path $BackupFile) {
        Copy-Item $BackupFile $ProtocolH -Force
        Remove-Item $BackupFile -Force
        Write-Host "  [+] protocol.h restored from backup" -ForegroundColor Green
    } else {
        Write-Host "  [!] No backup found — nothing to restore" -ForegroundColor Yellow
    }
    exit 0
}

# ── Mutate ──

if (-not (Test-Path $ProtocolH)) {
    Write-Host "  [x] protocol.h not found at: $ProtocolH" -ForegroundColor Red
    exit 1
}

# Backup original
Copy-Item $ProtocolH $BackupFile -Force
Write-Host "  [+] Backed up protocol.h" -ForegroundColor Cyan

# Read content
$content = Get-Content $ProtocolH -Raw

# Generate random values
$newSectionName = New-RandomString -Length 10
$newMagic = New-RandomHex32
$newPoolTag = New-RandomPoolTag

Write-Host ""
Write-Host "  Mutations:" -ForegroundColor White
Write-Host "  ──────────────────────────────────────────" -ForegroundColor DarkGray

# 1. Shared memory section name (kernel-mode)
$oldKmPattern = '(L"\\\\BaseNamedObjects\\\\Global\\\\)[^"]*(")'
$newKmValue = "`${1}$newSectionName`${2}"
if ($content -match $oldKmPattern) {
    $content = $content -replace $oldKmPattern, $newKmValue
    Write-Host "  [~] KM Section  : $newSectionName" -ForegroundColor Magenta
}

# 2. Shared memory section name (user-mode)
$oldUmPattern = '("Global\\\\)[^"]*(")'
$newUmValue = "`${1}$newSectionName`${2}"
if ($content -match $oldUmPattern) {
    $content = $content -replace $oldUmPattern, $newUmValue
    Write-Host "  [~] UM Section  : $newSectionName" -ForegroundColor Magenta
}

# 3. Magic handshake value
$oldMagicPattern = '(#define\s+PROTO_MAGIC\s+)0x[0-9A-Fa-f]+'
$newMagicValue = "`${1}$newMagic"
if ($content -match $oldMagicPattern) {
    $content = $content -replace $oldMagicPattern, $newMagicValue
    Write-Host "  [~] Magic       : $newMagic" -ForegroundColor Magenta
}

# 4. Pool tag
$oldPoolPattern = "(#define\s+DRV_POOL_TAG\s+)'[^']+'"
$newPoolValue = "`${1}$newPoolTag"
if ($content -match $oldPoolPattern) {
    $content = $content -replace $oldPoolPattern, $newPoolValue
    Write-Host "  [~] Pool Tag    : $newPoolTag" -ForegroundColor Magenta
}

# Write mutated content
Set-Content $ProtocolH $content -NoNewline
Write-Host ""
Write-Host "  [+] Source mutation complete — 4 values randomized" -ForegroundColor Green
Write-Host ""
