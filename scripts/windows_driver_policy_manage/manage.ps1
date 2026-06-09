<#
.SYNOPSIS
    Manage the "Windows Driver policy" (cross-signed driver Code-Integrity
    enforcement) so a cross-signed test driver can be loaded.

    Simple text menu:
       [1] Status   - show policy state + which .cip files exist
       [2] Remove   - back up + delete the cross-cert policy files (reboot)
       [3] Restore  - copy the backed-up policy files back (reboot)
       [Q] Quit

    Scope: only the two Microsoft cross-certificate policy GUIDs below are
    touched. Unrelated WDAC/lockdown policies are left alone.

    Ref: https://support.microsoft.com/en-us/windows/the-windows-driver-policy-ecd2a78c-750c-415d-93f2-e37302ce0443

.NOTES
    Run elevated (Administrator). Removing the policy lowers system security
    (re-allows legacy cross-signed kernel drivers) and requires a reboot.
    Windows Update may re-provision the policy later.
#>

$ErrorActionPreference = 'Stop'

# ---- Target policies (the "Windows Driver policy" cross-cert exceptions) ----
$TargetGuids = @(
    '8F9CB695-5D48-48D6-A329-7202B44607E3',  # enforcement
    '784C4414-79F4-4C32-A6A5-F0FB42A51D0D'   # audit
)

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackupRoot = Join-Path $ScriptDir 'ci_policy_backup'

# Locations that hold *.cip policy files. "EFI" is resolved at run time to a
# freshly mounted drive letter for the EFI System Partition.
$Sys32Active = Join-Path $env:windir 'System32\CodeIntegrity\CiPolicies\Active'
$EfiRelative = 'EFI\Microsoft\Boot\CiPolicies\Active'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Get-FreeDriveLetter {
    foreach ($c in 90..68) {            # Z .. D
        $l = [char]$c
        if (-not (Test-Path ("{0}:\" -f $l))) { return [string]$l }
    }
    throw 'No free drive letter available to mount the EFI partition.'
}

# Mount the EFI System Partition, run $Action with the mount path, always unmount.
function Use-EfiPartition {
    param([scriptblock]$Action)
    $letter = Get-FreeDriveLetter
    $mounted = $false
    try {
        & mountvol "${letter}:" /s | Out-Null
        $mounted = $true
        $path = "${letter}:\$EfiRelative"
        & $Action $path
    }
    finally {
        if ($mounted) { & mountvol "${letter}:" /d | Out-Null }
    }
}

# Match a file name against any target GUID (case-insensitive, braces optional).
function Test-IsTarget {
    param([string]$Name)
    foreach ($g in $TargetGuids) {
        if ($Name -match [regex]::Escape($g)) { return $true }
    }
    return $false
}

# Files/dirs under System32\CodeIntegrity are owned by TrustedInstaller and
# only grant Administrators read. Take ownership + grant full control so we can
# delete (file) or write into (dir). Uses the locale-independent Administrators
# SID (*S-1-5-32-544).
function Unlock-FsItem {
    param([string]$Path, [switch]$Directory)
    if ($Directory) {
        & takeown.exe /f "$Path" /a            2>&1 | Out-Null
        & icacls.exe  "$Path" /grant '*S-1-5-32-544:(OI)(CI)F' 2>&1 | Out-Null
    } else {
        & takeown.exe /f "$Path"               2>&1 | Out-Null
        & icacls.exe  "$Path" /grant '*S-1-5-32-544:F'         2>&1 | Out-Null
    }
}

# Best-effort revert of Unlock-FsItem: drop the explicit admin grant (restoring
# inherited ACLs) and hand ownership back to TrustedInstaller.
function Restore-FsAcl {
    param([string]$Path)
    & icacls.exe "$Path" /reset                                 2>&1 | Out-Null
    & icacls.exe "$Path" /setowner 'NT SERVICE\TrustedInstaller' 2>&1 | Out-Null
}

function Write-Title {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor DarkGray
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# [1] Status
# ---------------------------------------------------------------------------
function Show-Status {
    Write-Title 'STATUS'

    # System code-integrity related toggles
    try { $sb = Confirm-SecureBootUEFI } catch { $sb = 'unknown' }
    $ts = (& bcdedit /enum '{current}' 2>$null | Select-String -Pattern 'testsigning') -join ' '
    if (-not $ts) { $ts = 'testsigning      Off (default)' }
    Write-Host ("Secure Boot : {0}" -f $sb)
    Write-Host ("Test signing: {0}" -f ($ts.Trim()))

    # Policy enforcement state via CiTool
    Write-Host ''
    Write-Host 'Cross-cert policy enforcement (CiTool):' -ForegroundColor Yellow
    $lines = (& CiTool -lp) -split "`r?`n"
    $cur = @{}
    foreach ($ln in $lines) {
        $t = $ln.Trim()
        if ($t -match '^Policy ID:\s*(.+)$')            { $cur.Id = $matches[1].Trim() }
        elseif ($t -match '^Friendly Name:\s*(.+)$')    { $cur.Name = $matches[1].Trim() }
        elseif ($t -match '^Is Currently Enforced:\s*(.+)$') {
            $cur.Enforced = $matches[1].Trim()
            foreach ($g in $TargetGuids) {
                if ($cur.Id -and ($cur.Id -match [regex]::Escape($g))) {
                    $color = if ($cur.Enforced -eq 'True') { 'Red' } else { 'Green' }
                    Write-Host ("  [{0}] {1}" -f $cur.Enforced, $cur.Name) -ForegroundColor $color
                }
            }
            $cur = @{}
        }
    }

    # Files on disk
    Write-Host ''
    Write-Host 'Policy files present:' -ForegroundColor Yellow
    $any = $false
    Use-EfiPartition {
        param($efi)
        Get-ChildItem (Join-Path $efi '*.cip') -ErrorAction SilentlyContinue | ForEach-Object {
            if (Test-IsTarget $_.Name) {
                Write-Host ("  EFI      : {0}  ({1:N0} bytes)" -f $_.Name, $_.Length)
                $script:any = $true
            }
        }
    }
    Get-ChildItem (Join-Path $Sys32Active '*.cip') -ErrorAction SilentlyContinue | ForEach-Object {
        if (Test-IsTarget $_.Name) {
            Write-Host ("  System32 : {0}  ({1:N0} bytes)" -f $_.Name, $_.Length)
            $any = $true
        }
    }
    if (-not $any) { Write-Host '  (none of the target policy files are present)' -ForegroundColor Green }

    # Backup availability
    Write-Host ''
    if (Test-Path $BackupRoot) {
        $bk = Get-ChildItem $BackupRoot -Recurse -Filter '*.cip' -ErrorAction SilentlyContinue
        Write-Host ("Backup     : {0} file(s) in {1}" -f $bk.Count, $BackupRoot) -ForegroundColor Green
    } else {
        Write-Host 'Backup     : none yet' -ForegroundColor DarkGray
    }
}

# ---------------------------------------------------------------------------
# [2] Remove (backup + delete)
# ---------------------------------------------------------------------------
function Remove-Policy {
    Write-Title 'REMOVE POLICY  (backup + delete, reboot required)'
    Write-Host 'This re-allows legacy cross-signed kernel drivers and LOWERS security.' -ForegroundColor Yellow
    $ans = Read-Host 'Type  YES  to proceed'
    if ($ans -ne 'YES') { Write-Host 'Cancelled.' -ForegroundColor DarkGray; return }

    $script:deleted = 0

    # System32 files (TrustedInstaller-owned: back up, take ownership, delete)
    $dstSys = Join-Path $BackupRoot 'System32'
    New-Item -ItemType Directory -Force -Path $dstSys | Out-Null
    Get-ChildItem (Join-Path $Sys32Active '*.cip') -ErrorAction SilentlyContinue | ForEach-Object {
        if (Test-IsTarget $_.Name) {
            try {
                Copy-Item $_.FullName (Join-Path $dstSys $_.Name) -Force
                Unlock-FsItem $_.FullName
                Remove-Item $_.FullName -Force -ErrorAction Stop
                Write-Host ("  deleted System32 : {0}" -f $_.Name) -ForegroundColor Red
                $script:deleted++
            } catch {
                Write-Host ("  FAILED  System32 : {0} -> {1}" -f $_.Name, $_.Exception.Message) -ForegroundColor Yellow
            }
        }
    }

    # EFI files (FAT32, no ACLs)
    $dstEfi = Join-Path $BackupRoot 'EFI'
    New-Item -ItemType Directory -Force -Path $dstEfi | Out-Null
    Use-EfiPartition {
        param($efi)
        Get-ChildItem (Join-Path $efi '*.cip') -ErrorAction SilentlyContinue | ForEach-Object {
            if (Test-IsTarget $_.Name) {
                try {
                    Copy-Item $_.FullName (Join-Path $dstEfi $_.Name) -Force
                    Remove-Item $_.FullName -Force -ErrorAction Stop
                    Write-Host ("  deleted EFI      : {0}" -f $_.Name) -ForegroundColor Red
                    $script:deleted++
                } catch {
                    Write-Host ("  FAILED  EFI      : {0} -> {1}" -f $_.Name, $_.Exception.Message) -ForegroundColor Yellow
                }
            }
        }
    }

    $deleted = $script:deleted
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'

    "Removed $deleted file(s) at $stamp" | Out-File (Join-Path $BackupRoot 'last_action.txt') -Encoding utf8
    Write-Host ''
    if ($deleted -gt 0) {
        Write-Host ("Done. {0} file(s) backed up to {1} and deleted." -f $deleted, $BackupRoot) -ForegroundColor Green
        Write-Host 'REBOOT required for the change to take effect.' -ForegroundColor Yellow
    } else {
        Write-Host 'Nothing to remove (files already absent).' -ForegroundColor DarkGray
    }
}

# ---------------------------------------------------------------------------
# [3] Restore
# ---------------------------------------------------------------------------
function Restore-Policy {
    Write-Title 'RESTORE POLICY  (from backup, reboot required)'
    if (-not (Test-Path $BackupRoot)) {
        Write-Host 'No backup folder found - nothing to restore.' -ForegroundColor Yellow
        return
    }

    $script:restored = 0

    # System32: directory is TrustedInstaller-owned. Unlock the dir, copy each
    # file back, relock each file, then relock the dir.
    $srcSys = Join-Path $BackupRoot 'System32'
    if (Test-Path $srcSys) {
        $sysFiles = @(Get-ChildItem (Join-Path $srcSys '*.cip') -ErrorAction SilentlyContinue)
        if ($sysFiles.Count -gt 0) {
            Unlock-FsItem $Sys32Active -Directory
            foreach ($f in $sysFiles) {
                $dest = Join-Path $Sys32Active $f.Name
                try {
                    Copy-Item $f.FullName $dest -Force -ErrorAction Stop
                    Restore-FsAcl $dest
                    Write-Host ("  restored System32 : {0}" -f $f.Name) -ForegroundColor Green
                    $script:restored++
                } catch {
                    Write-Host ("  FAILED   System32 : {0} -> {1}" -f $f.Name, $_.Exception.Message) -ForegroundColor Yellow
                }
            }
            Restore-FsAcl $Sys32Active
        }
    }

    # EFI: FAT32, no ACLs.
    $srcEfi = Join-Path $BackupRoot 'EFI'
    if (Test-Path $srcEfi) {
        Use-EfiPartition {
            param($efi)
            New-Item -ItemType Directory -Force -Path $efi | Out-Null
            Get-ChildItem (Join-Path $srcEfi '*.cip') -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    Copy-Item $_.FullName (Join-Path $efi $_.Name) -Force -ErrorAction Stop
                    Write-Host ("  restored EFI      : {0}" -f $_.Name) -ForegroundColor Green
                    $script:restored++
                } catch {
                    Write-Host ("  FAILED   EFI      : {0} -> {1}" -f $_.Name, $_.Exception.Message) -ForegroundColor Yellow
                }
            }
        }
    }

    $restored = $script:restored

    Write-Host ''
    if ($restored -gt 0) {
        Write-Host ("Done. {0} file(s) restored." -f $restored) -ForegroundColor Green
        Write-Host 'REBOOT required for the change to take effect.' -ForegroundColor Yellow
    } else {
        Write-Host 'Backup folder had no .cip files to restore.' -ForegroundColor DarkGray
    }
}

# ---------------------------------------------------------------------------
# Menu loop
# ---------------------------------------------------------------------------
if (-not (Test-Admin)) {
    Write-Host 'ERROR: run this script from an elevated (Administrator) PowerShell.' -ForegroundColor Red
    exit 2
}

$running = $true
while ($running) {
    Write-Host ''
    Write-Host '==================== Windows Driver policy manager ====================' -ForegroundColor Cyan
    Write-Host '  [1] Status   - show policy state + policy files on disk'
    Write-Host '  [2] Remove   - back up + delete cross-cert policy (reboot)'
    Write-Host '  [3] Restore  - copy backed-up policy files back (reboot)'
    Write-Host '  [Q] Quit'
    $raw = Read-Host 'Select'
    if ($null -eq $raw) { break }   # EOF / piped input exhausted
    $choice = $raw.Trim().ToUpper()
    switch ($choice) {
        '1' { Show-Status }
        '2' { Remove-Policy }
        '3' { Restore-Policy }
        'Q' { $running = $false }
        default { Write-Host 'Unknown choice.' -ForegroundColor DarkGray }
    }
}

Write-Host 'Bye.'
