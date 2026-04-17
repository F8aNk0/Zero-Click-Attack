#requires -RunAsAdministrator
<#
Defensive file arrival monitor for Windows
- Watches selected paths
- Scores new/changed files
- Scans file with Microsoft Defender
- Checks Authenticode + Zone.Identifier
- Pulls recent Sysmon context
- Quarantines high-score files
- Writes JSON lines log

Run:
powershell -ExecutionPolicy Bypass -File .\ZeroClick-Guard.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -------------------------
# Config
# -------------------------
$Config = @{
    WatchPaths = @(
        "$env:USERPROFILE\Downloads",
        "$env:TEMP",
        "$env:LOCALAPPDATA\Temp",
        "C:\Users\Public\Downloads"
    )

    QuarantinePath     = "C:\ZeroClickGuard\Quarantine"
    LogDirectory       = "C:\ZeroClickGuard\Logs"
    JsonLogPath        = "C:\ZeroClickGuard\Logs\events.jsonl"
    MinSecondsBetweenSameFile = 8
    QuarantineThreshold = 40
    ScanTimeoutSeconds  = 20

    HighRiskExtensions = @(
        ".exe",".dll",".js",".jse",".vbs",".vbe",".ps1",".bat",".cmd",
        ".hta",".scr",".msi",".lnk",".iso",".img",".zip",".rar",".7z",
        ".chm",".cpl",".jar"
    )

    SuspiciousPathRegexes = @(
        "\\AppData\\Local\\Temp\\",
        "\\ProgramData\\",
        "\\Users\\Public\\",
        "\\Start Menu\\Programs\\Startup\\",
        "\\Windows\\Temp\\"
    )

    InterestingProcesses = @(
        "outlook.exe","teams.exe","msedge.exe","chrome.exe","firefox.exe",
        "onedrive.exe","explorer.exe","powershell.exe","pwsh.exe","wscript.exe",
        "cscript.exe","rundll32.exe","regsvr32.exe","mshta.exe"
    )
}

# -------------------------
# Bootstrap
# -------------------------
New-Item -ItemType Directory -Force -Path $Config.QuarantinePath | Out-Null
New-Item -ItemType Directory -Force -Path $Config.LogDirectory | Out-Null

$script:Seen = @{}  # path -> datetime
$script:Watchers = @()
$script:Subscriptions = @()

# -------------------------
# Helpers
# -------------------------
function Write-JsonLog {
    param([hashtable]$Record)

    $Record["timestamp"] = (Get-Date).ToString("o")
    $json = $Record | ConvertTo-Json -Depth 6 -Compress
    Add-Content -Path $Config.JsonLogPath -Value $json
}

function Get-SafeHash {
    param([string]$Path)
    try {
        (Get-FileHash -Path $Path -Algorithm SHA256).Hash
    } catch {
        "HASH_ERROR"
    }
}

function Get-ZoneIdentifierInfo {
    param([string]$Path)

    $result = @{
        present = $false
        zoneId = $null
        raw = $null
    }

    try {
        $stream = Get-Content -Path $Path -Stream Zone.Identifier -ErrorAction Stop
        $result.present = $true
        $result.raw = ($stream -join "`n")
        foreach ($line in $stream) {
            if ($line -match "^ZoneId=(\d+)$") {
                $result.zoneId = [int]$matches[1]
                break
            }
        }
    } catch {
        # no ADS or not supported
    }

    return $result
}

function Get-AuthenticodeSummary {
    param([string]$Path)

    $result = @{
        status = "Unknown"
        signer = $null
        isOSBinary = $false
    }

    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path
        $result.status = [string]$sig.Status
        if ($sig.SignerCertificate) {
            $result.signer = $sig.SignerCertificate.Subject
        }
        if ($sig.IsOSBinary) {
            $result.isOSBinary = $true
        }
    } catch {
        $result.status = "SignatureCheckError"
    }

    return $result
}

function Start-DefenderCustomScan {
    param([string]$Path)

    $result = @{
        attempted = $false
        success = $false
        error = $null
    }

    try {
        $result.attempted = $true
        Start-MpScan -ScanPath $Path -ScanType CustomScan
        $result.success = $true
    } catch {
        $result.error = $_.Exception.Message
    }

    return $result
}

function Get-RecentDefenderThreats {
    param([datetime]$Since)

    $result = @()
    try {
        $all = Get-MpThreatDetection
        foreach ($item in $all) {
            if ($item -and $item.InitialDetectionTime -and ([datetime]$item.InitialDetectionTime -ge $Since)) {
                $result += [pscustomobject]@{
                    ThreatName = $item.ThreatName
                    ActionSuccess = $item.ActionSuccess
                    Resources = $item.Resources
                    InitialDetectionTime = $item.InitialDetectionTime
                }
            }
        }
    } catch {
        # ignore if not available
    }
    return $result
}

function Get-RecentSysmonContext {
    param(
        [datetime]$Since,
        [int]$MaxEvents = 30
    )

    $context = @{
        processCreate = @()
        networkConnect = @()
    }

    try {
        $procEvents = Get-WinEvent -FilterHashtable @{
            LogName = "Microsoft-Windows-Sysmon/Operational"
            Id = 1
            StartTime = $Since
        } -ErrorAction Stop | Select-Object -First $MaxEvents

        foreach ($evt in $procEvents) {
            $xml = [xml]$evt.ToXml()
            $fields = @{}
            foreach ($d in $xml.Event.EventData.Data) {
                $fields[$d.Name] = $d.'#text'
            }

            $imageName = [System.IO.Path]::GetFileName(($fields["Image"] | ForEach-Object { $_ }))
            if ($Config.InterestingProcesses -contains ($imageName.ToLowerInvariant())) {
                $context.processCreate += [pscustomobject]@{
                    TimeCreated = $evt.TimeCreated.ToString("o")
                    Image = $fields["Image"]
                    CommandLine = $fields["CommandLine"]
                    ParentImage = $fields["ParentImage"]
                    User = $fields["User"]
                    ProcessGuid = $fields["ProcessGuid"]
                }
            }
        }
    } catch {
        $context.processCreate += [pscustomobject]@{ error = "Sysmon process events unavailable: $($_.Exception.Message)" }
    }

    try {
        $netEvents = Get-WinEvent -FilterHashtable @{
            LogName = "Microsoft-Windows-Sysmon/Operational"
            Id = 3
            StartTime = $Since
        } -ErrorAction Stop | Select-Object -First $MaxEvents

        foreach ($evt in $netEvents) {
            $xml = [xml]$evt.ToXml()
            $fields = @{}
            foreach ($d in $xml.Event.EventData.Data) {
                $fields[$d.Name] = $d.'#text'
            }

            $imageName = [System.IO.Path]::GetFileName(($fields["Image"] | ForEach-Object { $_ }))
            if ($Config.InterestingProcesses -contains ($imageName.ToLowerInvariant())) {
                $context.networkConnect += [pscustomobject]@{
                    TimeCreated = $evt.TimeCreated.ToString("o")
                    Image = $fields["Image"]
                    User = $fields["User"]
                    DestinationIp = $fields["DestinationIp"]
                    DestinationPort = $fields["DestinationPort"]
                    Protocol = $fields["Protocol"]
                    Initiated = $fields["Initiated"]
                }
            }
        }
    } catch {
        $context.networkConnect += [pscustomobject]@{ error = "Sysmon network events unavailable: $($_.Exception.Message)" }
    }

    return $context
}

function Score-File {
    param(
        [string]$Path,
        [System.IO.FileInfo]$Item,
        [hashtable]$ZoneInfo,
        [hashtable]$SigInfo
    )

    $reasons = New-Object System.Collections.Generic.List[string]
    $score = 0

    $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()

    if ($Config.HighRiskExtensions -contains $ext) {
        $score += 35
        $reasons.Add("high_risk_extension:$ext")
    }

    foreach ($rx in $Config.SuspiciousPathRegexes) {
        if ($Path -match $rx) {
            $score += 15
            $reasons.Add("suspicious_path")
            break
        }
    }

    if ($Item.Length -eq 0) {
        $score += 10
        $reasons.Add("zero_byte")
    }

    if ($Item.Length -gt 50MB) {
        $score += 10
        $reasons.Add("large_file")
    }

    if ($ZoneInfo.present -and $ZoneInfo.zoneId -ge 3) {
        $score += 15
        $reasons.Add("mark_of_the_web")
    }

    switch ($SigInfo.status) {
        "Valid" {
            $score -= 20
            $reasons.Add("valid_signature")
        }
        "NotSigned" {
            $score += 20
            $reasons.Add("unsigned")
        }
        "HashMismatch" {
            $score += 30
            $reasons.Add("signature_hash_mismatch")
        }
        default {
            if ($SigInfo.status -ne "Unknown") {
                $score += 10
                $reasons.Add("signature_status:$($SigInfo.status)")
            }
        }
    }

    if ($SigInfo.isOSBinary) {
        $score -= 25
        $reasons.Add("os_binary")
    }

    if ($score -lt 0) { $score = 0 }
    if ($score -gt 100) { $score = 100 }

    return @{
        score = $score
        reasons = $reasons
    }
}

function Move-ToQuarantine {
    param([string]$Path)

    $name = [System.IO.Path]::GetFileName($Path)
    $dest = Join-Path $Config.QuarantinePath ("{0}_{1}" -f (Get-Date -Format "yyyyMMdd_HHmmss"), $name)

    Move-Item -Path $Path -Destination $dest -Force
    return $dest
}

function Should-ProcessFileNow {
    param([string]$Path)

    $now = Get-Date
    if ($script:Seen.ContainsKey($Path)) {
        $delta = ($now - $script:Seen[$Path]).TotalSeconds
        if ($delta -lt $Config.MinSecondsBetweenSameFile) {
            return $false
        }
    }
    $script:Seen[$Path] = $now
    return $true
}

function Analyze-File {
    param([string]$Path)

    Start-Sleep -Milliseconds 900

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    if (-not (Should-ProcessFileNow -Path $Path)) {
        return
    }

    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item.PSIsContainer) {
        return
    }

    $hash = Get-SafeHash -Path $Path
    $zone = Get-ZoneIdentifierInfo -Path $Path
    $sig  = Get-AuthenticodeSummary -Path $Path
    $scoreResult = Score-File -Path $Path -Item $item -ZoneInfo $zone -SigInfo $sig

    $defenderScan = Start-DefenderCustomScan -Path $Path
    Start-Sleep -Seconds 2
    $recentThreats = Get-RecentDefenderThreats -Since ((Get-Date).AddMinutes(-5))
    $sysmonContext = Get-RecentSysmonContext -Since ((Get-Date).AddMinutes(-2))

    $quarantined = $false
    $quarantinePath = $null

    if ($scoreResult.score -ge $Config.QuarantineThreshold) {
        try {
            $quarantinePath = Move-ToQuarantine -Path $Path
            $quarantined = $true
        } catch {
            # keep logging even if move fails
        }
    }

    $record = @{
        event = "file_observed"
        original_path = $Path
        quarantined = $quarantined
        quarantine_path = $quarantinePath
        sha256 = $hash
        size = $item.Length
        extension = [System.IO.Path]::GetExtension($Path)
        creation_time = $item.CreationTimeUtc.ToString("o")
        last_write_time = $item.LastWriteTimeUtc.ToString("o")
        score = $scoreResult.score
        reasons = @($scoreResult.reasons)
        zone = $zone
        signature = $sig
        defender_scan = $defenderScan
        defender_recent_threats = $recentThreats
        sysmon_context = $sysmonContext
    }

    Write-JsonLog -Record $record
    Write-Host ("[{0}] score={1} quarantined={2} file={3}" -f (Get-Date -Format "HH:mm:ss"), $scoreResult.score, $quarantined, $Path)
}

function Start-PathWatcher {
    param([string]$WatchPath)

    if (-not (Test-Path -LiteralPath $WatchPath)) {
        Write-Host "Skip missing path: $WatchPath"
        return
    }

    $fsw = New-Object System.IO.FileSystemWatcher
    $fsw.Path = $WatchPath
    $fsw.Filter = "*.*"
    $fsw.IncludeSubdirectories = $true
    $fsw.EnableRaisingEvents = $true

    $sub1 = Register-ObjectEvent -InputObject $fsw -EventName Created -Action {
        try { Analyze-File -Path $Event.SourceEventArgs.FullPath } catch {}
    }
    $sub2 = Register-ObjectEvent -InputObject $fsw -EventName Changed -Action {
        try { Analyze-File -Path $Event.SourceEventArgs.FullPath } catch {}
    }
    $sub3 = Register-ObjectEvent -InputObject $fsw -EventName Renamed -Action {
        try { Analyze-File -Path $Event.SourceEventArgs.FullPath } catch {}
    }

    $script:Watchers += $fsw
    $script:Subscriptions += @($sub1, $sub2, $sub3)

    Write-Host "Watching: $WatchPath"
}

function Stop-AllWatchers {
    foreach ($s in $script:Subscriptions) {
        try { Unregister-Event -SourceIdentifier $s.Name -ErrorAction SilentlyContinue } catch {}
    }
    foreach ($w in $script:Watchers) {
        try { $w.EnableRaisingEvents = $false; $w.Dispose() } catch {}
    }
}

# -------------------------
# Main
# -------------------------
Write-Host "ZeroClick Guard starting..."
Write-Host "JSON log: $($Config.JsonLogPath)"
Write-Host "Quarantine: $($Config.QuarantinePath)"

foreach ($path in $Config.WatchPaths) {
    Start-PathWatcher -WatchPath $path
}

try {
    while ($true) {
        Start-Sleep -Seconds 3
    }
}
finally {
    Stop-AllWatchers
}