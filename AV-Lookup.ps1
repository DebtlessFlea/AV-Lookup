#Requires -Version 5.1
<#
.SYNOPSIS
    AV-Lookup v2.0 - detects antivirus / endpoint protection on the local PC.

.DESCRIPTION
    1. Queries Windows Security Center (root\SecurityCenter2). Only products that
       register themselves as AV are listed, so VPN clients, installers, leftover
       folders etc. cannot cause false positives. Reports real state
       (On/Off/Snoozed/Expired) and whether signatures are up to date.
    2. Adds Microsoft Defender details (running mode, real-time protection,
       signature age) via Get-MpComputerStatus.
    3. Fallback for Windows Server (no Security Center) and for EDR agents that
       don't register there: checks for known *running services*.

.PARAMETER Json
    Output machine-readable JSON instead of the formatted report.

.PARAMETER NoPause
    Don't wait for a key press at the end.
#>
[CmdletBinding()]
param(
    [switch]$Json,
    [switch]$NoPause
)

$ErrorActionPreference = 'SilentlyContinue'

# ---------------------------------------------------------------- helpers ---
function ConvertFrom-ProductState {
    param([uint32]$State)
    $status = ($State -shr 12) -band 0xF
    $sig    = ($State -shr 4)  -band 0xF
    [pscustomobject]@{
        State              = switch ($status) { 0 {'Off'} 1 {'On'} 2 {'Snoozed'} 3 {'Expired'} default {'Unknown'} }
        SignaturesUpToDate = ($sig -eq 0)
    }
}

# Known products detectable by service name (wildcards allowed).
# Match = keyword used to avoid listing a product twice.
$knownServices = @(
    @{ Name='Microsoft Defender Antivirus'; Match='Defender'; Type='Antivirus'; Services=@('WinDefend') }
    @{ Name='Microsoft Defender for Endpoint'; Match='for Endpoint'; Type='EDR'; Services=@('Sense') }
    @{ Name='ESET';               Match='ESET';        Type='Antivirus'; Services=@('ekrn') }
    @{ Name='Kaspersky';          Match='Kaspersky';   Type='Antivirus'; Services=@('AVP*','kavfs','klnagent') }
    @{ Name='Bitdefender';        Match='Bitdefender'; Type='Antivirus'; Services=@('vsserv','EPSecurityService','EPProtectedService') }
    @{ Name='Norton';             Match='Norton';      Type='Antivirus'; Services=@('NortonSecurity','N360','Norton*') }
    @{ Name='McAfee / Trellix';   Match='McAfee';      Type='Antivirus'; Services=@('mfevtp','mfemms','McShield','mfefire','masvc') }
    @{ Name='Avast';              Match='Avast';       Type='Antivirus'; Services=@('avast*','AvastSvc') }
    @{ Name='AVG';                Match='AVG';         Type='Antivirus'; Services=@('AVG*','avgsvc') }
    @{ Name='Avira';              Match='Avira';       Type='Antivirus'; Services=@('AntiVirService','Avira*') }
    @{ Name='Sophos';             Match='Sophos';      Type='Antivirus'; Services=@('Sophos*','SAVService','hmpalertsvc') }
    @{ Name='Trend Micro';        Match='Trend';       Type='Antivirus'; Services=@('ntrtscan','TmListen','TMBMServer','Amsp') }
    @{ Name='Webroot';            Match='Webroot';     Type='Antivirus'; Services=@('WRSVC') }
    @{ Name='Malwarebytes';       Match='Malwarebytes';Type='Antivirus'; Services=@('MBAMService') }
    @{ Name='F-Secure / WithSecure'; Match='Secure';   Type='Antivirus'; Services=@('F-Secure*','FSMA','WithSecure*') }
    @{ Name='Panda / WatchGuard'; Match='Panda';       Type='Antivirus'; Services=@('PSANHost','PandaAetherAgent') }
    @{ Name='Comodo';             Match='Comodo';      Type='Antivirus'; Services=@('cmdagent') }
    @{ Name='ZoneAlarm';          Match='ZoneAlarm';   Type='Antivirus'; Services=@('ZAPrivacyService','vsmon') }
    @{ Name='Symantec Endpoint Protection'; Match='Symantec'; Type='Antivirus'; Services=@('SepMasterService','SmcService') }
    @{ Name='CrowdStrike Falcon'; Match='CrowdStrike'; Type='EDR'; Services=@('CSFalconService') }
    @{ Name='SentinelOne';        Match='Sentinel';    Type='EDR'; Services=@('SentinelAgent','SentinelStaticEngine') }
    @{ Name='VMware Carbon Black';Match='Carbon';      Type='EDR'; Services=@('CbDefense','CarbonBlack*','Parity') }
    @{ Name='Cortex XDR';         Match='Cortex';      Type='EDR'; Services=@('cyserver','CortexXDR*') }
    @{ Name='Cylance';            Match='Cylance';     Type='EDR'; Services=@('CylanceSvc') }
    @{ Name='Elastic Endpoint';   Match='Elastic';     Type='EDR'; Services=@('ElasticEndpoint') }
)

$results = New-Object System.Collections.Generic.List[object]

# ------------------------------------------- 1) Windows Security Center ---
$scError = $null
try {
    $scProducts = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop
    foreach ($p in $scProducts) {
        $d = ConvertFrom-ProductState -State ([uint32]$p.productState)
        $results.Add([pscustomobject]@{
            Name               = $p.displayName
            Type               = 'Antivirus'
            Source             = 'Security Center'
            State              = $d.State
            SignaturesUpToDate = $d.SignaturesUpToDate
            Details            = $p.pathToSignedProductExe
        })
    }
} catch {
    $scError = $_.Exception.Message   # normal on Windows Server
}

# ----------------------------------------- 2) Defender extra information ---
$mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
$defenderInfo = $null
if ($mp) {
    $defenderInfo = [pscustomobject]@{
        RunningMode        = $mp.AMRunningMode
        RealTimeProtection = $mp.RealTimeProtectionEnabled
        SignatureAgeDays   = $mp.AntivirusSignatureAge
        SignatureVersion   = $mp.AntivirusSignatureVersion
    }
    foreach ($r in $results) {
        if ($r.Name -like '*Defender*') {
            $r.Details = "Mode: $($mp.AMRunningMode); real-time: $($mp.RealTimeProtectionEnabled); signature age: $($mp.AntivirusSignatureAge) d"
        }
    }
}

# ------------------------------- 3) Service-based fallback / EDR detection ---
$services = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
            Select-Object Name, DisplayName, State

foreach ($k in $knownServices) {
    # Already reported by Security Center? Skip duplicate.
    $dup = $false
    foreach ($r in $results) { if ($r.Name -like "*$($k.Match)*") { $dup = $true; break } }
    if ($dup) { continue }

    $hit = $null
    foreach ($svc in $services) {
        foreach ($pattern in $k.Services) {
            if ($svc.Name -like $pattern) { $hit = $svc; break }
        }
        if ($hit) { break }
    }
    if ($hit -and $hit.State -eq 'Running') {
        $detail = "Service: $($hit.Name)"
        if ($k.Match -eq 'Defender' -and $defenderInfo) {
            $detail = "Mode: $($defenderInfo.RunningMode); real-time: $($defenderInfo.RealTimeProtection); signature age: $($defenderInfo.SignatureAgeDays) d"
        }
        $results.Add([pscustomobject]@{
            Name               = $k.Name
            Type               = $k.Type
            Source             = 'Running service'
            State              = 'On'
            SignaturesUpToDate = $null
            Details            = $detail
        })
    }
}

# ----------------------------------------------------------------- output ---
if ($Json) {
    [pscustomobject]@{
        Computer = $env:COMPUTERNAME
        Date     = (Get-Date).ToString('s')
        Products = $results
    } | ConvertTo-Json -Depth 4
    return
}

Write-Host ''
Write-Host "AV-Lookup v2.0  -  $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host ('-' * 60)

if ($results.Count -eq 0) {
    Write-Host 'No antivirus / endpoint protection detected.' -ForegroundColor Red
} else {
    foreach ($r in ($results | Sort-Object Type, Name)) {
        $color = switch ($r.State) { 'On' {'Green'} 'Snoozed' {'Yellow'} default {'Red'} }
        Write-Host (" [{0}] " -f $r.Type) -NoNewline -ForegroundColor DarkGray
        Write-Host $r.Name -NoNewline -ForegroundColor White
        Write-Host ("  - {0}" -f $r.State) -ForegroundColor $color
        if ($null -ne $r.SignaturesUpToDate) {
            $sigText  = if ($r.SignaturesUpToDate) { 'up to date' } else { 'OUT OF DATE' }
            $sigColor = if ($r.SignaturesUpToDate) { 'Green' } else { 'Yellow' }
            Write-Host "       Signatures: " -NoNewline
            Write-Host $sigText -ForegroundColor $sigColor
        }
        if ($r.Details) { Write-Host "       $($r.Details)" -ForegroundColor DarkGray }
        Write-Host "       Source: $($r.Source)" -ForegroundColor DarkGray
    }
}

if ($scError) {
    Write-Host ''
    Write-Host 'Note: Security Center is unavailable (normal on Windows Server);' -ForegroundColor DarkYellow
    Write-Host '      results are based on running services only.' -ForegroundColor DarkYellow
}
if ($defenderInfo -and $defenderInfo.RunningMode -match 'Passive') {
    Write-Host ''
    Write-Host 'Note: Microsoft Defender is in passive mode (another product is primary).' -ForegroundColor DarkYellow
}

Write-Host ''
Write-Host 'Scan complete.' -ForegroundColor Cyan
if (-not $NoPause) { Read-Host 'Press Enter to exit' | Out-Null }
