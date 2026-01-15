<#
Detection and alert resolver v0.1 - Josh Bjorklund

How to use: Within the script, fill in environment information (console URL and site ID's), then after running, provide your API key and the file's hash. 

This should clear both alerts and detections. Additionally, within user config, you can change the analyst verdict to what is desired. Defalut is false positive.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ApiToken,

    [Parameter(Mandatory = $true)]
    [string]$FileHash
)

# ===================== USER CONFIG =====================

# Management console base URL – NO trailing slash.
# Example: "https://usea1-123.sentinelone.net"
$Server = "https://XXXXXXX.sentinelone.net"

# One or more Site IDs where you want to resolve threats.
# Example: @("1234567890123456789")
$SiteIds = @("XXXXXXXXXXX")

# Threats: what analyst verdict to apply when resolving
# Options: undefined, true_positive, false_positive, suspicious
$ThreatAnalystVerdict = "false_positive"

# Alerts (STAR custom alerts): analyst verdict when resolving
$AlertAnalystVerdict = "false_positive"

# Max per-call limits
$ThreatsBatchLimit = 5000   
$AlertsBatchLimit  = 500   

# Optional: delay between batches to be gentle with rate limits
$BatchDelaySeconds = 1

# ================= INTERNAL HELPERS ====================

function Get-HashFilterKeyForAlerts {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Hash
    )

    switch ($Hash.Length) {
        32 { return "sourceProcessFileHashMd5__contains" }      # MD5
        40 { return "sourceProcessFileHashSha1__contains" }     # SHA1
        64 { return "sourceProcessFileHashSha256__contains" }   # SHA256
        default {
            Write-Warning "Unknown hash length ($($Hash.Length)). Defaulting to SHA1 filter."
            return "sourceProcessFileHashSha1__contains"
        }
    }
}

$Headers = @{
    "Authorization" = "ApiToken $ApiToken"
}

# ================= THREATS (INCIDENTS) =================

function Resolve-ThreatIncidentsByHash {
    param(
        [string]$Hash
    )

    if (-not $SiteIds -or $SiteIds.Count -eq 0) {
        throw "SiteIds is empty. Please configure at least one Site ID."
    }

    $endpoint = "$Server/web/api/v2.1/threats/incident"

    $totalResolved = 0
    $batch = 0

    while ($true) {
        $batch++

        $body = @{
            filter = @{
                siteIds       = $SiteIds
                limit         = $ThreatsBatchLimit
                contentHashes = @($Hash)  
            }
            data = @{
                incidentStatus = "resolved"
                analystVerdict = $ThreatAnalystVerdict
            }
        } | ConvertTo-Json -Depth 5

        Write-Host "[-] Threats batch #${batch}: resolving incidents for hash $Hash ..." -ForegroundColor Cyan

        try {
            $response = Invoke-RestMethod -Uri $endpoint -Headers $Headers `
                                          -Method Post -ContentType "application/json" `
                                          -Body $body -ErrorAction Stop
        }
        catch {
            Write-Error "Error resolving threat incidents: $($_.Exception.Message)"
            break
        }

        $affected = 0
        if ($response -and $response.data -and $response.data.affected -ne $null) {
            $affected = [int]$response.data.affected
        }

        Write-Host "[+] Threats batch #$batch affected: $affected"

        $totalResolved += $affected

        if ($affected -lt $ThreatsBatchLimit -or $affected -eq 0) {
            break
        }

        Start-Sleep -Seconds $BatchDelaySeconds
    }

    Write-Host "[=] Total threat incidents resolved for hash ${Hash}: $totalResolved" -ForegroundColor Green
}

# ================= ALERTS (STAR) =======================

function Resolve-CloudDetectionAlertsByHash {
    param(
        [string]$Hash
    )

    $endpoint = "$Server/web/api/v2.1/cloud-detection/alerts/incident"

    $hashFilterKey = Get-HashFilterKeyForAlerts -Hash $Hash

    $totalResolved = 0
    $batch = 0

    while ($true) {
        $batch++

        # Filter unresolved STAR alerts whose source-process file hash matches
        $filter = @{
            limit          = $AlertsBatchLimit
            incidentStatus = "UNRESOLVED"  
        }
        $filter[$hashFilterKey] = @($Hash)

        $body = @{
            filter = $filter
            data   = @{
                incidentStatus = "resolved"
                analystVerdict = $AlertAnalystVerdict
            }
        } | ConvertTo-Json -Depth 5

        Write-Host "[-] Alerts batch #${batch}: resolving STAR alerts for hash $Hash using filter '$hashFilterKey' ..." -ForegroundColor Cyan

        try {
            $response = Invoke-RestMethod -Uri $endpoint -Headers $Headers `
                                          -Method Post -ContentType "application/json" `
                                          -Body $body -ErrorAction Stop
        }
        catch {
            Write-Error "Error resolving STAR alerts: $($_.Exception.Message)"
            break
        }

        $affected = 0
        if ($response -and $response.data -and $response.data.affected -ne $null) {
            $affected = [int]$response.data.affected
        }

        Write-Host "[+] Alerts batch #$batch affected: $affected"

        $totalResolved += $affected

        if ($affected -lt $AlertsBatchLimit -or $affected -eq 0) {
            break
        }

        Start-Sleep -Seconds $BatchDelaySeconds
    }

    Write-Host "[=] Total STAR alerts resolved for hash ${Hash}: $totalResolved" -ForegroundColor Green
}

# ===================== MAIN ============================

Write-Host "=== Resolving SentinelOne incidents and alerts for hash: $FileHash ===" -ForegroundColor Yellow
Write-Host "Console: $Server"
Write-Host "Sites:   $($SiteIds -join ', ')"
Write-Host ""

Resolve-ThreatIncidentsByHash -Hash $FileHash
Write-Host ""
Resolve-CloudDetectionAlertsByHash -Hash $FileHash

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Yellow
