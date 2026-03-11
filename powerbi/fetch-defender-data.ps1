<#
.SYNOPSIS
    Downloads Microsoft Defender for Endpoint vulnerability data as CSV files
    for use with the VRM Report Power BI project in preloaded mode.

.DESCRIPTION
    Fetches three datasets from the Defender for Endpoint REST API —
    Machines, Vulnerabilities, and MachineVulnerabilities — and saves them
    as CSV files.  Power BI refreshes from these static files with no live
    API calls and no per-client credential management inside Power BI Desktop.

    Authentication modes (ranked from simplest to most complex):

      azure_cli         – (Default) Uses your active 'az login' session.
                          No app registration needed.
                          Run first: az login --tenant <tenantId>

      azure_powershell  – Uses your active 'Connect-AzAccount' session.
                          No app registration needed.
                          Run first: Connect-AzAccount -TenantId <tenantId>

      device_code       – Raw OAuth 2.0 device-code flow.  Opens a browser
                          at aka.ms/devicelogin.
                          Requires: -ClientId (Entra app registration with
                          delegated Vulnerability.Read permission and
                          "Allow public client flows" enabled)

      client_credential – Headless service-principal flow.  No user sign-in.
                          Requires: -ClientId and -ClientSecret (Entra app
                          registration with application Vulnerability.Read.All
                          permission and admin consent granted)

.PARAMETER TenantId
    Entra tenant ID GUID or verified domain name (e.g. "contoso.onmicrosoft.com").
    Required.

.PARAMETER ClientId
    Entra application (client) ID.  Required for device_code and
    client_credential auth modes only.

.PARAMETER ClientSecret
    App client secret.  Required for client_credential mode only.

.PARAMETER AuthMode
    Authentication flow to use.  Defaults to 'azure_cli'.

.PARAMETER OutputFolder
    Folder where CSV files are saved.  Defaults to ".\csv\<TenantId>\" next
    to this script, so separate clients never share a folder.

.PARAMETER DefenderBaseUrl
    Defender for Endpoint API base URL.
    Defaults to https://api.securitycenter.microsoft.com
    Use https://api-gcc.securitycenter.microsoft.us for GCC tenants.

.EXAMPLE
    # Azure CLI — most common, no app registration needed
    az login --tenant contoso.onmicrosoft.com
    ./fetch-defender-data.ps1 -TenantId "contoso.onmicrosoft.com"

    # Azure PowerShell — no app registration needed
    Connect-AzAccount -TenantId "contoso.onmicrosoft.com"
    ./fetch-defender-data.ps1 -TenantId "contoso.onmicrosoft.com" -AuthMode azure_powershell

    # Device-code interactive sign-in (requires app registration)
    ./fetch-defender-data.ps1 -TenantId "contoso.onmicrosoft.com" `
        -ClientId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -AuthMode device_code

    # Headless client-credential (requires app registration + secret)
    ./fetch-defender-data.ps1 -TenantId "contoso.onmicrosoft.com" `
        -ClientId "xxxxxxxx-..." -ClientSecret "..." -AuthMode client_credential

    # After fetching, build the Power BI report from the downloaded data
    ./setup.ps1 -DataSource preloaded -TenantId "contoso" `
        -CsvFolderPath "./csv/contoso.onmicrosoft.com" -Open
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$TenantId,

    [string]$ClientId,
    [string]$ClientSecret,

    [ValidateSet('azure_cli', 'azure_powershell', 'device_code', 'client_credential')]
    [string]$AuthMode = 'azure_cli',

    [string]$OutputFolder,

    [string]$DefenderBaseUrl = 'https://api.securitycenter.microsoft.com'
)

$ErrorActionPreference = 'Stop'
$scriptDir = $PSScriptRoot

# PS5's Export-Csv -Encoding UTF8 writes a BOM; use this helper instead.
function Export-CsvNoBOM {
    param([string]$Path)
    begin   { $lines = [Collections.Generic.List[string]]::new() }
    process { $lines.Add($_) }
    end {
        $enc = New-Object System.Text.UTF8Encoding $false
        [IO.File]::WriteAllLines($Path, $lines.ToArray(), $enc)
    }
}

# ---------------------------------------------------------------------------
# Resolve and prepare output folder
# ---------------------------------------------------------------------------
if (-not $OutputFolder) {
    $OutputFolder = Join-Path $scriptDir "csv" $TenantId
}
if (-not (Test-Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}
$OutputFolder = (Resolve-Path $OutputFolder).Path

Write-Host ""
Write-Host "VRM Report - Defender Data Fetcher" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan
Write-Host "Tenant      : $TenantId"
Write-Host "Auth mode   : $AuthMode"
Write-Host "API base    : $DefenderBaseUrl"
Write-Host "Output      : $OutputFolder"
Write-Host ""

# ---------------------------------------------------------------------------
# Token acquisition — four modes, no external modules required for the first two
# ---------------------------------------------------------------------------
$resourceUrl = $DefenderBaseUrl

function Get-TokenAzureCli {
    param([string]$Resource, [string]$Tenant)
    Write-Host "Acquiring token via Azure CLI..." -ForegroundColor Yellow
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        throw "Azure CLI not found.  Install from https://aka.ms/installazurecliwindows " +
              "or use -AuthMode azure_powershell / device_code instead."
    }
    $result = az account get-access-token --resource $Resource --tenant $Tenant 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Azure CLI token acquisition failed.`n" +
              "Run: az login --tenant $Tenant`nError: $result"
    }
    return ($result | ConvertFrom-Json).accessToken
}

function Get-TokenAzurePowerShell {
    param([string]$Resource, [string]$Tenant)
    Write-Host "Acquiring token via Azure PowerShell..." -ForegroundColor Yellow
    if (-not (Get-Command Get-AzAccessToken -ErrorAction SilentlyContinue)) {
        throw "Az PowerShell module not found.`n" +
              "Install: Install-Module Az -Scope CurrentUser`n" +
              "Or use -AuthMode azure_cli / device_code instead."
    }
    try {
        $tokenObj = Get-AzAccessToken -ResourceUrl $Resource -TenantId $Tenant
        return $tokenObj.Token
    } catch {
        throw "Azure PowerShell token acquisition failed.`n" +
              "Run: Connect-AzAccount -TenantId $Tenant`nError: $_"
    }
}

function Get-TokenDeviceCode {
    param([string]$Tenant, [string]$AppClientId, [string]$Resource)
    if (-not $AppClientId) {
        throw "-ClientId is required for device_code auth mode.`n" +
              "Create an Entra app registration with delegated permission " +
              "'Vulnerability.Read' and 'Allow public client flows' enabled."
    }
    Write-Host "Requesting device code..." -ForegroundColor Yellow
    $dcResp = Invoke-RestMethod -Method POST `
        -Uri "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/devicecode" `
        -Body @{ client_id = $AppClientId; scope = "$Resource/.default offline_access" } `
        -ContentType 'application/x-www-form-urlencoded'

    Write-Host ""
    Write-Host "ACTION REQUIRED:" -ForegroundColor Yellow -BackgroundColor Black
    Write-Host "  1. Open:       $($dcResp.verification_uri)" -ForegroundColor Cyan
    Write-Host "  2. Enter code: $($dcResp.user_code)" -ForegroundColor Cyan
    Write-Host ""
    try { Start-Process $dcResp.verification_uri } catch {}

    $pollBody = @{
        grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
        device_code = $dcResp.device_code
        client_id   = $AppClientId
    }
    $interval = if ($null -ne $dcResp.interval) { [int]$dcResp.interval } else { 5 }
    $deadline = (Get-Date).AddSeconds($(if ($null -ne $dcResp.expires_in) { [int]$dcResp.expires_in } else { 900 }))
    $spinner  = @('|', '/', '-', '\')
    $i = 0

    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds $interval
        Write-Host "`r  Waiting for sign-in... $($spinner[$i++ % 4])" -NoNewline
        try {
            $tok = Invoke-RestMethod -Method POST `
                -Uri "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token" `
                -Body $pollBody `
                -ContentType 'application/x-www-form-urlencoded' `
                -ErrorAction SilentlyContinue
            if ($tok.access_token) {
                Write-Host "`r  Sign-in successful!                    " -ForegroundColor Green
                return $tok.access_token
            }
        } catch {
            $errBody = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($errBody.error -in @('authorization_declined', 'expired_token', 'bad_verification_code')) {
                throw "Sign-in cancelled or expired.  Re-run the script to try again."
            }
            # 'authorization_pending' is expected while waiting — keep polling
        }
    }
    throw "Device code expired.  Re-run the script to try again."
}

function Get-TokenClientCredential {
    param([string]$Tenant, [string]$AppClientId, [string]$AppClientSecret, [string]$Resource)
    if (-not $AppClientId)     { throw "-ClientId is required for client_credential mode." }
    if (-not $AppClientSecret) { throw "-ClientSecret is required for client_credential mode." }
    Write-Host "Acquiring token via client credential..." -ForegroundColor Yellow
    $resp = Invoke-RestMethod -Method POST `
        -Uri "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token" `
        -Body @{
            grant_type    = 'client_credentials'
            client_id     = $AppClientId
            client_secret = $AppClientSecret
            scope         = "$Resource/.default"
        } `
        -ContentType 'application/x-www-form-urlencoded'
    return $resp.access_token
}

$accessToken = switch ($AuthMode) {
    'azure_cli'          { Get-TokenAzureCli          -Resource $resourceUrl -Tenant $TenantId }
    'azure_powershell'   { Get-TokenAzurePowerShell   -Resource $resourceUrl -Tenant $TenantId }
    'device_code'        { Get-TokenDeviceCode        -Tenant $TenantId -AppClientId $ClientId -Resource $resourceUrl }
    'client_credential'  { Get-TokenClientCredential  -Tenant $TenantId -AppClientId $ClientId -AppClientSecret $ClientSecret -Resource $resourceUrl }
}
Write-Host "Token acquired." -ForegroundColor Green
Write-Host ""

# ---------------------------------------------------------------------------
# Paginated GET — follows @odata.nextLink until all pages are consumed
# ---------------------------------------------------------------------------
function Invoke-PaginatedGet {
    param(
        [string]$StartUrl,
        [string]$AccessToken,
        [string]$DisplayName
    )
    $all    = [System.Collections.Generic.List[object]]::new()
    $url    = $StartUrl
    $page   = 1
    $headers = @{ Authorization = "Bearer $AccessToken"; Accept = 'application/json' }

    do {
        Write-Host "  Page $page..." -NoNewline -ForegroundColor Gray
        $resp  = Invoke-RestMethod -Uri $url -Headers $headers -Method GET
        $chunk = $resp.value
        if ($chunk -and $chunk.Count -gt 0) {
            $all.AddRange([object[]]$chunk)
            Write-Host " $($chunk.Count) records (total so far: $($all.Count))" -ForegroundColor Gray
        } else {
            Write-Host " 0 records" -ForegroundColor Gray
        }
        $url = $resp.'@odata.nextLink'
        $page++
    } while ($url)

    Write-Host "  => $DisplayName: $($all.Count) records total" -ForegroundColor Cyan
    return $all.ToArray()
}

# ---------------------------------------------------------------------------
# Helper — flatten a JSON value to a CSV-safe string
# ---------------------------------------------------------------------------
function Format-CsvValue {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [System.Array]) { return ($Value -join ';') }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        return (($Value | ForEach-Object { $_ }) -join ';')
    }
    return $Value
}

# ---------------------------------------------------------------------------
# 1. Machines  (/api/machines)
# ---------------------------------------------------------------------------
Write-Host "Fetching Machines..." -ForegroundColor Yellow
$machines = Invoke-PaginatedGet `
    -StartUrl  "$DefenderBaseUrl/api/machines" `
    -AccessToken $accessToken `
    -DisplayName "Machines"

$machines | ForEach-Object {
    [PSCustomObject]@{
        id              = Format-CsvValue $_.id
        computerDnsName = Format-CsvValue $_.computerDnsName
        osPlatform      = Format-CsvValue $_.osPlatform
        rbacGroupName   = Format-CsvValue $_.rbacGroupName
        lastIpAddress   = Format-CsvValue $_.lastIpAddress
        healthStatus    = Format-CsvValue $_.healthStatus
        riskScore       = Format-CsvValue $_.riskScore
        exposureLevel   = Format-CsvValue $_.exposureLevel
        deviceValue     = Format-CsvValue $_.deviceValue
    }
} | ConvertTo-Csv -NoTypeInformation | Export-CsvNoBOM (Join-Path $OutputFolder "machines.csv")
Write-Host "  Saved: machines.csv" -ForegroundColor Green
Write-Host ""

# ---------------------------------------------------------------------------
# 2. Vulnerabilities  (/api/vulnerabilities)
# ---------------------------------------------------------------------------
Write-Host "Fetching Vulnerabilities..." -ForegroundColor Yellow
$vulnerabilities = Invoke-PaginatedGet `
    -StartUrl  "$DefenderBaseUrl/api/vulnerabilities" `
    -AccessToken $accessToken `
    -DisplayName "Vulnerabilities"

$vulnerabilities | ForEach-Object {
    [PSCustomObject]@{
        id                = Format-CsvValue $_.id
        name              = Format-CsvValue $_.name
        description       = Format-CsvValue $_.description
        severity          = Format-CsvValue $_.severity
        cvssV3            = Format-CsvValue $_.cvssV3
        cvssVector        = Format-CsvValue $_.cvssVector
        exposedMachines   = Format-CsvValue $_.exposedMachines
        publishedOn       = Format-CsvValue $_.publishedOn
        updatedOn         = Format-CsvValue $_.updatedOn
        firstDetected     = Format-CsvValue $_.firstDetected
        publicExploit     = Format-CsvValue $_.publicExploit
        exploitVerified   = Format-CsvValue $_.exploitVerified
        exploitInKit      = Format-CsvValue $_.exploitInKit
        exploitTypes      = Format-CsvValue $_.exploitTypes
        exploitUris       = Format-CsvValue $_.exploitUris
        cveSupportability = Format-CsvValue $_.cveSupportability
        tags              = Format-CsvValue $_.tags
        epss              = Format-CsvValue $_.epss
        status            = Format-CsvValue $_.status
    }
} | ConvertTo-Csv -NoTypeInformation | Export-CsvNoBOM (Join-Path $OutputFolder "vulnerabilities.csv")
Write-Host "  Saved: vulnerabilities.csv" -ForegroundColor Green
Write-Host ""

# ---------------------------------------------------------------------------
# 3. MachineVulnerabilities  (/api/vulnerabilities/machinesVulnerabilities)
#    This is the largest dataset — may take several minutes for big tenants.
# ---------------------------------------------------------------------------
Write-Host "Fetching MachineVulnerabilities (largest dataset — may take several minutes)..." -ForegroundColor Yellow
$mv = Invoke-PaginatedGet `
    -StartUrl  "$DefenderBaseUrl/api/vulnerabilities/machinesVulnerabilities" `
    -AccessToken $accessToken `
    -DisplayName "MachineVulnerabilities"

$mv | ForEach-Object {
    [PSCustomObject]@{
        id             = Format-CsvValue $_.id
        cveId          = Format-CsvValue $_.cveId
        machineId      = Format-CsvValue $_.machineId
        fixingKbId     = Format-CsvValue $_.fixingKbId
        productName    = Format-CsvValue $_.productName
        productVendor  = Format-CsvValue $_.productVendor
        productVersion = Format-CsvValue $_.productVersion
        severity       = Format-CsvValue $_.severity
    }
} | ConvertTo-Csv -NoTypeInformation | Export-CsvNoBOM (Join-Path $OutputFolder "machineVulnerabilities.csv")
Write-Host "  Saved: machineVulnerabilities.csv" -ForegroundColor Green
Write-Host ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
$totalFiles = 3
Write-Host "Done!  $totalFiles CSV files written to:" -ForegroundColor Green
Write-Host "  $OutputFolder" -ForegroundColor White
Write-Host ""
Write-Host "  machines.csv                 — $($machines.Count) devices"
Write-Host "  vulnerabilities.csv          — $($vulnerabilities.Count) CVEs"
Write-Host "  machineVulnerabilities.csv   — $($mv.Count) device×CVE rows"
Write-Host ""
Write-Host "Next: generate the Power BI report from these files:" -ForegroundColor Cyan
$tenantShort = $TenantId -replace '\..*$', ''   # first label before the first dot
Write-Host "  ./setup.ps1 -DataSource preloaded -TenantId `"$tenantShort`" ``" -ForegroundColor White
Write-Host "             -CsvFolderPath `"$OutputFolder`" -Open" -ForegroundColor White
Write-Host ""
Write-Host "To refresh data in the future: re-run this script, then click Refresh in Power BI." -ForegroundColor Gray
Write-Host ""
