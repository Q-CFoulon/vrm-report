<#
.SYNOPSIS
    Generates a Power BI Project (.pbip) for the VRM Vulnerability Report.

.DESCRIPTION
    Reads the Power Query (M) scripts from the queries/ folder, embeds them
    with DAX measures and column definitions into a complete model.bim, and
    produces a Power BI Project (.pbip) that can be opened directly in
    Power BI Desktop.

    Supports two data-source modes:
      api  – (default) live queries via Defender for Endpoint REST API
      csv  – offline mode using CSV files exported from the Defender portal

.PARAMETER DataSource
    Either 'api' (default) or 'csv'.
    In CSV mode the fn_PaginatedGet function and API parameter are omitted;
    instead a CsvFolderPath parameter points to the folder with your CSVs.

.PARAMETER CsvFolderPath
    Folder containing the exported CSV files (csv mode only):
      export-tvm-vulnerabilities.csv  (Weaknesses export)
      devices.csv                     (Devices export)
    Defaults to a 'csv' folder next to this script.

.PARAMETER EnrichmentPath
    Absolute path to the asset-enrichment JSON file.
    Defaults to data/enrichment/asset-enrichment.json in the repo root.

.PARAMETER DefenderBaseUrl
    Base URL for the Defender for Endpoint API (api mode only).
    Defaults to https://api.securitycenter.microsoft.com

.PARAMETER Open
    If specified, opens the generated .pbip file in Power BI Desktop.

.EXAMPLE
    .\setup.ps1 -Open
    .\setup.ps1 -TenantId "contoso" -Open
    .\setup.ps1 -DataSource csv -CsvFolderPath "C:\exports" -TenantId "fabrikam" -Open
    .\setup.ps1 -EnrichmentPath "C:\data\enrichment.json" -TenantId "contoso" -Open
#>
[CmdletBinding()]
param(
    [ValidateSet('api','csv','preloaded')]
    [string]$DataSource = 'api',
    [string]$CsvFolderPath,
    [string]$EnrichmentPath,
    [string]$DefenderBaseUrl = "https://api.securitycenter.microsoft.com",
    # Client/tenant identifier — used to name the output .pbip and as a visible
    # Power BI parameter so you always know which client you are working on.
    # Use the tenant's short name or Entra tenant ID GUID.
    [string]$TenantId,
    [switch]$Open
)

$ErrorActionPreference = "Stop"
$scriptDir   = $PSScriptRoot
$queriesDir  = Join-Path $scriptDir "queries"
$projectName = if ($TenantId) { "VRM-Report-$TenantId" } else { "VRM-Report" }

# ---------------------------------------------------------------------------
# Resolve the enrichment file path
# ---------------------------------------------------------------------------
if (-not $EnrichmentPath) {
    $defaultPath = Join-Path (Split-Path $scriptDir) "data\enrichment\asset-enrichment.json"
    if (Test-Path $defaultPath) {
        $EnrichmentPath = (Resolve-Path $defaultPath).Path
    } else {
        $EnrichmentPath = $defaultPath
        Write-Warning "Enrichment file not found at:`n  $EnrichmentPath`nYou can update the EnrichmentFilePath parameter inside Power BI later."
    }
}

# ---------------------------------------------------------------------------
# Resolve CSV folder path (csv and preloaded modes)
# ---------------------------------------------------------------------------
if ($DataSource -eq 'csv' -or $DataSource -eq 'preloaded') {
    if (-not $CsvFolderPath) {
        $CsvFolderPath = Join-Path $scriptDir "csv"
    }
    if ($DataSource -eq 'csv' -and -not (Test-Path $CsvFolderPath)) {
        New-Item -Path $CsvFolderPath -ItemType Directory -Force | Out-Null
        Write-Warning "CSV folder created at: $CsvFolderPath`nPlace your exported CSVs there:`n  export-tvm-vulnerabilities.csv  (Weaknesses export)`n  devices.csv                     (Devices export)"
    }
    if ($DataSource -eq 'preloaded' -and -not (Test-Path $CsvFolderPath)) {
        throw "CSV folder not found: $CsvFolderPath`nRun fetch-defender-data.ps1 first to download the data from the tenant."
    }
}

Write-Host ""
Write-Host "VRM Report - Power BI Project Generator" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Data source  : $DataSource"
if ($DataSource -eq 'api') {
    Write-Host "Defender API : $DefenderBaseUrl"
} else {
    Write-Host "CSV folder   : $CsvFolderPath"
}
Write-Host "Enrichment   : $EnrichmentPath"
if ($TenantId) {
    Write-Host "Tenant ID    : $TenantId" -ForegroundColor Cyan
} else {
    Write-Warning "No -TenantId specified. Consider passing -TenantId <name-or-guid> so each client gets its own .pbip file and you always know which tenant you are working on."
}
Write-Host ""

# ---------------------------------------------------------------------------
# Read all .pq files
# ---------------------------------------------------------------------------
Write-Host "Reading Power Query scripts..." -ForegroundColor Yellow
$mQueries = @{}

# Always load common queries (Enrichment, EnrichmentDefaults, VRM_Report)
Get-ChildItem "$queriesDir\*.pq" | ForEach-Object {
    $mQueries[$_.BaseName] = (Get-Content $_.FullName -Raw).TrimEnd()
    Write-Host "  + $($_.BaseName)" -ForegroundColor Gray
}

# In CSV mode, override the three data queries with their CSV variants
if ($DataSource -eq 'csv') {
    $csvDir = Join-Path $queriesDir "csv"
    foreach ($csvFile in (Get-ChildItem "$csvDir\*.pq")) {
        # Strip _CSV suffix → e.g. Vulnerabilities_CSV → Vulnerabilities
        $baseName = $csvFile.BaseName -replace '_CSV$', ''
        $mQueries[$baseName] = (Get-Content $csvFile.FullName -Raw).TrimEnd()
        Write-Host "  ~ $baseName (CSV override: $($csvFile.Name))" -ForegroundColor DarkYellow
    }
}

# In preloaded mode, override the three API data queries with CSV-backed
# equivalents that read files produced by fetch-defender-data.ps1.
# VRM_Report.pq is NOT overridden — it runs unchanged for full per-device rows.
if ($DataSource -eq 'preloaded') {
    $preloadedDir = Join-Path $queriesDir "preloaded"
    foreach ($preFile in (Get-ChildItem "$preloadedDir\*.pq")) {
        $baseName = $preFile.BaseName -replace '_preloaded$', ''
        $mQueries[$baseName] = (Get-Content $preFile.FullName -Raw).TrimEnd()
        Write-Host "  ~ $baseName (preloaded: $($preFile.Name))" -ForegroundColor DarkCyan
    }
}

$requiredQueries = if ($DataSource -eq 'csv') {
    @("Vulnerabilities", "Machines",
      "Enrichment", "EnrichmentDefaults", "VRM_Report")
} elseif ($DataSource -eq 'preloaded') {
    # Same as API mode but no fn_PaginatedGet — data comes from static CSVs
    @("Vulnerabilities", "MachineVulnerabilities",
      "Machines", "Enrichment", "EnrichmentDefaults", "VRM_Report")
} else {
    @("fn_PaginatedGet", "Vulnerabilities", "MachineVulnerabilities",
      "Machines", "Enrichment", "EnrichmentDefaults", "VRM_Report")
}
foreach ($q in $requiredQueries) {
    if (-not $mQueries.ContainsKey($q)) {
        throw "Missing required query file: $q.pq"
    }
}

# ---------------------------------------------------------------------------
# Helper: split M expression into array of lines for model.bim
# ---------------------------------------------------------------------------
function Split-Expression([string]$expr) {
    return @($expr -split "`r?`n")
}

# ---------------------------------------------------------------------------
# Define VRM_Report columns  (must match the final column names from the M query)
# ---------------------------------------------------------------------------
function New-Column([string]$name, [string]$dataType = "string") {
    $col = [ordered]@{
        name         = $name
        dataType     = $dataType
        sourceColumn = $name
        summarizeBy  = "none"
    }
    if ($dataType -eq "dateTime") {
        $col["formatString"] = "General Date"
    }
    return $col
}

$columns = @(
    New-Column "Unique ID"
    New-Column "Criticality"
    New-Column "CVE#"
    New-Column "CVSS Score" "double"
    New-Column "Description"
    New-Column "Device OS"
    New-Column "Device Type"
    New-Column "Date First Detected" "dateTime"
    New-Column "Date Last Detected"  "dateTime"
    New-Column "Status"
    New-Column "Risk Acceptance"
    New-Column "Asset Criticality"
    New-Column "Data Type"
    New-Column "Location"
    New-Column "Notes"
    New-Column "Product"
    New-Column "Machine Name"
)

# ---------------------------------------------------------------------------
# Define DAX measures
# ---------------------------------------------------------------------------
function New-Measure([string]$name, [string]$expression) {
    return [ordered]@{ name = $name; expression = $expression }
}

$measures = @(
    New-Measure "Total Vulnerabilities" "COUNTROWS('VRM_Report')"
    New-Measure "Unique CVEs"           "DISTINCTCOUNT('VRM_Report'[CVE#])"
    New-Measure "Unique Machines"       "DISTINCTCOUNT('VRM_Report'[Machine Name])"

    New-Measure "Critical Count"    "CALCULATE(COUNTROWS('VRM_Report'), 'VRM_Report'[Criticality] = ""Critical"")"
    New-Measure "High Count"        "CALCULATE(COUNTROWS('VRM_Report'), 'VRM_Report'[Criticality] = ""High"")"
    New-Measure "Exploitable Count" "CALCULATE(COUNTROWS('VRM_Report'), 'VRM_Report'[Criticality] = ""Exploitable"")"
    New-Measure "Medium Count"      "CALCULATE(COUNTROWS('VRM_Report'), 'VRM_Report'[Criticality] = ""Medium"")"
    New-Measure "Low Count"         "CALCULATE(COUNTROWS('VRM_Report'), 'VRM_Report'[Criticality] = ""Low"")"

    New-Measure "Patched Count"         "CALCULATE(COUNTROWS('VRM_Report'), 'VRM_Report'[Status] = ""Patched"")"
    New-Measure "Pending Under 1 Month" "CALCULATE(COUNTROWS('VRM_Report'), 'VRM_Report'[Status] = ""Pending < 1 month"")"
    New-Measure "Pending Over 1 Month"  "CALCULATE(COUNTROWS('VRM_Report'), 'VRM_Report'[Status] = ""Pending > 1 month"")"
    New-Measure "Pending Over 2 Months" "CALCULATE(COUNTROWS('VRM_Report'), 'VRM_Report'[Status] = ""Pending > 2 months"")"
    New-Measure "Pending Over 3 Months" "CALCULATE(COUNTROWS('VRM_Report'), 'VRM_Report'[Status] = ""Pending > 3 months"")"

    New-Measure "Risk Accepted Count" "CALCULATE(COUNTROWS('VRM_Report'), 'VRM_Report'[Risk Acceptance] = ""Yes"")"
    New-Measure "Risk Accepted Pct"   "DIVIDE([Risk Accepted Count], [Total Vulnerabilities], 0)"
    New-Measure "Average CVSS"        "AVERAGE('VRM_Report'[CVSS Score])"

    New-Measure "Critical or Exploitable Unpatched" @"
CALCULATE(
    COUNTROWS('VRM_Report'),
    'VRM_Report'[Criticality] IN {"Critical", "Exploitable"},
    'VRM_Report'[Status] <> "Patched"
)
"@

    New-Measure "Overdue Over 90 Days" "CALCULATE(COUNTROWS('VRM_Report'), 'VRM_Report'[Status] = ""Pending > 3 months"")"

    New-Measure "Avg Days Open" @"
AVERAGEX(
    FILTER('VRM_Report', 'VRM_Report'[Status] <> "Patched"),
    DATEDIFF('VRM_Report'[Date First Detected], TODAY(), DAY)
)
"@
)

# ---------------------------------------------------------------------------
# Build model.bim  (Tabular Object Model JSON)
# ---------------------------------------------------------------------------
Write-Host "Building model.bim..." -ForegroundColor Yellow

$model = [ordered]@{
    compatibilityLevel = 1567
    model = [ordered]@{
        culture = "en-US"
        dataAccessOptions = [ordered]@{
            legacyRedirects        = $true
            returnErrorValuesAsNull = $true
        }
        defaultPowerBIDataSourceVersion = "powerBI_V3"
        sourceQueryCulture = "en-US"

        # -- Parameters & staging M expressions (not loaded as tables) ------
        expressions = $(
            $exprs = [System.Collections.ArrayList]::new()

            # TenantId parameter — always emitted first so it is the most
            # prominent entry in Transform Data > Manage Parameters.
            # Changing this value is the signal that you are switching clients;
            # you must also clear credentials (see SETUP.md).
            [void]$exprs.Add([ordered]@{
                name = "TenantId"
                kind = "m"
                expression = Split-Expression(
                    "`"$TenantId`" meta [IsParameterQuery=true, Type=`"Text`", IsParameterQueryRequired=true]"
                )
            })

            if ($DataSource -eq 'csv' -or $DataSource -eq 'preloaded') {
                # CSV / preloaded mode: CsvFolderPath parameter instead of API URL.
                # In preloaded mode the folder holds API-format CSVs from
                # fetch-defender-data.ps1; in csv mode it holds portal exports.
                [void]$exprs.Add([ordered]@{
                    name = "CsvFolderPath"
                    kind = "m"
                    expression = Split-Expression(
                        "`"$CsvFolderPath`" meta [IsParameterQuery=true, Type=`"Text`", IsParameterQueryRequired=true]"
                    )
                })
            } else {
                # API mode: DefenderApiBaseUrl parameter + pagination helper
                [void]$exprs.Add([ordered]@{
                    name = "DefenderApiBaseUrl"
                    kind = "m"
                    expression = Split-Expression(
                        "`"$DefenderBaseUrl`" meta [IsParameterQuery=true, Type=`"Text`", IsParameterQueryRequired=true]"
                    )
                })
                [void]$exprs.Add([ordered]@{
                    name = "fn_PaginatedGet"
                    kind = "m"
                    expression = Split-Expression $mQueries["fn_PaginatedGet"]
                })
            }

            # EnrichmentFilePath parameter (both modes)
            [void]$exprs.Add([ordered]@{
                name = "EnrichmentFilePath"
                kind = "m"
                expression = Split-Expression(
                    "`"$EnrichmentPath`" meta [IsParameterQuery=true, Type=`"Text`", IsParameterQueryRequired=true]"
                )
            })

            # Staging queries (varies by mode — CSV mode has no MachineVulnerabilities)
            $stagingNames = if ($DataSource -eq 'csv') {
                @("Vulnerabilities", "Machines", "Enrichment", "EnrichmentDefaults")
            } else {
                @("Vulnerabilities", "MachineVulnerabilities", "Machines", "Enrichment", "EnrichmentDefaults")
            }
            foreach ($stagingName in $stagingNames) {
                [void]$exprs.Add([ordered]@{
                    name = $stagingName
                    kind = "m"
                    expression = Split-Expression $mQueries[$stagingName]
                })
            }

            ,$exprs.ToArray()
        )

        # -- Tables (only VRM_Report is loaded into the model) --------------
        tables = @(
            [ordered]@{
                name    = "VRM_Report"
                columns = $columns
                measures = $measures
                partitions = @(
                    [ordered]@{
                        name   = "VRM_Report-partition"
                        mode   = "import"
                        source = [ordered]@{
                            type       = "m"
                            expression = Split-Expression $mQueries["VRM_Report"]
                        }
                    }
                )
            }
        )
    }
}

$modelJson = $model | ConvertTo-Json -Depth 30

# ---------------------------------------------------------------------------
# Write PBIP project files
# ---------------------------------------------------------------------------
Write-Host "Writing PBIP project files..." -ForegroundColor Yellow

# Folder structure
$semanticDir = Join-Path $scriptDir "$projectName.SemanticModel"
$reportDir   = Join-Path $scriptDir "$projectName.Report"

# Clean previous PBI Desktop-generated files (TMDL, caches, etc.)
foreach ($sub in @("definition",".pbi",".platform")) {
    $p = Join-Path $semanticDir $sub
    if (Test-Path $p) { Remove-Item $p -Recurse -Force }
    $p = Join-Path $reportDir $sub
    if (Test-Path $p) { Remove-Item $p -Recurse -Force }
}
$sr = Join-Path $reportDir "StaticResources"
if (Test-Path $sr) { Remove-Item $sr -Recurse -Force }

New-Item -Path $semanticDir -ItemType Directory -Force | Out-Null
New-Item -Path $reportDir   -ItemType Directory -Force | Out-Null

# 1. model.bim  (directly in SemanticModel folder, not in definition subfolder)
$modelPath = Join-Path $semanticDir "model.bim"
$modelJson | Out-File -FilePath $modelPath -Encoding utf8 -Force
Write-Host "  + $projectName.SemanticModel/model.bim" -ForegroundColor Gray

# 2. definition.pbism
$datasetPath = Join-Path $scriptDir "$projectName.SemanticModel\definition.pbism"
$datasetJson = [ordered]@{
    version  = "1.0"
    settings = [ordered]@{}
} | ConvertTo-Json -Depth 5
$datasetJson | Out-File -FilePath $datasetPath -Encoding utf8 -Force
Write-Host "  + $projectName.SemanticModel/definition.pbism" -ForegroundColor Gray

# 3. definition.pbir
$reportPath = Join-Path $reportDir "definition.pbir"
$reportJson = [ordered]@{
    '$schema' = "https://developer.microsoft.com/json-schemas/fabric/item/report/definitionProperties/2.0.0/schema.json"
    version = "4.0"
    datasetReference = [ordered]@{
        byPath = [ordered]@{
            path = "../$projectName.SemanticModel"
        }
    }
} | ConvertTo-Json -Depth 5
$reportJson | Out-File -FilePath $reportPath -Encoding utf8 -Force
Write-Host "  + $projectName.Report/definition.pbir" -ForegroundColor Gray

# ---------------------------------------------------------------------------
# Enhanced report format files  (required by PBI Desktop when definition.pbir exists)
# Schema versions sourced from PBI Desktop February 2026 (v2.151.1182.0).
# ---------------------------------------------------------------------------
Write-Host "Building enhanced report format..." -ForegroundColor Yellow

# ── .platform ──
[ordered]@{
    '$schema' = "https://developer.microsoft.com/json-schemas/fabric/gitIntegration/platformProperties/2.0.0/schema.json"
    metadata  = [ordered]@{
        type        = "Report"
        displayName = $projectName
    }
    config = [ordered]@{
        version   = "2.0"
        logicalId = [guid]::NewGuid().ToString()
    }
} | ConvertTo-Json -Depth 5 |
    Out-File (Join-Path $reportDir ".platform") -Encoding utf8
Write-Host "  + .platform" -ForegroundColor Gray

$defDir   = Join-Path $reportDir "definition"
$pagesDir = Join-Path $defDir "pages"
New-Item -Path $pagesDir -ItemType Directory -Force | Out-Null

# ── definition/version.json ──
[ordered]@{
    '$schema' = "https://developer.microsoft.com/json-schemas/fabric/item/report/definition/versionMetadata/1.0.0/schema.json"
    version   = "2.0.0"
} | ConvertTo-Json -Depth 5 |
    Out-File (Join-Path $defDir "version.json") -Encoding utf8
Write-Host "  + definition/version.json" -ForegroundColor Gray

# ── StaticResources/SharedResources/BaseThemes/CY26SU02.json ──
$themeDir = Join-Path $reportDir "StaticResources\SharedResources\BaseThemes"
New-Item -Path $themeDir -ItemType Directory -Force | Out-Null
$themeRef = Join-Path $scriptDir "data\references\CY26SU02.json"
if (Test-Path $themeRef) {
    Copy-Item $themeRef (Join-Path $themeDir "CY26SU02.json") -Force
} else {
    '{}' | Out-File (Join-Path $themeDir "CY26SU02.json") -Encoding utf8
}
Write-Host "  + StaticResources base theme" -ForegroundColor Gray

# ── definition/report.json ──
[ordered]@{
    '$schema' = "https://developer.microsoft.com/json-schemas/fabric/item/report/definition/report/3.1.0/schema.json"
    themeCollection = [ordered]@{
        baseTheme = [ordered]@{
            name = "CY26SU02"
            reportVersionAtImport = [ordered]@{
                visual = "2.6.0"
                report = "3.1.0"
                page   = "2.3.0"
            }
            type = "SharedResources"
        }
    }
    objects = [ordered]@{
        section = @(
            [ordered]@{
                properties = [ordered]@{
                    verticalAlignment = [ordered]@{
                        expr = [ordered]@{
                            Literal = [ordered]@{ Value = "'Top'" }
                        }
                    }
                }
            }
        )
    }
    resourcePackages = @(
        [ordered]@{
            name  = "SharedResources"
            type  = "SharedResources"
            items = @(
                [ordered]@{
                    name = "CY26SU02"
                    path = "BaseThemes/CY26SU02.json"
                    type = "BaseTheme"
                }
            )
        }
    )
    settings = [ordered]@{
        useStylableVisualContainerHeader = $true
        exportDataMode                   = "AllowSummarized"
        defaultDrillFilterOtherVisuals   = $true
        allowChangeFilterTypes           = $true
        useEnhancedTooltips              = $true
        useDefaultAggregateDisplayName   = $true
    }
    slowDataSourceSettings = [ordered]@{
        isCrossHighlightingDisabled       = $true
        isSlicerSelectionsButtonEnabled   = $false
        isFilterSelectionsButtonEnabled   = $false
        isApplyAllButtonEnabled           = $true
    }
} | ConvertTo-Json -Depth 10 |
    Out-File (Join-Path $defDir "report.json") -Encoding utf8
Write-Host "  + definition/report.json" -ForegroundColor Gray

# ── Pages ──
$page1Id = "3ca93e99e0a16a569000"
$page2Id = "d4e5f6a7b8c9d0e1f200"

[ordered]@{
    '$schema'      = "https://developer.microsoft.com/json-schemas/fabric/item/report/definition/pagesMetadata/1.0.0/schema.json"
    pageOrder      = @($page1Id, $page2Id)
    activePageName = $page1Id
} | ConvertTo-Json -Depth 5 |
    Out-File (Join-Path $pagesDir "pages.json") -Encoding utf8

foreach ($pg in @(
    @{ Id = $page1Id; Name = "Executive Summary" },
    @{ Id = $page2Id; Name = "Detail Table" }
)) {
    $pgDir = Join-Path $pagesDir $pg.Id
    New-Item -Path $pgDir -ItemType Directory -Force | Out-Null
    [ordered]@{
        '$schema'     = "https://developer.microsoft.com/json-schemas/fabric/item/report/definition/page/2.0.0/schema.json"
        name          = $pg.Id
        displayName   = $pg.Name
        displayOption = "FitToPage"
        height        = 720
        width         = 1280
        pageBinding   = [ordered]@{
            name           = [guid]::NewGuid().ToString("N").Substring(0,20)
            type           = "Default"
            parameters     = @()
            referenceScope = "CrossReport"
        }
    } | ConvertTo-Json -Depth 5 |
        Out-File (Join-Path $pgDir "page.json") -Encoding utf8
    Write-Host "  + Page: $($pg.Name)" -ForegroundColor Gray
}

# 4. VRM-Report.pbip  (main project file)
$pbipPath = Join-Path $scriptDir "$projectName.pbip"
$pbipJson = [ordered]@{
    version   = "1.0"
    artifacts = @(
        [ordered]@{
            report = [ordered]@{
                path = "$projectName.Report"
            }
        }
    )
    settings = [ordered]@{
        enableAutoRecovery = $true
    }
} | ConvertTo-Json -Depth 5
$pbipJson | Out-File -FilePath $pbipPath -Encoding utf8 -Force
Write-Host "  + $projectName.pbip" -ForegroundColor Gray

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "Done! Project generated at:" -ForegroundColor Green
Write-Host "  $pbipPath" -ForegroundColor White
Write-Host ""
if ($TenantId) {
    Write-Host "Tenant       : $TenantId" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Switching clients later?" -ForegroundColor Cyan
    Write-Host "  Re-run:  .\fetch-defender-data.ps1 -TenantId <new-tenant>" -ForegroundColor White
    Write-Host "  Then:    .\setup.ps1 -DataSource preloaded -TenantId <new-tenant> -CsvFolderPath <folder> -Open" -ForegroundColor White
    if ($DataSource -eq 'api') {
        Write-Host "  Or for API mode: clear credentials in Power BI first" -ForegroundColor Gray
        Write-Host "    File > Options > Data Source Settings > Clear Permissions" -ForegroundColor Gray
    }
    Write-Host ""
}
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Open $projectName.pbip in Power BI Desktop"
if ($DataSource -eq 'csv') {
    Write-Host "  2. Place your CSVs in: $CsvFolderPath" -ForegroundColor White
    Write-Host "     - export-tvm-vulnerabilities.csv  (Weaknesses export)"
    Write-Host "     - devices.csv                     (Devices export)"
    Write-Host "  3. Click Refresh to load data from the CSVs"
    Write-Host ""
    Write-Host "  Note: CSV mode produces one row per CVE (not per device)." -ForegroundColor DarkYellow
    Write-Host "  The Devices table is loaded as a supplementary reference." -ForegroundColor DarkYellow
} elseif ($DataSource -eq 'preloaded') {
    Write-Host "  2. Click Refresh — data loads instantly from the pre-downloaded CSVs"
    Write-Host "     No API credentials or sign-in needed in Power BI." -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "  Note: Preloaded mode gives full per-device×CVE rows (same as API mode)." -ForegroundColor DarkCyan
    Write-Host "  CSV folder: $CsvFolderPath" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  To update data for this client:" -ForegroundColor Cyan
    Write-Host "    .\fetch-defender-data.ps1 -TenantId `"$TenantId`"" -ForegroundColor White
    Write-Host "    Then click Refresh in Power BI." -ForegroundColor White
} else {
    Write-Host "  2. When prompted, sign in with your Organizational Account"
    Write-Host "  3. Set privacy level to Organizational"
    Write-Host "  4. Click Refresh to load live Defender data"
}
Write-Host ""
Write-Host "To update parameters later:" -ForegroundColor Cyan
Write-Host "  Transform Data > Manage Parameters" -ForegroundColor White
Write-Host ""

# ---------------------------------------------------------------------------
# Optionally open in Power BI Desktop
# ---------------------------------------------------------------------------
if ($Open) {
    Write-Host "Opening in Power BI Desktop..." -ForegroundColor Yellow
    Start-Process $pbipPath
}
