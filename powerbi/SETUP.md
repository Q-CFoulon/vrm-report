# VRM Report -- Power BI Setup Guide

This guide walks you through setting up the Power BI VRM report that pulls
data from **Microsoft Defender for Endpoint**.

Three data-source modes are available -- choose the one that fits your situation:

| Mode | How it works | Granularity | Best for |
|---|---|---|---|
| **preloaded** | PowerShell script fetches API data -> saved as CSVs -> Power BI reads CSVs | Per-device x CVE (full) | Multi-client consulting -- recommended |
| **csv** | Manual portal export -> CSVs -> Power BI reads CSVs | Per-CVE only | Quick one-off when no tooling access |
| **api** | Power BI calls Defender API live during refresh | Per-device x CVE (full) | Internal team with stable device access |

---

## Prerequisites

| Requirement | Details |
|---|---|
| **Power BI Desktop** | Latest version (free download from Microsoft) |
| **Enrichment file** | Copy `data/enrichment/asset-enrichment.example.json` -> `asset-enrichment.json` and customise it for the environment |

---

## Quick start -- Preloaded mode (recommended for multi-client work)

**Preloaded mode** separates the data-fetch step from Power BI entirely.  A
PowerShell script authenticates to the Defender API and saves the data as CSV
files.  Power BI reads those static files with no live API calls, no OAuth
prompts inside Power BI Desktop, and no Fabric requirement.

This is the recommended approach for consultants working across multiple
client tenants.

### Step 1: Authenticate and download the data

Run `fetch-defender-data.ps1` from the `powerbi/` folder.

**No app registration needed** -- just Azure CLI:

```powershell
az login --tenant contoso.onmicrosoft.com
.\fetch-defender-data.ps1 -TenantId "contoso.onmicrosoft.com"
```

Or Azure PowerShell if you prefer that:

```powershell
Connect-AzAccount -TenantId "contoso.onmicrosoft.com"
.\fetch-defender-data.ps1 -TenantId "contoso.onmicrosoft.com" -AuthMode azure_powershell
```

The script downloads and saves three CSV files to `powerbi/csv/contoso.onmicrosoft.com/`:

| File | Content |
|---|---|
| `machines.csv` | All devices and their properties |
| `vulnerabilities.csv` | All CVEs with severity, CVSS, exploit status |
| `machineVulnerabilities.csv` | One row per device x CVE (the join table) |

> **Switching tenants:** Just re-run the script with a different `-TenantId`.
> Each tenant gets its own subfolder automatically.

### Step 2: Generate and open the Power BI project

```powershell
.\setup.ps1 -DataSource preloaded -TenantId "contoso" `
            -CsvFolderPath ".\csv\contoso.onmicrosoft.com" -Open
```

### Step 3: Refresh in Power BI

1. Click **Refresh** (or **Transform Data** -> **Close & Apply**)
2. If prompted about file privacy, set to **Organizational** -> **Connect**
3. Data loads -- full per-device x CVE rows with no sign-in

### Updating the data for a client

Re-run `fetch-defender-data.ps1` with the same `-TenantId`, then click
**Refresh** in Power BI -- no credential management needed inside Power BI.

```powershell
az login --tenant contoso.onmicrosoft.com   # only needed if session expired
.\fetch-defender-data.ps1 -TenantId "contoso.onmicrosoft.com"
```

---

## Quick start -- CSV mode (one-off, no tooling required)

If your organization enforces Conditional Access (e.g. registered devices
only), use CSV mode to bypass the OAuth flow entirely.

### Step 1: Export CSVs from the Defender portal

Sign in at [security.microsoft.com](https://security.microsoft.com) on a
compliant device (or via browser) and export two files:

| Export | Portal path | Expected filename |
|---|---|---|
| **Weaknesses** | Vulnerability Management -> Weaknesses -> Export | `export-tvm-vulnerabilities.csv` |
| **Devices** | Assets -> Devices -> Export | `devices.csv` |

> **Note:** CSV mode produces one row per CVE (not per device x CVE like API
> mode). The Devices table is loaded as supplementary reference data.

### Step 2: Place CSVs in the export folder

Put both files in one folder -- either `powerbi/csv/` or any folder you
prefer (use `-CsvFolderPath` to specify):

```
my-exports/
  export-tvm-vulnerabilities.csv
  devices.csv
```

### Step 3: Generate and open the project

```powershell
cd powerbi
.\setup.ps1 -DataSource csv -Open
```

Or with a custom CSV folder and client label:

```powershell
.\setup.ps1 -DataSource csv -CsvFolderPath "C:\exports\defender" -TenantId "contoso" -Open
```

### Step 4: Refresh in Power BI

1. Click **Refresh** (or **Transform Data** -> **Close & Apply**)
2. If prompted about file privacy, set to **Organizational** -> **Connect**
3. Data loads from the CSVs -- no device compliance check needed

### Updating the data

Re-export the two CSVs from the Defender portal, drop them into the same
folder, and click **Refresh** in Power BI.

---

## Quick start -- API mode

Open PowerShell in the `powerbi/` folder and run:

```powershell
.\setup.ps1 -Open
```

With a client label (recommended -- names the output file per tenant):

```powershell
.\setup.ps1 -TenantId "contoso" -Open
```

This will:
1. Read all the Power Query (M) scripts from `queries/`
2. Build a complete `model.bim` with all queries, columns, and DAX measures
3. Generate a Power BI Project (`.pbip`) folder structure
4. Open it in Power BI Desktop

When Power BI opens:
1. Click **Refresh** (or **Transform Data** -> **Close & Apply**)
2. When prompted for credentials, choose **Organizational account** -> **Sign in**
3. Set privacy level to **Organizational** -> **Connect**
4. Data loads -- you're done

### Optional parameters

```powershell
# Custom enrichment file path
.\setup.ps1 -EnrichmentPath "C:\data\my-enrichment.json" -TenantId "contoso" -Open

# Custom Defender API base URL (e.g. for GCC tenants)
.\setup.ps1 -DefenderBaseUrl "https://api-gcc.securitycenter.microsoft.us" -Open
```

You can also change these later inside Power BI: **Transform Data** -> **Manage Parameters**.

---

## Manual setup (alternative)

### 1. Open Power BI Desktop -> Blank report

### 2. Create the helper function `fn_PaginatedGet`

1. **Home** -> **Transform data** (opens Power Query Editor)
2. **Home** -> **New Source** -> **Blank Query**
3. Right-click the new query in the left pane -> **Rename** -> `fn_PaginatedGet`
4. Click **Advanced Editor** and paste the contents of
   [`powerbi/queries/fn_PaginatedGet.pq`](queries/fn_PaginatedGet.pq)
5. Click **Done**

### 3. Create the data queries

Repeat for each file below (New Source -> Blank Query -> Advanced Editor -> paste):

| Query name | File |
|---|---|
| `Vulnerabilities` | [`queries/Vulnerabilities.pq`](queries/Vulnerabilities.pq) |
| `MachineVulnerabilities` | [`queries/MachineVulnerabilities.pq`](queries/MachineVulnerabilities.pq) |
| `Machines` | [`queries/Machines.pq`](queries/Machines.pq) |
| `Enrichment` | [`queries/Enrichment.pq`](queries/Enrichment.pq) |
| `EnrichmentDefaults` | [`queries/EnrichmentDefaults.pq`](queries/EnrichmentDefaults.pq) |
| `VRM_Report` | [`queries/VRM_Report.pq`](queries/VRM_Report.pq) |

> **Important:** The query names must match exactly -- `VRM_Report` references
> the other queries by name.

### 4. Configure parameters

In Power Query Editor, go to **Home** -> **Manage Parameters** and set:

- `TenantId` -> short name or Entra tenant ID of the client (e.g. `contoso`)
- `DefenderApiBaseUrl` -> `https://api.securitycenter.microsoft.com`
- `EnrichmentFilePath` -> absolute path to your `asset-enrichment.json`

### 5. Authenticate to the Defender API

When Power BI first tries to refresh, it will prompt for credentials:

1. Click **Edit Credentials**
2. Choose **Organizational account**
3. Click **Sign in** -- use your Microsoft 365 account
4. Set privacy level to **Organizational**
5. Click **Connect**

This uses your existing user permissions (delegated access). No app
registration or admin consent is needed -- if your account can see
vulnerabilities in the Defender portal, it works here.

### 6. Load the data

1. In Power Query Editor, select `VRM_Report` and verify the preview shows
   your report columns (Unique ID through Product)
2. Right-click the helper/staging queries (`fn_PaginatedGet`,
   `Vulnerabilities`, `MachineVulnerabilities`, `Machines`, `Enrichment`,
   `EnrichmentDefaults`) -> **Enable load** = unchecked (they feed
   `VRM_Report` but don't need their own tables in the model)
3. Click **Close & Apply**

### 7. Add DAX measures (optional)

The file [`powerbi/measures/dax-measures.dax`](measures/dax-measures.dax)
contains pre-built measures for summary KPIs. In the report view:

1. Select the `VRM_Report` table in the Fields pane
2. **Modeling** -> **New Measure**
3. Paste each measure one at a time

Key measures include:
- **Total Vulnerabilities** / **Unique CVEs** / **Unique Devices**
- **Critical Count**, **High Count**, **Exploitable Count**
- **Critical or Exploitable Unpatched** -- the most urgent items
- **Overdue Over 90 Days** -- SLA breaches
- **Avg Days Open** -- mean age of unpatched vulns
- **Risk Accepted Pct** -- % of vulns under exception

### 8. Build your report pages

**Suggested layout (Page 1 -- Executive Summary):**

| Visual | Data |
|---|---|
| Card | Total Vulnerabilities |
| Card | Critical or Exploitable Unpatched |
| Card | Overdue Over 90 Days |
| Card | Avg Days Open |
| Donut chart | Count by Criticality |
| Stacked bar | Count by Status |
| Stacked bar | Count by Device OS |

**Suggested layout (Page 2 -- Detail Table):**

| Visual | Data |
|---|---|
| Table / Matrix | All VRM_Report columns |
| Slicer | Criticality |
| Slicer | Status |
| Slicer | Device OS |
| Slicer | Location |

### 9. Schedule refresh (optional -- Power BI Service)

Publish to Power BI Service and configure a **scheduled refresh** (e.g.,
daily at 6 AM) using a data gateway so the report stays current.

---

## Switching between clients

Each client's data lives in a different Microsoft Defender tenant, which means
both the **OAuth credential** and the **enrichment file** must change when you
switch clients.  Follow these steps every time.

### Step 1: Generate a client-specific report file

Pass `-TenantId` when running `setup.ps1`.  This names the output `.pbip` after
the client so each tenant gets its own project -- they never share a credential
cache entry in Power BI Desktop:

```powershell
# API mode
.\setup.ps1 -TenantId "contoso" -Open

# CSV mode
.\setup.ps1 -DataSource csv -CsvFolderPath "C:\exports\contoso" `
            -TenantId "contoso" -Open
```

The generated file will be `VRM-Report-contoso.pbip`.  Running it again for
another client (e.g. `-TenantId "fabrikam"`) produces `VRM-Report-fabrikam.pbip`
as a completely separate file.

### Step 2: Clear the previous client's API credential (API mode only)

Power BI Desktop stores OAuth tokens globally per URL, not per report file.
Before opening a different tenant's report you **must** clear the cached
credential:

1. In Power BI Desktop go to **File -> Options & Settings -> Data Source Settings**
2. Select `https://api.securitycenter.microsoft.com`
3. Click **Clear Permissions** -> **Delete**
4. Click **Close**

### Step 3: Update the enrichment file (if not embedded in setup.ps1)

If the `EnrichmentFilePath` parameter still points to another client's JSON,
update it:

**Transform Data -> Manage Parameters -> EnrichmentFilePath**

Set it to the absolute path for this client's `asset-enrichment.json`.

### Step 4: Refresh and re-authenticate

Click **Refresh**.  Power BI will prompt: **Organizational account -> Sign in**
-- sign in with the new client's Microsoft 365 account.

> **Tip (CSV mode):** CSV mode has no OAuth prompt.  After updating the
> `CsvFolderPath` parameter and dropping in the new client's exports, just
> click **Refresh** -- no sign-in required.

### Quick-reference checklist

| # | Action | API mode | CSV mode |
|---|---|---|---|
| 1 | Re-run `setup.ps1 -TenantId <client>` to get a named `.pbip` | yes | yes |
| 2 | Clear credentials for `api.securitycenter.microsoft.com` | **Required** | Not needed |
| 3 | Update `EnrichmentFilePath` parameter | yes | yes |
| 4 | Update `CsvFolderPath` parameter to new client's export folder | -- | **Required** |
| 5 | Click Refresh and sign in with the new client's account | yes | yes |

---

## Troubleshooting

| Issue | Fix |
|---|---|
| **`az login` says no subscription found** | Ignore -- only a tenant login is needed. Re-run `fetch-defender-data.ps1`; the token is valid even without a subscription |
| **Error 50131 / "You can't get there from here"** | Conditional Access blocks unregistered devices. Use preloaded or CSV mode instead |
| **`fetch-defender-data.ps1` fails mid-download** | Re-run the script -- it overwrites each file on completion. Partial CSV files are replaced on the next run |
| **"Access to the resource is forbidden"** | Your account needs the Security Reader or Security Admin role in Defender for Endpoint |
| **Timeout on large tenants (API mode)** | In Power Query, edit `fn_PaginatedGet` and add `?$top=10000` to the initial URL to set explicit page size |
| **Enrichment file not found** | Check the `FilePath` variable in `Enrichment` and `EnrichmentDefaults` queries -- use an absolute path |
| **Column "X" not found** | Ensure query names match exactly (case-sensitive): `fn_PaginatedGet`, `Vulnerabilities`, `MachineVulnerabilities`, `Machines`, `Enrichment`, `EnrichmentDefaults`, `VRM_Report` |

---

## Files reference

```
powerbi/
  fetch-defender-data.ps1        <- downloads API data as CSVs (preloaded mode)
  setup.ps1                      <- run this to generate the PBIP project
  VRM-Report.pbip                <- (generated) open in Power BI Desktop
  VRM-Report-<tenant>.pbip       <- (generated) per-client file when -TenantId is used
  VRM-Report.SemanticModel/      <- (generated) semantic model definition
  VRM-Report.Report/             <- (generated) report definition
  csv/
    <tenantId>/                  <- per-client CSVs from fetch-defender-data.ps1
      machines.csv
      vulnerabilities.csv
      machineVulnerabilities.csv
  queries/
    fn_PaginatedGet.pq           <- reusable paginated API call function (API mode)
    Vulnerabilities.pq           <- GET /api/vulnerabilities (API mode)
    MachineVulnerabilities.pq    <- GET /api/vulnerabilities/machinesVulnerabilities (API mode)
    Machines.pq                  <- GET /api/machines (API mode)
    Enrichment.pq                <- business-context JSON loader
    EnrichmentDefaults.pq        <- default values from enrichment JSON
    VRM_Report.pq                <- main report: joins + columns A-O (API and preloaded modes)
    csv/
      Vulnerabilities_CSV.pq     <- load export-tvm-vulnerabilities.csv (csv mode)
      Machines_CSV.pq            <- load devices.csv (csv mode)
      VRM_Report_CSV.pq          <- CVE-level report from portal CSV data
    preloaded/
      Vulnerabilities_preloaded.pq          <- load vulnerabilities.csv (preloaded mode)
      MachineVulnerabilities_preloaded.pq   <- load machineVulnerabilities.csv
      Machines_preloaded.pq                 <- load machines.csv
  measures/
    dax-measures.dax             <- DAX measures reference (embedded by setup.ps1)
  SETUP.md                       <- this file
```