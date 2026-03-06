# VRM Report — Power BI Setup Guide

This guide walks you through setting up the Power BI VRM report that pulls
data from **Microsoft Defender for Endpoint** — either live via the REST API
or offline via CSV exports from the Defender portal.

---

## Prerequisites

| Requirement | Details |
|---|---|
| **Power BI Desktop** | Latest version (free download from Microsoft) |
| **Data source** | **API mode:** Microsoft 365 account with Security Reader role, **OR** **CSV mode:** exported CSVs from the Defender portal |
| **Enrichment file** | Copy `data/enrichment/asset-enrichment.example.json` → `asset-enrichment.json` and customise it for your environment |

---

## Quick start — CSV mode (recommended if device compliance blocks API)

If your organization enforces Conditional Access (e.g. registered devices
only), use CSV mode to bypass the OAuth flow entirely.

### Step 1: Export CSVs from the Defender portal

Sign in at [security.microsoft.com](https://security.microsoft.com) on a
compliant device (or via browser) and export two files:

| Export | Portal path | Expected filename |
|---|---|---|
| **Weaknesses** | Vulnerability Management → Weaknesses → Export | `export-tvm-vulnerabilities.csv` |
| **Devices** | Assets → Devices → Export | `devices.csv` |

> **Note:** CSV mode produces one row per CVE (not per device×CVE like API
> mode). The Devices table is loaded as supplementary reference data.

### Step 2: Place CSVs in the export folder

Put both files in one folder — either `powerbi/csv/` or any folder you
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

Or with a custom CSV folder:

```powershell
.\setup.ps1 -DataSource csv -CsvFolderPath "C:\exports\defender" -Open
```

### Step 4: Refresh in Power BI

1. Click **Refresh** (or **Transform Data** → **Close & Apply**)
2. If prompted about file privacy, set to **Organizational** → **Connect**
3. Data loads from the CSVs — no device compliance check needed

### Updating the data

Re-export the two CSVs from the Defender portal, drop them into the same
folder, and click **Refresh** in Power BI.

---

## Quick start — API mode

Open PowerShell in the `powerbi/` folder and run:

```powershell
.\setup.ps1 -Open
```

This will:
1. Read all the Power Query (M) scripts from `queries/`
2. Build a complete `model.bim` with all queries, columns, and DAX measures
3. Generate a Power BI Project (`.pbip`) folder structure
4. Open it in Power BI Desktop

When Power BI opens:
1. Click **Refresh** (or **Transform Data** → **Close & Apply**)
2. When prompted for credentials, choose **Organizational account** → **Sign in**
3. Set privacy level to **Organizational** → **Connect**
4. Data loads — you're done

### Optional parameters

```powershell
# Custom enrichment file path
.\setup.ps1 -EnrichmentPath "C:\data\my-enrichment.json" -Open

# Custom Defender API base URL (e.g. for GCC tenants)
.\setup.ps1 -DefenderBaseUrl "https://api-gcc.securitycenter.microsoft.us" -Open
```

You can also change these later inside Power BI: **Transform Data** → **Manage Parameters**.

---

## Manual setup (alternative)

### 1. Open Power BI Desktop → Blank report

### 2. Create the helper function `fn_PaginatedGet`

1. **Home** → **Transform data** (opens Power Query Editor)
2. **Home** → **New Source** → **Blank Query**
3. Right-click the new query in the left pane → **Rename** → `fn_PaginatedGet`
4. Click **Advanced Editor** and paste the contents of
   [`powerbi/queries/fn_PaginatedGet.pq`](queries/fn_PaginatedGet.pq)
5. Click **Done**

### 3. Create the data queries

Repeat for each file below (New Source → Blank Query → Advanced Editor → paste):

| Query name | File |
|---|---|
| `Vulnerabilities` | [`queries/Vulnerabilities.pq`](queries/Vulnerabilities.pq) |
| `MachineVulnerabilities` | [`queries/MachineVulnerabilities.pq`](queries/MachineVulnerabilities.pq) |
| `Machines` | [`queries/Machines.pq`](queries/Machines.pq) |
| `Enrichment` | [`queries/Enrichment.pq`](queries/Enrichment.pq) |
| `EnrichmentDefaults` | [`queries/EnrichmentDefaults.pq`](queries/EnrichmentDefaults.pq) |
| `VRM_Report` | [`queries/VRM_Report.pq`](queries/VRM_Report.pq) |

> **Important:** The query names must match exactly — `VRM_Report` references
> the other queries by name.

### 4. Configure parameters

In Power Query Editor, go to **Home** → **Manage Parameters** and set:

- `DefenderApiBaseUrl` → `https://api.securitycenter.microsoft.com`
- `EnrichmentFilePath` → absolute path to your `asset-enrichment.json`

### 5. Authenticate to the Defender API

When Power BI first tries to refresh, it will prompt for credentials:

1. Click **Edit Credentials**
2. Choose **Organizational account**
3. Click **Sign in** — use your Microsoft 365 account
4. Set privacy level to **Organizational**
5. Click **Connect**

This uses your existing user permissions (delegated access). No app
registration or admin consent is needed — if your account can see
vulnerabilities in the Defender portal, it works here.

### 6. Load the data

1. In Power Query Editor, select `VRM_Report` and verify the preview shows
   your report columns (Unique ID through Product)
2. Right-click the helper/staging queries (`fn_PaginatedGet`,
   `Vulnerabilities`, `MachineVulnerabilities`, `Machines`, `Enrichment`,
   `EnrichmentDefaults`) → **Enable load** = unchecked (they feed
   `VRM_Report` but don't need their own tables in the model)
3. Click **Close & Apply**

### 7. Add DAX measures (optional)

The file [`powerbi/measures/dax-measures.dax`](measures/dax-measures.dax)
contains pre-built measures for summary KPIs. In the report view:

1. Select the `VRM_Report` table in the Fields pane
2. **Modeling** → **New Measure**
3. Paste each measure one at a time

Key measures include:
- **Total Vulnerabilities** / **Unique CVEs** / **Unique Devices**
- **Critical Count**, **High Count**, **Exploitable Count**
- **Critical or Exploitable Unpatched** — the most urgent items
- **Overdue Over 90 Days** — SLA breaches
- **Avg Days Open** — mean age of unpatched vulns
- **Risk Accepted Pct** — % of vulns under exception

### 8. Build your report pages

**Suggested layout (Page 1 — Executive Summary):**

| Visual | Data |
|---|---|
| Card | Total Vulnerabilities |
| Card | Critical or Exploitable Unpatched |
| Card | Overdue Over 90 Days |
| Card | Avg Days Open |
| Donut chart | Count by Criticality |
| Stacked bar | Count by Status |
| Stacked bar | Count by Device OS |

**Suggested layout (Page 2 — Detail Table):**

| Visual | Data |
|---|---|
| Table / Matrix | All VRM_Report columns |
| Slicer | Criticality |
| Slicer | Status |
| Slicer | Device OS |
| Slicer | Location |

### 9. Schedule refresh (optional — Power BI Service)

Publish to Power BI Service and configure a **scheduled refresh** (e.g.,
daily at 6 AM) using a data gateway so the report stays current.

---

## Troubleshooting

| Issue | Fix |
|---|---|
| **Error 50131 / "You can't get there from here"** | Conditional Access blocks unregistered devices. Use CSV mode instead: `.\setup.ps1 -DataSource csv -Open` |
| **"Access to the resource is forbidden"** | Your account needs the Security Reader or Security Admin role in Defender for Endpoint |
| **Timeout on large tenants** | In Power Query, edit `fn_PaginatedGet` and add `?$top=10000` to the initial URL to set explicit page size |
| **Enrichment file not found** | Check the `FilePath` variable in `Enrichment` and `EnrichmentDefaults` queries — use an absolute path |
| **Column "X" not found** | Ensure query names match exactly (case-sensitive): `fn_PaginatedGet`, `Vulnerabilities`, `MachineVulnerabilities`, `Machines`, `Enrichment`, `EnrichmentDefaults`, `VRM_Report` |

---

## Files reference

```
powerbi/
  setup.ps1                      ← run this to generate the PBIP project
  VRM-Report.pbip                ← (generated) open in Power BI Desktop
  VRM-Report.SemanticModel/      ← (generated) semantic model definition
  VRM-Report.Report/             ← (generated) report definition
  csv/                           ← drop exported CSVs here (csv mode)
  queries/
    fn_PaginatedGet.pq           ← reusable paginated API call function (API mode)
    Vulnerabilities.pq           ← GET /api/vulnerabilities (API mode)
    MachineVulnerabilities.pq    ← GET /api/vulnerabilities/machinesVulnerabilities (API mode)
    Machines.pq                  ← GET /api/machines (API mode)
    Enrichment.pq                ← business-context JSON loader
    EnrichmentDefaults.pq        ← default values from enrichment JSON
    VRM_Report.pq                ← main report: joins + columns A–O (API mode)
    csv/
      Vulnerabilities_CSV.pq     ← load export-tvm-vulnerabilities.csv
      Machines_CSV.pq            ← load devices.csv
      VRM_Report_CSV.pq          ← CVE-level report from CSV data
  measures/
    dax-measures.dax             ← DAX measures reference (embedded by setup.ps1)
  SETUP.md                       ← this file
```
