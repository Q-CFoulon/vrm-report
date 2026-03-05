# VRM Report Generator

Vulnerability Risk Management (VRM) report generator that pulls data from **Microsoft Defender for Endpoint** APIs, enriches it with business context, and produces a structured Excel/CSV report for risk-informed decision-making.

## Report Columns

The generated report maps to the following columns:

| Column | Field | Source |
|--------|-------|--------|
| A | **Unique ID** | Auto-incremented row number |
| B | **Criticality** | Defender severity + exploit status → Critical, High, Exploitable, Medium, Low |
| C | **CVE# / CVSS#** | CVE identifier and CVSS v3 score from Defender |
| D | **Vulnerability Description** | Full description from Defender |
| E | **Device OS** | Machine `osPlatform` (Windows 11, Server 2016, Linux, iOS, etc.) |
| F | **Device Type** | Enrichment file → Mobile Phone, Laptop, Server, VM, Firewall, IoT, Network Device |
| G | **Date First Detected** | `firstDetected` from Defender |
| H | **Date Last Detected** | `updatedOn` from Defender |
| I | **Status** | Computed aging: Patched, Pending < 1 month, > 1 month, > 2 months, > 3 months |
| J | **Risk Acceptance** | Yes if CVE is under exception in Defender, otherwise No |
| K | **Asset Criticality** | Enrichment file → Critical Impact, Moderate Impact, Low Impact |
| L | **Data Type** | Enrichment file → IP, PII, CUI, End Point User, Finance, Code |
| M | **Location** | Enrichment file → Internal, External, Customer Facing |
| N | **Notes** | Enrichment file → free-form notes |

## Defender for Endpoint APIs Used

| Endpoint | Purpose |
|----------|---------|
| `GET /api/vulnerabilities` | All vulnerabilities in the tenant |
| `GET /api/vulnerabilities/machinesVulnerabilities` | Vulnerability ↔ machine ↔ software mappings |
| `GET /api/vulnerabilities/{cveId}` | Single CVE detail lookup |
| `GET /api/vulnerabilities/{cveId}/machineReferences` | Machines affected by a specific CVE |

Reference: [Defender for Endpoint API docs](https://learn.microsoft.com/en-us/defender-endpoint/api/get-all-vulnerabilities)

## Prerequisites

1. **Node.js** ≥ 18
2. **Microsoft Entra ID App Registration** with:
   - **Interactive mode (default):** Delegated permission `Vulnerability.Read` + "Allow public client flows" enabled
   - **Client-credential mode:** Application permission `Vulnerability.Read.All` + admin consent + client secret
3. **Microsoft Defender for Endpoint** Plan 1 or Plan 2 license

## Setup

```bash
# Clone the repo
git clone <repo-url> vrm-report
cd vrm-report

# Install dependencies
npm install

# Copy and configure environment variables
cp .env.example .env
# Edit .env with your tenant ID and client ID
# For interactive login (default): no client secret needed
# For client-credential mode: also set AZURE_CLIENT_SECRET and AUTH_MODE=client_credential
```

## Enrichment File

Business-context fields (Device Type, Asset Criticality, Data Type, Location, Notes) are not available from the Defender API. Maintain them in `data/enrichment/asset-enrichment.json`.

Copy the example and customize:

```bash
cp data/enrichment/asset-enrichment.example.json data/enrichment/asset-enrichment.json
```

Enrichment entries can be matched by:
- **hostname** — machine DNS name
- **machineId** — Defender machine ID
- **rbacGroup** — Defender RBAC group name (applies to all machines in the group)
- **ipAddress** — machine IP address

See `data/enrichment/asset-enrichment.example.json` for the full schema.

## Usage

### Validate API Connectivity

```bash
npm run validate
```

Tests token acquisition and API access. In interactive mode, this will display a device code and URL — open the URL in your browser and sign in with your credentials. Run this first to confirm your permissions are correct.

### Generate Report

```bash
# Excel report only
npm run generate

# Excel + CSV
npx ts-node src/index.ts generate --csv

# Custom output directory
npx ts-node src/index.ts generate --output ./reports
```

Reports are written to the `output/` directory by default.

### Output

- **Excel (.xlsx)** — Two sheets:
  - *Executive Summary* — Key metrics (critical count, aging buckets, patched count, etc.)
  - *VRM Detail* — Full row-level data with conditional formatting and auto-filters
- **CSV** — Flat export for SIEM or downstream tooling

## Project Structure

```
vrm-report/
├── src/
│   ├── index.ts                    # CLI entry point (generate / validate)
│   ├── config/settings.ts          # Environment configuration
│   ├── types/                      # TypeScript interfaces
│   │   ├── defender-api.types.ts   # Defender API response shapes
│   │   ├── vrm-report.types.ts     # VRM report row (columns A–O)
│   │   └── enrichment.types.ts     # Asset enrichment schema
│   ├── services/
│   │   ├── auth.service.ts         # MSAL auth (interactive device-code + client-credential)
│   │   ├── defender-api.service.ts # Paginated Defender API client
│   │   ├── enrichment.service.ts   # Business-context enrichment loader
│   │   └── report.service.ts       # Excel + CSV report generation
│   ├── mappers/
│   │   └── vulnerability.mapper.ts # API data → VRM rows
│   └── utils/
│       ├── date.utils.ts           # Aging calculation & date formatting
│       └── logger.ts               # Winston logger
├── data/enrichment/                # Enrichment JSON files
├── output/                         # Generated reports
├── .env.example                    # Environment template
└── package.json
```

## Permissions Required

| Permission Type | Permission | Description |
|----------------|------------|-------------|
| Application | `Vulnerability.Read.All` | Read Threat and Vulnerability Management vulnerability information |
| Delegated | `Vulnerability.Read` | Read Threat and Vulnerability Management vulnerability information |

**Interactive mode (default):** The app registration needs delegated `Vulnerability.Read` permission and "Allow public client flows" enabled in the app registration's Authentication settings.

**Client-credential mode:** The app registration needs application `Vulnerability.Read.All` permission with admin consent. See [Use Microsoft Defender for Endpoint APIs](https://learn.microsoft.com/en-us/defender-endpoint/api/apis-intro) for setup instructions.

## Security Notes

- Interactive device-code flow is the default — no client secret needed
- Credentials are loaded from environment variables only (never hardcoded)
- The `.env` file is excluded from git via `.gitignore`
- Access tokens are cached in memory and refreshed automatically
- No secrets are written to report output files
- OData query parameters are used as documented — no raw string interpolation
