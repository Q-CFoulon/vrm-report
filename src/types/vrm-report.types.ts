/**
 * VRM Report row types — maps 1:1 to the spreadsheet columns (A–O) from the
 * report specification image.
 */

// Column B: Criticality
export type Criticality = 'Critical' | 'High' | 'Exploitable' | 'Medium' | 'Low';

// Column E: Device OS
export type DeviceOS =
  | 'Windows 11'
  | 'Windows 10'
  | 'Windows Server 2022'
  | 'Windows Server 2019'
  | 'Windows Server 2016'
  | 'Linux'
  | 'macOS'
  | 'iOS'
  | 'Android'
  | string; // allow unmapped values

// Column F: Device Type
export type DeviceType =
  | 'Mobile Phone'
  | 'Tablet'
  | 'Laptop'
  | 'Desktop'
  | 'Server'
  | 'VM'
  | 'Firewall'
  | 'IoT'
  | 'Network Device'
  | string;

// Column I: Remediation Status
export type RemediationStatus =
  | 'Patched'
  | 'Pending < 1 month'
  | 'Pending > 1 month'
  | 'Pending > 2 months'
  | 'Pending > 3 months'
  | 'Resurfaced';

// Column J: Risk Acceptance
export type RiskAcceptance = 'Yes' | 'No';

// Column K: Asset Criticality to the business
export type AssetCriticality = 'Critical Impact' | 'Moderate Impact' | 'Low Impact';

// Column L: Data Type
export type DataType = 'IP' | 'PII' | 'CUI' | 'End Point User' | 'Finance' | 'Code' | string;

// Column M: Location
export type AssetLocation = 'Internal' | 'External' | 'Customer Facing';

/**
 * One row in the final VRM report.  Columns A–O as described in the
 * specification image.
 */
export interface VrmReportRow {
  /** A – Unique identifier (auto-increment or ID from scanning tool) */
  uniqueId: string;

  /** B – Criticality */
  criticality: Criticality;

  /** C – CVE# / CVSS# / ID# */
  cveId: string;
  cvssScore: number;

  /** D – Vulnerability description */
  description: string;

  /** E – Device OS */
  deviceOS: DeviceOS;

  /** F – Device Type */
  deviceType: DeviceType;

  /** G – Date first detected (ISO string) */
  dateFirstDetected: string;

  /** H – Date last detected (ISO string) */
  dateLastDetected: string;

  /** I – Status (remediation/aging) */
  status: RemediationStatus;

  /** J – Risk Acceptance */
  riskAcceptance: RiskAcceptance;

  /** K – Asset Criticality to the business */
  assetCriticality: AssetCriticality;

  /** L – Data Type */
  dataType: DataType;

  /** M – Location */
  location: AssetLocation;

  /** N – Notes (free-form) */
  notes: string;

  // -- Extra metadata (not displayed as primary columns but useful) ---------// o – Machine name (for traceability)
  machineName: string;
  /** Machine ID from Defender */
  machineId: string;
  /** Product / software name affected */
  productName: string;
}

/**
 * Summary statistics for the executive section of the report.
 */
export interface VrmReportSummary {
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  exploitableCount: number;
  pendingOver30Days: number;
  pendingOver60Days: number;
  pendingOver90Days: number;
  patchedCount: number;
  riskAcceptedCount: number;
  uniqueMachinesAffected: number;
  generatedAt: string;
}
