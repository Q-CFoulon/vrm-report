/**
 * Microsoft Defender for Endpoint API response types.
 * Based on:
 *   GET /api/vulnerabilities
 *   GET /api/vulnerabilities/machinesVulnerabilities
 *   GET /api/vulnerabilities/{cveId}
 *   GET /api/vulnerabilities/{cveId}/machineReferences
 *   Machine resource type
 */

// -- OData wrapper ----------------------------------------------------------

export interface ODataResponse<T> {
  '@odata.context': string;
  value: T[];
  '@odata.nextLink'?: string;
}

// -- GET /api/vulnerabilities -----------------------------------------------

export interface DefenderVulnerability {
  id: string;                 // e.g. "CVE-2024-7256"
  name: string;
  description: string;
  severity: VulnerabilitySeverity;
  cvssV3: number;
  cvssVector: string;
  exposedMachines: number;
  publishedOn: string;        // ISO 8601
  updatedOn: string;          // ISO 8601
  firstDetected: string;      // ISO 8601
  publicExploit: boolean;
  exploitVerified: boolean;
  exploitInKit: boolean;
  exploitTypes: string[];
  exploitUris: string[];
  cveSupportability: string;
  tags: string[];
  epss: number;
  status: VulnerabilityStatus;
}

export type VulnerabilitySeverity = 'Critical' | 'High' | 'Medium' | 'Low' | 'None';

export type VulnerabilityStatus =
  | 'RemediationRequired'
  | 'NoActionRequired'
  | 'UnderException'
  | 'PartialException';

// -- GET /api/vulnerabilities/machinesVulnerabilities -----------------------

export interface MachineVulnerability {
  id: string;                 // composite key
  cveId: string;
  machineId: string;
  fixingKbId: string | null;
  productName: string;
  productVendor: string;
  productVersion: string;
  severity: VulnerabilitySeverity;
}

// -- GET /api/vulnerabilities/{cveId}/machineReferences --------------------

export interface MachineReference {
  id: string;                 // machineId
  computerDnsName: string;
  osPlatform: string;         // e.g. "Windows10", "Windows11", "Linux"
  rbacGroupName: string;
}

// -- Machine resource type --------------------------------------------------

export interface DefenderMachine {
  id: string;
  computerDnsName: string;
  firstSeen: string;
  lastSeen: string;
  osPlatform: string;
  onboardingStatus: string;
  osProcessor: string;
  osArchitecture: string;
  version: string;
  osBuild: number | null;
  lastIpAddress: string;
  lastExternalIpAddress: string;
  healthStatus: MachineHealthStatus;
  rbacGroupName: string;
  rbacGroupId: string;
  riskScore: MachineRiskScore;
  aadDeviceId: string | null;
  machineTags: string[];
  exposureLevel: ExposureLevel;
  deviceValue: DeviceValue;
  ipAddresses: IpAddress[];
}

export type MachineHealthStatus =
  | 'Active'
  | 'Inactive'
  | 'ImpairedCommunication'
  | 'NoSensorData'
  | 'NoSensorDataImpairedCommunication'
  | 'Unknown';

export type MachineRiskScore = 'None' | 'Informational' | 'Low' | 'Medium' | 'High';
export type ExposureLevel = 'None' | 'Low' | 'Medium' | 'High';
export type DeviceValue = 'Normal' | 'Low' | 'High';

export interface IpAddress {
  ipAddress: string;
  macAddress: string;
  type: string;
  operationalStatus: string;
}
