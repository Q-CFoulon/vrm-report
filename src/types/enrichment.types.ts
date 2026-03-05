/**
 * Enrichment data types.
 *
 * Because some VRM report columns (Data Type, Location, Device Type, Asset
 * Criticality, Notes) are business-context fields that the Defender API does
 * not provide, they are sourced from a local enrichment file that the operator
 * maintains.
 *
 * Enrichment can be keyed by machine hostname, machine ID, RBAC group, or
 * IP address.
 */

import type { AssetCriticality, AssetLocation, DataType, DeviceType } from './vrm-report.types';

/**
 * One enrichment entry – keyed by machine identifier.
 */
export interface AssetEnrichment {
  /** Match key – machine DNS name, machine ID, or RBAC group name */
  matchKey: string;

  /** How the matchKey should be interpreted */
  matchType: 'hostname' | 'machineId' | 'rbacGroup' | 'ipAddress';

  /** Column F override */
  deviceType?: DeviceType;

  /** Column K override */
  assetCriticality?: AssetCriticality;

  /** Column L override */
  dataType?: DataType;

  /** Column M override */
  location?: AssetLocation;

  /** Column N – any standing notes */
  notes?: string;
}

/**
 * Schema for the enrichment JSON file.
 */
export interface EnrichmentFile {
  /**
   * Default values applied when no specific match is found.
   */
  defaults: {
    assetCriticality: AssetCriticality;
    dataType: DataType;
    location: AssetLocation;
    deviceType: DeviceType;
  };

  /**
   * Per-asset enrichment entries.
   */
  assets: AssetEnrichment[];
}
