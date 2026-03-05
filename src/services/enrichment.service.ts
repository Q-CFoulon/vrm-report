/**
 * Enrichment service — loads business-context data from a local JSON file and
 * merges it onto VRM report rows.
 *
 * Fields like Data Type, Location, Device Type, Asset Criticality, and Notes
 * are not available from the Defender API and must be maintained by the
 * operator in the enrichment file.
 */

import * as fs from 'fs';
import type { EnrichmentFile, AssetEnrichment } from '../types';
import type { AssetCriticality, AssetLocation, DataType, DeviceType } from '../types';
import { getLogger } from '../utils/logger';

export class EnrichmentService {
  private enrichment: EnrichmentFile;
  private lookupMap = new Map<string, AssetEnrichment>();

  constructor(enrichmentFilePath: string) {
    const logger = getLogger();

    if (!fs.existsSync(enrichmentFilePath)) {
      logger.warn(
        `Enrichment file not found at ${enrichmentFilePath} — using defaults only.`,
      );
      this.enrichment = {
        defaults: {
          assetCriticality: 'Moderate Impact',
          dataType: 'End Point User',
          location: 'Internal',
          deviceType: 'Desktop',
        },
        assets: [],
      };
    } else {
      const raw = fs.readFileSync(enrichmentFilePath, 'utf-8');
      this.enrichment = JSON.parse(raw) as EnrichmentFile;
      logger.info(
        `Loaded ${this.enrichment.assets.length} enrichment entries from ${enrichmentFilePath}`,
      );
    }

    // Build lookup map
    for (const asset of this.enrichment.assets) {
      this.lookupMap.set(
        this.normalizeKey(asset.matchType, asset.matchKey),
        asset,
      );
    }
  }

  private normalizeKey(matchType: string, key: string): string {
    return `${matchType}::${key.toLowerCase()}`;
  }

  /**
   * Find the best enrichment match for a machine, trying hostname first, then
   * machine ID, then RBAC group.
   */
  findEnrichment(
    hostname?: string,
    machineId?: string,
    rbacGroup?: string,
    ipAddress?: string,
  ): AssetEnrichment | undefined {
    if (hostname) {
      const match = this.lookupMap.get(this.normalizeKey('hostname', hostname));
      if (match) return match;
    }
    if (machineId) {
      const match = this.lookupMap.get(this.normalizeKey('machineId', machineId));
      if (match) return match;
    }
    if (rbacGroup) {
      const match = this.lookupMap.get(this.normalizeKey('rbacGroup', rbacGroup));
      if (match) return match;
    }
    if (ipAddress) {
      const match = this.lookupMap.get(this.normalizeKey('ipAddress', ipAddress));
      if (match) return match;
    }
    return undefined;
  }

  /** Column F default */
  get defaultDeviceType(): DeviceType {
    return this.enrichment.defaults.deviceType;
  }

  /** Column K default */
  get defaultAssetCriticality(): AssetCriticality {
    return this.enrichment.defaults.assetCriticality;
  }

  /** Column L default */
  get defaultDataType(): DataType {
    return this.enrichment.defaults.dataType;
  }

  /** Column M default */
  get defaultLocation(): AssetLocation {
    return this.enrichment.defaults.location;
  }
}
