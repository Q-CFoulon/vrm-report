/**
 * Defender for Endpoint API client.
 *
 * Wraps the four vulnerability endpoints:
 *   GET /api/vulnerabilities
 *   GET /api/vulnerabilities/machinesVulnerabilities
 *   GET /api/vulnerabilities/{cveId}
 *   GET /api/vulnerabilities/{cveId}/machineReferences
 *
 * Handles OData pagination ($top / $skip / @odata.nextLink) automatically.
 */

import axios, { type AxiosInstance } from 'axios';
import type { AppConfig } from '../config/settings';
import type {
  DefenderVulnerability,
  MachineVulnerability,
  MachineReference,
  ODataResponse,
} from '../types';
import { AuthService } from './auth.service';
import { getLogger } from '../utils/logger';

const PAGE_SIZE = 8000; // max supported by the API

export class DefenderApiService {
  private authService: AuthService;
  private client: AxiosInstance;

  constructor(config: AppConfig, authService: AuthService) {
    this.authService = authService;
    this.client = axios.create({
      baseURL: config.defender.baseUrl,
      timeout: 120_000,
    });
  }

  // -- Internal helpers -----------------------------------------------------

  private async authHeaders(): Promise<Record<string, string>> {
    const token = await this.authService.getToken();
    return { Authorization: `Bearer ${token}` };
  }

  /**
   * Generic paginated GET — follows @odata.nextLink until all pages are
   * fetched, or uses $top/$skip when nextLink is absent.
   */
  private async paginatedGet<T>(path: string): Promise<T[]> {
    const logger = getLogger();
    const results: T[] = [];
    let url: string | null = path;
    let skip = 0;

    while (url) {
      let requestUrl: string;
      if (url.startsWith('http')) {
        requestUrl = url;
      } else {
        const separator = url.includes('?') ? '&' : '?';
        requestUrl = `${url}${separator}$top=${PAGE_SIZE}&$skip=${skip}`;
      }

      logger.debug(`GET ${requestUrl}`);
      const headers = await this.authHeaders();
      const response = await this.client.get<ODataResponse<T>>(requestUrl, { headers });
      const data = response.data;

      if (data.value) {
        results.push(...data.value);
      }

      if (data['@odata.nextLink']) {
        url = data['@odata.nextLink'];
        skip = 0; // nextLink already contains pagination
      } else if (data.value && data.value.length === PAGE_SIZE) {
        skip += PAGE_SIZE;
      } else {
        url = null;
      }
    }

    logger.info(`Fetched ${results.length} records from ${path}`);
    return results;
  }

  // -- Public API methods ---------------------------------------------------

  /**
   * GET /api/vulnerabilities
   * Returns all vulnerabilities in the tenant.
   */
  async getAllVulnerabilities(): Promise<DefenderVulnerability[]> {
    return this.paginatedGet<DefenderVulnerability>('/api/vulnerabilities');
  }

  /**
   * GET /api/vulnerabilities/machinesVulnerabilities
   * Returns all vulnerability ↔ machine ↔ software mappings.
   */
  async getAllMachineVulnerabilities(): Promise<MachineVulnerability[]> {
    return this.paginatedGet<MachineVulnerability>(
      '/api/vulnerabilities/machinesVulnerabilities',
    );
  }

  /**
   * GET /api/vulnerabilities/{cveId}
   * Returns details for a single vulnerability.
   */
  async getVulnerabilityById(cveId: string): Promise<DefenderVulnerability> {
    const headers = await this.authHeaders();
    const { data } = await this.client.get<DefenderVulnerability>(
      `/api/vulnerabilities/${encodeURIComponent(cveId)}`,
      { headers },
    );
    return data;
  }

  /**
   * GET /api/vulnerabilities/{cveId}/machineReferences
   * Returns machines affected by a specific CVE.
   */
  async getMachinesByVulnerability(cveId: string): Promise<MachineReference[]> {
    return this.paginatedGet<MachineReference>(
      `/api/vulnerabilities/${encodeURIComponent(cveId)}/machineReferences`,
    );
  }
}
