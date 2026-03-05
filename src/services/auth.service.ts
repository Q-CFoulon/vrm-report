/**
 * MSAL-based authentication service for Microsoft Defender for Endpoint APIs.
 * Uses client-credential flow (application permissions).
 */

import { ConfidentialClientApplication } from '@azure/msal-node';
import type { AppConfig } from '../config/settings';
import { getLogger } from '../utils/logger';

export class AuthService {
  private cca: ConfidentialClientApplication;
  private scope: string;
  private cachedToken: string | null = null;
  private tokenExpiry = 0;

  constructor(config: AppConfig) {
    this.scope = config.defender.scope;

    this.cca = new ConfidentialClientApplication({
      auth: {
        clientId: config.azure.clientId,
        authority: `https://login.microsoftonline.com/${config.azure.tenantId}`,
        clientSecret: config.azure.clientSecret,
      },
    });
  }

  /**
   * Acquire an access token for the Defender for Endpoint API.
   * Caches the token until 5 minutes before expiry.
   */
  async getToken(): Promise<string> {
    const logger = getLogger();
    const now = Date.now();

    if (this.cachedToken && now < this.tokenExpiry - 5 * 60 * 1000) {
      return this.cachedToken;
    }

    logger.info('Acquiring new access token via client credentials...');

    const result = await this.cca.acquireTokenByClientCredential({
      scopes: [this.scope],
    });

    if (!result?.accessToken) {
      throw new Error('Failed to acquire access token — check your Entra ID app registration and credentials.');
    }

    this.cachedToken = result.accessToken;
    this.tokenExpiry = result.expiresOn
      ? result.expiresOn.getTime()
      : now + 60 * 60 * 1000;

    logger.info('Access token acquired successfully.');
    return this.cachedToken;
  }
}
