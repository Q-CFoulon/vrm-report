/**
 * Authentication service for Microsoft Defender for Endpoint APIs.
 *
 * Supports two flows:
 *   - **Interactive (device-code)** — default. Uses @azure/identity
 *     DeviceCodeCredential so the user signs in via browser.
 *     Requires delegated permission `Vulnerability.Read`.
 *   - **Client-credential** — set AUTH_MODE=client_credential in .env and
 *     provide AZURE_CLIENT_SECRET. Uses MSAL ConfidentialClientApplication
 *     with application permission `Vulnerability.Read.All`.
 */

import { DeviceCodeCredential } from '@azure/identity';
import { ConfidentialClientApplication } from '@azure/msal-node';
import type { AppConfig } from '../config/settings';
import { getLogger } from '../utils/logger';

export class AuthService {
  private config: AppConfig;
  private cachedToken: string | null = null;
  private tokenExpiry = 0;
  private deviceCodeCredential: DeviceCodeCredential | null = null;

  constructor(config: AppConfig) {
    this.config = config;
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

    if (this.config.authMode === 'client_credential') {
      return this.acquireViaClientCredential();
    }

    return this.acquireViaDeviceCode();
  }

  // -- Device-code (interactive) flow via @azure/identity -------------------

  private async acquireViaDeviceCode(): Promise<string> {
    const logger = getLogger();
    const scope = this.config.defender.delegatedScope;
    logger.info('Starting interactive device-code sign-in...');
    logger.debug(`Scope: ${scope}`);

    if (!this.deviceCodeCredential) {
      this.deviceCodeCredential = new DeviceCodeCredential({
        tenantId: this.config.azure.tenantId,
        clientId: this.config.azure.clientId,
        userPromptCallback: (info) => {
          console.log('\n========================================');
          console.log(info.message);
          console.log('========================================\n');
        },
      });
    }

    try {
      const token = await this.deviceCodeCredential.getToken(scope);
      this.cachedToken = token.token;
      this.tokenExpiry = token.expiresOnTimestamp;
      logger.info('Access token acquired successfully.');
      return this.cachedToken;
    } catch (err: any) {
      logger.error(`Device-code auth failed: ${err.message}`);
      logger.error(
        'Ensure your app registration has:\n' +
        '  1. Authentication > "Allow public client flows" = Yes\n' +
        '  2. API permissions > WindowsDefenderATP > Delegated > Vulnerability.Read\n' +
        '  3. Admin consent granted for the permission',
      );
      throw err;
    }
  }

  // -- Client-credential flow -----------------------------------------------

  private async acquireViaClientCredential(): Promise<string> {
    const logger = getLogger();
    logger.info('Acquiring token via client-credential flow...');

    if (!this.config.azure.clientSecret) {
      throw new Error(
        'AUTH_MODE is client_credential but AZURE_CLIENT_SECRET is not set.',
      );
    }

    const cca = new ConfidentialClientApplication({
      auth: {
        clientId: this.config.azure.clientId,
        authority: `https://login.microsoftonline.com/${this.config.azure.tenantId}`,
        clientSecret: this.config.azure.clientSecret,
      },
    });

    const result = await cca.acquireTokenByClientCredential({
      scopes: [this.config.defender.appScope],
    });

    if (!result?.accessToken) {
      throw new Error(
        'Failed to acquire access token — check your Entra ID app registration and credentials.',
      );
    }

    this.cachedToken = result.accessToken;
    this.tokenExpiry = result.expiresOn
      ? result.expiresOn.getTime()
      : Date.now() + 60 * 60 * 1000;

    logger.info('Access token acquired successfully.');
    return this.cachedToken;
  }
}
