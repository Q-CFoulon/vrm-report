/**
 * Authentication service for Microsoft Defender for Endpoint APIs.
 *
 * Supports four flows:
 *   - **azure_cli** — default. Uses your existing `az login` session.
 *     No app registration needed. Just run `az login` once.
 *   - **browser** — pops open a browser window for interactive sign-in.
 *     Requires app registration with http://localhost redirect URI.
 *   - **interactive** — device-code flow (sign in at aka.ms/devicelogin).
 *     Requires app registration with "Allow public client flows" enabled.
 *   - **client_credential** — headless app secret flow.
 *     Requires AZURE_CLIENT_SECRET in .env.
 */

import {
  DeviceCodeCredential,
  InteractiveBrowserCredential,
  AzureCliCredential,
} from '@azure/identity';
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

    switch (this.config.authMode) {
      case 'azure_cli':         return this.acquireViaAzureCli();
      case 'browser':           return this.acquireViaBrowser();
      case 'client_credential': return this.acquireViaClientCredential();
      default:                  return this.acquireViaDeviceCode();
    }
  }

  // -- Azure CLI flow (no app registration required) ------------------------

  private async acquireViaAzureCli(): Promise<string> {
    const logger = getLogger();
    logger.info('Acquiring token via Azure CLI (az login session)...');

    const cred = new AzureCliCredential();
    try {
      const token = await cred.getToken(this.config.defender.delegatedScope);
      this.cachedToken = token.token;
      this.tokenExpiry = token.expiresOnTimestamp;
      logger.info('Access token acquired successfully.');
      return this.cachedToken;
    } catch (err: any) {
      logger.error(`Azure CLI auth failed: ${err.message}`);
      logger.error(
        'Make sure you are logged in: run `az login` then try again.\n' +
        'If your account needs access to the Defender API, ensure you have\n' +
        'the SecurityReader or equivalent role in Defender for Endpoint.',
      );
      throw err;
    }
  }

  // -- Interactive browser popup flow ---------------------------------------

  private async acquireViaBrowser(): Promise<string> {
    const logger = getLogger();
    logger.info('Opening browser for interactive sign-in...');

    const cred = new InteractiveBrowserCredential({
      tenantId: this.config.azure.tenantId,
      clientId: this.config.azure.clientId,
    });

    try {
      const token = await cred.getToken(this.config.defender.delegatedScope);
      this.cachedToken = token.token;
      this.tokenExpiry = token.expiresOnTimestamp;
      logger.info('Access token acquired successfully.');
      return this.cachedToken;
    } catch (err: any) {
      logger.error(`Browser auth failed: ${err.message}`);
      logger.error(
        'Ensure your app registration has:\n' +
        '  1. Authentication > Redirect URIs includes http://localhost\n' +
        '  2. Authentication > "Allow public client flows" = Yes\n' +
        '  3. API permissions > WindowsDefenderATP > Delegated > Vulnerability.Read',
      );
      throw err;
    }
  }

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
          const url  = info.verificationUri ?? (info as any).verification_uri ?? 'https://microsoft.com/devicelogin';
          const code = info.userCode ?? (info as any).user_code ?? '(see above)';
          const msg  = info.message ?? `To sign in, open ${url} and enter the code: ${code}`;
          console.log('\n========================================');
          console.log(msg);
          console.log(`  URL:  ${url}`);
          console.log(`  Code: ${code}`);
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
