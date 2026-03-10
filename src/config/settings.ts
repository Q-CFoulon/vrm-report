import * as dotenv from 'dotenv';
import * as path from 'path';

dotenv.config();

export type AuthMode = 'vscode' | 'interactive' | 'browser' | 'azure_cli' | 'client_credential';

export interface AppConfig {
  authMode: AuthMode;
  azure: {
    tenantId?: string;
    clientId?: string;
    clientSecret?: string;
  };
  defender: {
    baseUrl: string;
    /** Scope for client-credential flow (/.default) */
    appScope: string;
    /** Scope for delegated / interactive flow */
    delegatedScope: string;
  };
  outputDir: string;
  enrichmentFile: string;
  logLevel: string;
}

function requireEnv(key: string): string {
  const value = process.env[key];
  if (!value) {
    throw new Error(`Missing required environment variable: ${key}`);
  }
  return value;
}

export function loadConfig(): AppConfig {
  const baseUrl =
    process.env.DEFENDER_API_BASE_URL ??
    'https://api.security.microsoft.com';

  const authMode = (process.env.AUTH_MODE ?? 'vscode') as AuthMode;

  // AZURE_TENANT_ID is required for all auth modes:
  //   - interactive / browser / client_credential: determines which Entra tenant
  //     the app registration belongs to.
  //   - vscode / azure_cli: passed to VisualStudioCodeCredential /
  //     AzureCliCredential so they pick the right tenant when the user is
  //     signed into multiple tenants simultaneously (avoids silent wrong-tenant
  //     token acquisition).
  const tenantId = requireEnv('AZURE_TENANT_ID');

  // clientId only required for flows that need an app registration
  const needsAppReg = authMode === 'interactive' || authMode === 'browser' || authMode === 'client_credential';
  const clientId = needsAppReg ? requireEnv('AZURE_CLIENT_ID') : process.env.AZURE_CLIENT_ID;

  return {
    authMode,
    azure: {
      tenantId,
      clientId,
      clientSecret: process.env.AZURE_CLIENT_SECRET || undefined,
    },
    defender: {
      baseUrl,
      appScope: `${baseUrl}/.default`,
      delegatedScope: `${baseUrl}/.default`,
    },
    outputDir: path.resolve(process.env.OUTPUT_DIR ?? './output'),
    enrichmentFile: path.resolve(
      process.env.ENRICHMENT_FILE ?? './data/enrichment/asset-enrichment.json',
    ),
    logLevel: process.env.LOG_LEVEL ?? 'info',
  };
}