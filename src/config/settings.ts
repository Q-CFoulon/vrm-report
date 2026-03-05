import * as dotenv from 'dotenv';
import * as path from 'path';

dotenv.config();

export interface AppConfig {
  azure: {
    tenantId: string;
    clientId: string;
    clientSecret: string;
  };
  defender: {
    baseUrl: string;
    scope: string;
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
    process.env.DEFENDER_API_BASE_URL ?? 'https://api.security.microsoft.com';

  return {
    azure: {
      tenantId: requireEnv('AZURE_TENANT_ID'),
      clientId: requireEnv('AZURE_CLIENT_ID'),
      clientSecret: requireEnv('AZURE_CLIENT_SECRET'),
    },
    defender: {
      baseUrl,
      // The scope for Defender for Endpoint APIs
      scope: `${baseUrl}/.default`,
    },
    outputDir: path.resolve(process.env.OUTPUT_DIR ?? './output'),
    enrichmentFile: path.resolve(
      process.env.ENRICHMENT_FILE ?? './data/enrichment/asset-enrichment.json',
    ),
    logLevel: process.env.LOG_LEVEL ?? 'info',
  };
}
