/**
 * VRM Report Generator – CLI entry point.
 *
 * Commands:
 *   generate    Fetch data from Defender APIs, merge enrichment, produce report.
 *   from-json   Re-export a previously saved JSON report to Excel and/or CSV (no API calls).
 *   validate    Test API connectivity and permissions (no report generated).
 */

import * as fs from 'fs';
import * as path from 'path';
import { Command } from 'commander';
import { loadConfig } from './config/settings';
import { getLogger } from './utils/logger';
import { AuthService } from './services/auth.service';
import { DefenderApiService } from './services/defender-api.service';
import { EnrichmentService } from './services/enrichment.service';
import { mapToVrmRows } from './mappers/vulnerability.mapper';
import {
  generateExcelReport,
  generateCsvReport,
  generateJsonReport,
  computeSummary,
} from './services/report.service';
import type { MachineReference, VrmReportRow } from './types';

const program = new Command();

program
  .name('vrm-report')
  .description(
    'Vulnerability Risk Management Report Generator — pulls data from Microsoft Defender for Endpoint APIs to produce risk-informed VRM reports.',
  )
  .version('1.0.0');

// ---------------------------------------------------------------------------
// generate command
// ---------------------------------------------------------------------------
program
  .command('generate')
  .description('Fetch vulnerability data and generate the VRM report.')
  .option('--csv', 'Also produce a CSV export alongside the Excel report.')
  .option('--json', 'Also produce a JSON export alongside the Excel report.')
  .option('--output <dir>', 'Override output directory.')
  .action(async (opts) => {
    const config = loadConfig();
    const logger = getLogger(config.logLevel);

    try {
      logger.info('=== VRM Report Generator ===');

      // 1. Authenticate
      const authService = new AuthService(config);
      const apiService = new DefenderApiService(config, authService);

      // 2. Fetch data from Defender APIs (parallel where possible)
      logger.info('Fetching vulnerability data from Defender for Endpoint...');

      const [vulnerabilities, machineVulnerabilities] = await Promise.all([
        apiService.getAllVulnerabilities(),
        apiService.getAllMachineVulnerabilities(),
      ]);

      logger.info(
        `Retrieved ${vulnerabilities.length} vulnerabilities, ${machineVulnerabilities.length} machine-vulnerability mappings.`,
      );

      // 3. For each unique CVE that has machine mappings, fetch machine
      //    references to get OS and hostname data.
      const uniqueCves = new Set(machineVulnerabilities.map((mv) => mv.cveId));
      logger.info(`Fetching machine references for ${uniqueCves.size} unique CVEs...`);

      const machineRefsByCve = new Map<string, MachineReference[]>();

      // Batch in groups of 20 to avoid overwhelming the API
      const cveArray = [...uniqueCves];
      const batchSize = 20;
      for (let i = 0; i < cveArray.length; i += batchSize) {
        const batch = cveArray.slice(i, i + batchSize);
        const results = await Promise.all(
          batch.map((cveId) =>
            apiService
              .getMachinesByVulnerability(cveId)
              .then((refs) => ({ cveId, refs }))
              .catch((err) => {
                logger.warn(`Failed to fetch machine refs for ${cveId}: ${err.message}`);
                return { cveId, refs: [] as MachineReference[] };
              }),
          ),
        );
        for (const { cveId, refs } of results) {
          machineRefsByCve.set(cveId, refs);
        }

        if (i + batchSize < cveArray.length) {
          logger.info(
            `  ... fetched machine refs for ${Math.min(i + batchSize, cveArray.length)}/${cveArray.length} CVEs`,
          );
        }
      }

      // 4. Load enrichment data
      const enrichmentService = new EnrichmentService(config.enrichmentFile);

      // 5. Map to VRM rows
      const rows = mapToVrmRows(
        { vulnerabilities, machineVulnerabilities, machineRefsByCve },
        enrichmentService,
      );

      if (rows.length === 0) {
        logger.warn('No VRM rows generated — check your data and enrichment.');
        return;
      }

      // 6. Print summary
      const summary = computeSummary(rows);
      logger.info('--- Report Summary ---');
      logger.info(`  Total findings:      ${summary.totalVulnerabilities}`);
      logger.info(`  Critical:            ${summary.criticalCount}`);
      logger.info(`  High:                ${summary.highCount}`);
      logger.info(`  Exploitable:         ${summary.exploitableCount}`);
      logger.info(`  Pending > 30 days:   ${summary.pendingOver30Days}`);
      logger.info(`  Pending > 90 days:   ${summary.pendingOver90Days}`);
      logger.info(`  Patched:             ${summary.patchedCount}`);
      logger.info(`  Risk accepted:       ${summary.riskAcceptedCount}`);
      logger.info(`  Machines affected:   ${summary.uniqueMachinesAffected}`);

      // 7. Generate reports
      const outputDir = opts.output ?? config.outputDir;
      const excelPath = await generateExcelReport(rows, outputDir);
      logger.info(`Excel report: ${excelPath}`);

      if (opts.csv) {
        const csvPath = generateCsvReport(rows, outputDir);
        logger.info(`CSV report:   ${csvPath}`);
      }

      if (opts.json) {
        const jsonPath = generateJsonReport(rows, outputDir);
        logger.info(`JSON report:  ${jsonPath}`);
      }

      logger.info('=== Done ===');
    } catch (err: any) {
      logger.error(`Report generation failed: ${err.message}`);
      if (err.response?.data) {
        logger.error(`API response: ${JSON.stringify(err.response.data)}`);
      }
      process.exit(1);
    }
  });

// ---------------------------------------------------------------------------
// from-json command
// ---------------------------------------------------------------------------
program
  .command('from-json')
  .description('Re-export a previously saved JSON report to Excel and/or CSV without API calls.')
  .requiredOption('--input <file>', 'Path to a VRM-Report-*.json file produced by generate --json.')
  .option('--csv', 'Also produce a CSV export.')
  .option('--no-excel', 'Skip the Excel output (use with --csv to get CSV only).')
  .option('--output <dir>', 'Override output directory.')
  .action(async (opts) => {
    const config = loadConfig();
    const logger = getLogger(config.logLevel);

    try {
      const inputPath = path.resolve(opts.input);
      if (!fs.existsSync(inputPath)) {
        logger.error(`Input file not found: ${inputPath}`);
        process.exit(1);
      }

      logger.info(`=== VRM Re-export from JSON ===`);
      logger.info(`Reading: ${inputPath}`);

      const raw = JSON.parse(fs.readFileSync(inputPath, 'utf-8')) as {
        generatedAt: string;
        rows: VrmReportRow[];
      };

      if (!Array.isArray(raw.rows) || raw.rows.length === 0) {
        logger.error('JSON file contains no rows — is this a valid VRM-Report JSON?');
        process.exit(1);
      }

      logger.info(`Loaded ${raw.rows.length} rows (originally generated ${raw.generatedAt}).`);

      const outputDir = opts.output ?? config.outputDir;

      if (opts.excel !== false) {
        const excelPath = await generateExcelReport(raw.rows, outputDir);
        logger.info(`Excel report: ${excelPath}`);
      }

      if (opts.csv) {
        const csvPath = generateCsvReport(raw.rows, outputDir);
        logger.info(`CSV report:   ${csvPath}`);
      }

      logger.info('=== Done ===');
    } catch (err: any) {
      logger.error(`Re-export failed: ${err.message}`);
      process.exit(1);
    }
  });

// ---------------------------------------------------------------------------
// validate command
// ---------------------------------------------------------------------------
program
  .command('validate')
  .description('Test API connectivity and token acquisition (no report generated).')
  .action(async () => {
    const config = loadConfig();
    const logger = getLogger(config.logLevel);

    try {
      logger.info('=== Validating Defender API configuration ===');

      // 1. Token acquisition
      const authService = new AuthService(config);
      const token = await authService.getToken();
      logger.info('Token acquired successfully.');

      // 2. Quick API test — fetch first page of vulnerabilities
      const apiService = new DefenderApiService(config, authService);
      const vulns = await apiService.getAllVulnerabilities();
      logger.info(`API connectivity OK — ${vulns.length} vulnerabilities returned.`);

      logger.info('=== Validation passed ===');
    } catch (err: any) {
      logger.error(`Validation failed: ${err.message}`);
      if (err.response?.status === 401) {
        logger.error(
          'HTTP 401 — check that your app registration has Vulnerability.Read.All permission and admin consent has been granted.',
        );
      }
      if (err.response?.status === 403) {
        logger.error(
          'HTTP 403 — your app registration lacks the required API permissions. Required: Vulnerability.Read.All (Application) or Vulnerability.Read (Delegated).',
        );
      }
      process.exit(1);
    }
  });

program.parse();
