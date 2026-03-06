/**
 * Report generation service.
 *
 * Produces an Excel workbook (.xlsx) with:
 *   Sheet 1 – "Executive Summary" with key metrics
 *   Sheet 2 – "VRM Detail" with all rows (columns A–O from spec)
 *
 * Also exports a flat CSV for downstream tooling / SIEM ingestion.
 */

import * as fs from 'fs';
import * as path from 'path';
import ExcelJS from 'exceljs';
import type { VrmReportRow, VrmReportSummary } from '../types';
import { formatReportDate, daysElapsed } from '../utils/date.utils';
import { getLogger } from '../utils/logger';

// -- Summary calculator -----------------------------------------------------

export function computeSummary(rows: VrmReportRow[]): VrmReportSummary {
  const now = new Date();
  const uniqueMachines = new Set(rows.map((r) => r.machineId));

  return {
    totalVulnerabilities: rows.length,
    criticalCount: rows.filter((r) => r.criticality === 'Critical').length,
    highCount: rows.filter((r) => r.criticality === 'High').length,
    exploitableCount: rows.filter((r) => r.criticality === 'Exploitable').length,
    pendingOver30Days: rows.filter(
      (r) => r.status === 'Pending > 1 month' || r.status === 'Pending > 2 months' || r.status === 'Pending > 3 months',
    ).length,
    pendingOver60Days: rows.filter(
      (r) => r.status === 'Pending > 2 months' || r.status === 'Pending > 3 months',
    ).length,
    pendingOver90Days: rows.filter((r) => r.status === 'Pending > 3 months').length,
    patchedCount: rows.filter((r) => r.status === 'Patched').length,
    riskAcceptedCount: rows.filter((r) => r.riskAcceptance === 'Yes').length,
    uniqueMachinesAffected: uniqueMachines.size,
    generatedAt: now.toISOString(),
  };
}

// -- Colour helpers ---------------------------------------------------------

function criticalityFill(crit: string): ExcelJS.FillPattern | undefined {
  const fills: Record<string, ExcelJS.FillPattern> = {
    Critical: { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFF0000' } },
    Exploitable: { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFF4500' } },
    High: { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFF8C00' } },
    Medium: { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFFFF00' } },
    Low: { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF90EE90' } },
  };
  return fills[crit];
}

function statusFill(status: string): ExcelJS.FillPattern | undefined {
  if (status === 'Patched')
    return { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF90EE90' } };
  if (status.includes('3 months'))
    return { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFF0000' } };
  if (status.includes('2 months'))
    return { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFF8C00' } };
  if (status.includes('1 month'))
    return { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFFFF00' } };
  return undefined;
}

// -- Excel workbook ---------------------------------------------------------

export async function generateExcelReport(
  rows: VrmReportRow[],
  outputDir: string,
): Promise<string> {
  const logger = getLogger();
  const wb = new ExcelJS.Workbook();
  wb.creator = 'VRM Report Generator';
  wb.created = new Date();

  // ---- Sheet 1: Executive Summary ----
  const summary = computeSummary(rows);
  const summarySheet = wb.addWorksheet('Executive Summary');

  summarySheet.columns = [
    { header: 'Metric', key: 'metric', width: 40 },
    { header: 'Value', key: 'value', width: 20 },
  ];

  const summaryRows = [
    { metric: 'Report Generated', value: formatReportDate(summary.generatedAt) },
    { metric: 'Total Vulnerability Findings', value: summary.totalVulnerabilities },
    { metric: 'Critical', value: summary.criticalCount },
    { metric: 'High', value: summary.highCount },
    { metric: 'Exploitable (public exploit)', value: summary.exploitableCount },
    { metric: 'Pending > 30 Days', value: summary.pendingOver30Days },
    { metric: 'Pending > 60 Days', value: summary.pendingOver60Days },
    { metric: 'Pending > 90 Days', value: summary.pendingOver90Days },
    { metric: 'Patched', value: summary.patchedCount },
    { metric: 'Risk Accepted', value: summary.riskAcceptedCount },
    { metric: 'Unique Machines Affected', value: summary.uniqueMachinesAffected },
  ];

  for (const sr of summaryRows) {
    summarySheet.addRow(sr);
  }

  // Style header row
  summarySheet.getRow(1).font = { bold: true, size: 12 };
  summarySheet.getRow(1).fill = {
    type: 'pattern',
    pattern: 'solid',
    fgColor: { argb: 'FF4472C4' },
  };
  summarySheet.getRow(1).font = { bold: true, color: { argb: 'FFFFFFFF' }, size: 12 };

  // ---- Sheet 2: VRM Detail ----
  const detailSheet = wb.addWorksheet('VRM Detail');

  detailSheet.columns = [
    { header: 'ID',                key: 'uniqueId',          width: 8 },
    { header: 'Criticality',       key: 'criticality',       width: 14 },
    { header: 'CVE#',              key: 'cveId',             width: 18 },
    { header: 'CVSS',              key: 'cvssScore',         width: 8 },
    { header: 'Description',       key: 'description',       width: 60 },
    { header: 'Device OS',         key: 'deviceOS',          width: 22 },
    { header: 'Device Type',       key: 'deviceType',        width: 16 },
    { header: 'First Detected',    key: 'dateFirstDetected', width: 16 },
    { header: 'Last Detected',     key: 'dateLastDetected',  width: 16 },
    { header: 'Status',            key: 'status',            width: 22 },
    { header: 'Risk Acceptance',   key: 'riskAcceptance',    width: 16 },
    { header: 'Asset Criticality', key: 'assetCriticality',  width: 20 },
    { header: 'Data Type',         key: 'dataType',          width: 16 },
    { header: 'Location',          key: 'location',          width: 18 },
    { header: 'Notes',             key: 'notes',             width: 30 },
    { header: 'Machine Name',      key: 'machineName',       width: 24 },
    { header: 'Product',           key: 'productName',       width: 24 },
  ];

  // Header style
  detailSheet.getRow(1).font = { bold: true, color: { argb: 'FFFFFFFF' }, size: 11 };
  detailSheet.getRow(1).fill = {
    type: 'pattern',
    pattern: 'solid',
    fgColor: { argb: 'FF4472C4' },
  };

  // Add data rows
  for (const row of rows) {
    const excelRow = detailSheet.addRow({
      ...row,
      dateFirstDetected: formatReportDate(row.dateFirstDetected),
      dateLastDetected: formatReportDate(row.dateLastDetected),
    });

    // Conditional formatting
    const critCell = excelRow.getCell('criticality');
    const critFill = criticalityFill(row.criticality);
    if (critFill) critCell.fill = critFill;

    const statusCell = excelRow.getCell('status');
    const sFill = statusFill(row.status);
    if (sFill) statusCell.fill = sFill;
  }

  // Auto-filter
  detailSheet.autoFilter = {
    from: { row: 1, column: 1 },
    to: { row: rows.length + 1, column: detailSheet.columns.length },
  };

  // Freeze top row
  detailSheet.views = [{ state: 'frozen', ySplit: 1 }];

  // Write file
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const filename = `VRM-Report-${timestamp}.xlsx`;
  const filePath = path.join(outputDir, filename);

  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  await wb.xlsx.writeFile(filePath);
  logger.info(`Excel report written to ${filePath}`);
  return filePath;
}

// -- JSON export ------------------------------------------------------------

export function generateJsonReport(
  rows: VrmReportRow[],
  outputDir: string,
): string {
  const logger = getLogger();
  const summary = computeSummary(rows);

  const payload = {
    generatedAt: summary.generatedAt,
    summary,
    rows: rows.map((r) => ({
      ...r,
      dateFirstDetected: formatReportDate(r.dateFirstDetected),
      dateLastDetected: formatReportDate(r.dateLastDetected),
    })),
  };

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const filename = `VRM-Report-${timestamp}.json`;
  const filePath = path.join(outputDir, filename);

  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  fs.writeFileSync(filePath, JSON.stringify(payload, null, 2), 'utf-8');
  logger.info(`JSON report written to ${filePath}`);
  return filePath;
}

// -- CSV export -------------------------------------------------------------

export function generateCsvReport(
  rows: VrmReportRow[],
  outputDir: string,
): string {
  const logger = getLogger();

  const headers = [
    'ID', 'Criticality', 'CVE#', 'CVSS', 'Description', 'Device OS',
    'Device Type', 'First Detected', 'Last Detected', 'Status',
    'Risk Acceptance', 'Asset Criticality', 'Data Type', 'Location',
    'Notes', 'Machine Name', 'Product',
  ];

  const csvRows = rows.map((r) => [
    r.uniqueId,
    r.criticality,
    r.cveId,
    String(r.cvssScore),
    `"${r.description.replace(/"/g, '""')}"`,
    r.deviceOS,
    r.deviceType,
    formatReportDate(r.dateFirstDetected),
    formatReportDate(r.dateLastDetected),
    r.status,
    r.riskAcceptance,
    r.assetCriticality,
    r.dataType,
    r.location,
    `"${r.notes.replace(/"/g, '""')}"`,
    r.machineName,
    r.productName,
  ]);

  const csv = [headers.join(','), ...csvRows.map((r) => r.join(','))].join('\n');

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const filename = `VRM-Report-${timestamp}.csv`;
  const filePath = path.join(outputDir, filename);

  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  fs.writeFileSync(filePath, csv, 'utf-8');
  logger.info(`CSV report written to ${filePath}`);
  return filePath;
}
