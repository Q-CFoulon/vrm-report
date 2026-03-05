/**
 * Date utilities for the VRM report.
 * Computes aging buckets and formats dates for the spreadsheet.
 */

import type { RemediationStatus } from '../types';

/**
 * Compute how many full days have elapsed since `dateStr` relative to `now`.
 */
export function daysElapsed(dateStr: string, now: Date = new Date()): number {
  const d = new Date(dateStr);
  const diffMs = now.getTime() - d.getTime();
  return Math.floor(diffMs / (1000 * 60 * 60 * 24));
}

/**
 * Derive the remediation aging status from the first-detected date and the
 * Defender API status field.
 *
 * If the API says the vuln requires no action, we mark it as Patched.
 * Otherwise we bucket by how long it has been pending.
 */
export function computeRemediationStatus(
  firstDetected: string,
  defenderStatus: string,
  now: Date = new Date(),
): RemediationStatus {
  if (defenderStatus === 'NoActionRequired') {
    return 'Patched';
  }

  const days = daysElapsed(firstDetected, now);

  if (days > 90) return 'Pending > 3 months';
  if (days > 60) return 'Pending > 2 months';
  if (days > 30) return 'Pending > 1 month';
  return 'Pending < 1 month';
}

/**
 * Format an ISO 8601 date string as a short locale date for the report, e.g.
 * "Jan 15, 2026".
 */
export function formatReportDate(isoString: string): string {
  if (!isoString) return '';
  const d = new Date(isoString);
  return d.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}
