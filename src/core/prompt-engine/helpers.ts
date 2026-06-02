import type { ScanEvidence } from '../../types/scan.types.js';

export function isScanEvidence(value: unknown): value is ScanEvidence {
  return (
    typeof value === 'object' &&
    value !== null &&
    'pages' in value &&
    'headers' in value &&
    'cookies' in value
  );
}

export function asScanEvidence(value: unknown): ScanEvidence | null {
  return isScanEvidence(value) ? value : null;
}

/**
 * Iterate the per-URL header maps in a ScanEvidence in a typed way.
 */
export function eachHeaders(
  evidence: ScanEvidence,
): Array<{ url: string; headers: Record<string, string> }> {
  return Object.entries(evidence.headers).map(([url, headers]) => ({ url, headers }));
}

export function findHeader(
  headers: Record<string, string>,
  name: string,
): string | undefined {
  return headers[name.toLowerCase()];
}
