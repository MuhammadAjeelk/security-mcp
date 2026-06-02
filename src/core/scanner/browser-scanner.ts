import type { ScanEvidence, ScanRequest } from '../../types/scan.types.js';
import { AuditLogger } from '../logging/audit-logger.js';

/**
 * Optional browser-based scan layer. Playwright is an optional dependency —
 * if it isn't installed the scanner returns a no-op note rather than failing
 * the whole scan. This keeps the V1 install lightweight while still allowing
 * callers to opt-in via `includeBrowserTests: true`.
 */
export async function runBrowserChecks(
  request: ScanRequest,
  evidence: ScanEvidence,
  audit: AuditLogger,
): Promise<ScanEvidence> {
  if (!request.includeBrowserTests) {
    return evidence;
  }

  let playwright: typeof import('playwright') | undefined;
  try {
    playwright = await import('playwright');
  } catch {
    evidence.notes.push(
      'Browser tests requested but `playwright` is not installed. Install it with `npm i -D playwright` and run `npx playwright install chromium`.',
    );
    audit.event('browser.skip', { reason: 'playwright-not-installed' });
    return evidence;
  }

  audit.event('browser.start', { target: request.targetUrl });
  const browser = await playwright.chromium.launch({ headless: true });
  try {
    const context = await browser.newContext({
      userAgent: 'security-mcp/0.1 (+authorized-testing-only)',
    });
    const page = await context.newPage();
    const consoleErrors: string[] = [];
    page.on('console', (msg) => {
      if (msg.type() === 'error') consoleErrors.push(msg.text());
    });
    await page.goto(request.targetUrl, { waitUntil: 'domcontentloaded' });

    const cspMeta = await page
      .locator('meta[http-equiv="Content-Security-Policy"]')
      .first()
      .getAttribute('content')
      .catch(() => null);

    evidence.notes.push(
      `Browser visit recorded ${consoleErrors.length} console error(s)${
        cspMeta ? `; CSP meta tag present` : ''
      }.`,
    );
  } finally {
    await browser.close();
    audit.event('browser.done', { target: request.targetUrl });
  }
  return evidence;
}
