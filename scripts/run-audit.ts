/**
 * Local audit runner — exercises the ENHANCED scan engine directly (bypassing
 * the installed MCP build) so we can validate the new discovery/probe/register
 * modules end-to-end against a live localhost target.
 *
 * Usage: tsx scripts/run-audit.ts http://localhost:3000/
 */
import { handleSecurityScan } from '../src/mcp/tools/security-scan.tool.js';

const target = process.argv[2] ?? 'http://localhost:3000/';

const res = await handleSecurityScan({
  targetUrl: target,
  scanType: 'deep',
  includeActiveProbes: true,
  includeTemplates: true,
  includeContentDiscovery: true,
  registerAccounts: true,
});

if (!res.ok) {
  console.log('SCAN REJECTED:', res.reason);
  process.exit(1);
}

const ev = res.evidence;
const as = ev.attackSurface;

console.log('\n===== ATTACK SURFACE =====');
console.log(
  JSON.stringify(
    {
      requestCount: ev.requestCount,
      totalEndpoints: as?.totalEndpoints,
      withParams: as?.withParams,
      withPathId: as?.withPathId,
      apiLike: as?.apiLike,
      authGated: as?.authGated,
      uploads: as?.uploads,
      adminLike: as?.adminLike,
      forms: as?.forms,
    },
    null,
    2,
  ),
);

console.log('\n===== ENDPOINTS (by source) =====');
const bySource: Record<string, string[]> = {};
for (const e of ev.endpoints) {
  (bySource[e.source] ??= []).push(`${e.method} ${e.url}`);
}
for (const [src, list] of Object.entries(bySource)) {
  console.log(`\n[${src}] (${list.length})`);
  for (const l of list.slice(0, 25)) console.log('  ' + l);
}

console.log('\n===== SELF-REGISTRATION =====');
console.log(JSON.stringify(ev.autoRegister, null, 2));

console.log('\n===== API PAYLOAD HINTS =====');
console.log(JSON.stringify(ev.apiPayloadHints, null, 2));

console.log('\n===== NOTES =====');
for (const n of ev.notes) console.log('  - ' + n);

console.log('\n===== FINDINGS =====');
for (const f of res.findings) {
  console.log(`\n[${f.severity.toUpperCase()}/${f.confidence ?? '?'}] ${f.title}`);
  console.log('  ' + f.description);
  if (f.evidence) console.log('  evidence: ' + JSON.stringify(f.evidence).slice(0, 300));
}
console.log(`\nTotal findings: ${res.findings.length}`);
console.log('Report written to:', res.reportPaths);
