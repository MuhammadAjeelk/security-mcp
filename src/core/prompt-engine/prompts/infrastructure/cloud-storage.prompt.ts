import type { SecurityPrompt } from '../../types.js';
import { asScanEvidence, eachHeaders } from '../../helpers.js';

/**
 * Cloud object-storage host / URL signatures. Matching one of these in
 * client-reachable content means a bucket or object reference has leaked —
 * the starting point for a public-bucket or presigned-URL data exposure.
 */
const STORAGE_PATTERNS: Array<{ name: string; re: RegExp }> = [
  // Amazon S3 — virtual-hosted, path-style, regional, and s3:// scheme
  { name: 'Amazon S3 bucket URL', re: /\b[a-z0-9.-]+\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\b/i },
  { name: 'Amazon S3 path-style URL', re: /\bs3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\/[a-z0-9.\-_]+/i },
  { name: 'S3 scheme reference', re: /\bs3:\/\/[a-z0-9.\-_]+/i },
  // Google Cloud Storage
  { name: 'Google Cloud Storage URL', re: /\b(?:storage\.googleapis\.com|storage\.cloud\.google\.com)\/[a-z0-9.\-_]+/i },
  { name: 'GCS bucket subdomain', re: /\b[a-z0-9.-]+\.storage\.googleapis\.com\b/i },
  { name: 'GCS scheme reference', re: /\bgs:\/\/[a-z0-9.\-_]+/i },
  // Azure Blob Storage
  { name: 'Azure Blob Storage URL', re: /\b[a-z0-9-]+\.blob\.core\.windows\.net\b/i },
  // Other S3-compatible providers
  { name: 'DigitalOcean Spaces URL', re: /\b[a-z0-9.-]+\.digitaloceanspaces\.com\b/i },
  { name: 'Cloudflare R2 URL', re: /\b[a-z0-9.-]+\.r2\.cloudflarestorage\.com\b/i },
  { name: 'Backblaze B2 URL', re: /\b[a-z0-9.-]+\.backblazeb2\.com\b/i },
];

/**
 * Presigned-URL / shared-access-signature markers. Their presence in
 * client-reachable content means a time-limited (often long-lived) credential
 * to a private object has leaked into logs, responses, or source.
 */
const PRESIGNED_PATTERNS: Array<{ name: string; re: RegExp }> = [
  { name: 'AWS presigned URL signature', re: /[?&]X-Amz-Signature=/i },
  { name: 'AWS presigned URL credential', re: /[?&]X-Amz-Credential=/i },
  { name: 'GCS signed URL signature', re: /[?&]X-Goog-Signature=/i },
  { name: 'Azure SAS token', re: /[?&]sig=[^&\s]+(?:&|.*?)(?:se|sp|sv)=/i },
];

export const cloudStoragePrompt: SecurityPrompt = {
  id: 'infrastructure.cloud-storage-exposure',
  title: 'Exposed cloud storage (S3/GCS/Azure Blob) buckets, objects & presigned URLs',
  category: 'infrastructure',
  severityFocus: 'high',
  prompt: [
    'Goal: Find data leakage through cloud object storage — public/listable buckets, world-readable',
    'objects holding sensitive data, and presigned/SAS URLs that have leaked into client-reachable',
    'content. This is one of the most common breach vectors for data-heavy apps.',
    '',
    'Evidence required: JSON/HTML response bodies, OpenAPI/Swagger spec, JS bundles, redirect',
    '`Location` headers, CDN/asset config, and any discovered endpoint URLs. Look for storage hosts:',
    's3*.amazonaws.com / <bucket>.s3.*.amazonaws.com / s3://, storage.googleapis.com / gs://,',
    '*.blob.core.windows.net, *.digitaloceanspaces.com, *.r2.cloudflarestorage.com.',
    '',
    'Method (NON-DESTRUCTIVE, stay in scope):',
    '1. Extract every bucket and object URL referenced anywhere in reachable content; record the',
    '   provider and bucket name.',
    '2. For presigned/SAS URLs (X-Amz-Signature, X-Goog-Signature, Azure sig=) note the expiry',
    '   (X-Amz-Expires / se=) — a long-lived signed URL handed to the client is a credential leak.',
    '3. Assess public exposure ONLY within the target policy. If the bucket lives on a different host',
    '   that validate_target would reject, do NOT fetch it — report the bucket name and recommend the',
    '   owner verify with an unauthenticated `aws s3 ls s3://<bucket> --no-sign-request` (or provider',
    '   equivalent). NEVER use leaked credentials and never attempt anonymous writes.',
    '4. If an object URL is in-scope and returns data without auth, confirm whether it holds PII/PHI',
    '   or other sensitive data — that is a confirmed data leak.',
    '',
    'Output: critical when a public bucket/object exposes sensitive data or a live write-capable',
    'credential leaks; high for a leaked presigned URL or a confirmed world-readable private object;',
    'medium for a disclosed bucket name whose ACL could not be verified in scope. Confidence high only',
    'on observed evidence (HTTP response, listing XML); medium/low when reasoning from a URL alone.',
  ].join('\n'),
  heuristic(ctx) {
    const ev = asScanEvidence(ctx.evidence);
    if (!ev) return [];
    const findings = [];

    // Deterministically scan what we hold: endpoint URLs, crawl notes, and
    // response header values (redirects to storage hosts show up here).
    const haystacks: Array<{ where: string; text: string }> = [
      ...ev.endpoints.map((e) => ({ where: e.url, text: e.url })),
      ...(ev.notes ?? []).map((n, i) => ({ where: `note[${i}]`, text: n })),
    ];
    for (const { url, headers } of eachHeaders(ev)) {
      for (const [name, value] of Object.entries(headers)) {
        haystacks.push({ where: `${url} [header:${name}]`, text: value });
      }
    }

    const seen = new Set<string>();
    for (const { where, text } of haystacks) {
      for (const pat of PRESIGNED_PATTERNS) {
        if (pat.re.test(text)) {
          const key = `presigned:${where}`;
          if (seen.has(key)) continue;
          seen.add(key);
          findings.push({
            title: `Leaked presigned/SAS storage URL: ${pat.name}`,
            severity: 'high' as const,
            category: 'infrastructure',
            description: `A ${pat.name} is reachable at ${where}. A signed URL is a time-limited credential to a private object; if it leaks to the client or logs it grants direct object access until it expires.`,
            evidence: { where, pattern: pat.name },
            impact: 'Anyone with the leaked signed URL can read (and sometimes write) the private object until expiry — a direct data-exposure path that bypasses application auth.',
            remediation: 'Keep presigned URLs short-lived, never log them, generate them per-request server-side, and prefer short TTLs. Revoke/rotate the underlying keys if a long-lived URL leaked.',
            confidence: 'medium' as const,
          });
        }
      }
      for (const pat of STORAGE_PATTERNS) {
        const m = text.match(pat.re);
        if (m) {
          const key = `store:${pat.name}:${m[0].toLowerCase()}`;
          if (seen.has(key)) continue;
          seen.add(key);
          findings.push({
            title: `Cloud storage reference disclosed: ${pat.name}`,
            severity: 'medium' as const,
            category: 'infrastructure',
            description: `A cloud object-storage reference (${m[0]}) is exposed in client-reachable content at ${where}. Verify whether the bucket is publicly listable or the object is world-readable.`,
            evidence: { where, match: m[0], provider: pat.name },
            impact: 'Disclosed bucket names let an attacker probe for public-list/public-read misconfigurations; a permissive ACL would expose stored data directly.',
            remediation: 'Confirm the bucket blocks public access (S3 Block Public Access / uniform bucket-level access), serve user content via authenticated, short-lived signed URLs, and avoid embedding raw bucket URLs in client responses.',
            confidence: 'low' as const,
          });
        }
      }
    }
    return findings;
  },
};
