import { getAllowedHosts } from '../../config/allowed-hosts.js';
import type { ValidateTargetResult } from '../../types/scan.types.js';

/**
 * Substrings that disqualify a hostname even if it is otherwise allowlisted.
 * Matching is case-insensitive on the hostname. Checked BEFORE the staging
 * substring allow, so e.g. `staging-prod.example.com` stays blocked.
 */
const FORBIDDEN_SUBSTRINGS = ['production', 'prod', 'live'];

/**
 * Any hostname containing this substring is treated as an authorized staging
 * target. This is a deliberately broad rule (per project policy): a host like
 * `api.staging.lynsi.net` is allowed without being named in the env allowlist.
 * The forbidden-substring check above still wins, and cloud-metadata /
 * link-local hosts remain blocked. NOTE: this allows ANY `*staging*` host on
 * the internet — only point the scanner at targets you are authorized to test.
 */
const STAGING_SUBSTRING = 'staging';

/**
 * Cloud metadata / link-local IPs that must never be scanned.
 */
const BLOCKED_HOSTS = new Set<string>(['169.254.169.254', 'metadata.google.internal']);

/**
 * IPv4 ranges considered "private" — blocked unless explicitly allowlisted.
 * Each entry: [networkInt, maskBits].
 */
const PRIVATE_RANGES_V4: Array<[number, number]> = [
  [ipv4ToInt('10.0.0.0'), 8],
  [ipv4ToInt('172.16.0.0'), 12],
  [ipv4ToInt('192.168.0.0'), 16],
  [ipv4ToInt('169.254.0.0'), 16],
];

export interface TargetPolicyOptions {
  /**
   * Extra hostnames considered allowed for this single call (e.g. supplied
   * by the tool input). Merged with the env-configured staging hosts.
   */
  extraAllowedHosts?: string[];
}

export function validateTarget(
  rawUrl: string,
  options: TargetPolicyOptions = {},
): ValidateTargetResult {
  const trimmed = (rawUrl ?? '').trim();
  if (!trimmed) {
    return { allowed: false, reason: 'targetUrl is empty' };
  }

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    return { allowed: false, reason: `Not a valid URL: ${trimmed}` };
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return {
      allowed: false,
      reason: `Only http/https protocols are permitted (got ${url.protocol})`,
    };
  }

  const hostname = url.hostname.toLowerCase();

  if (!hostname) {
    return { allowed: false, reason: 'URL has no hostname' };
  }

  // Cloud-metadata / link-local hosts are never a legitimate target and cannot
  // be overridden by any allowlist.
  if (BLOCKED_HOSTS.has(hostname)) {
    return {
      allowed: false,
      reason: `Host ${hostname} is on the blocklist (cloud metadata / link-local)`,
    };
  }

  const allowed = getAllowedHosts();
  const extra = new Set((options.extraAllowedHosts ?? []).map((h) => h.toLowerCase()));

  if (allowed.localhostHostnames.has(hostname) || hostname === '[::1]') {
    return {
      allowed: true,
      reason: 'Localhost target',
      normalizedUrl: url.toString(),
      classification: 'localhost',
    };
  }

  // An EXPLICITLY named host (env allowlist or per-call extra) is allowed even
  // if it contains a forbidden substring — this is a deliberate operator
  // decision (e.g. allowing `staging.live.example.com`). Checked before the
  // forbidden-substring guard so the named exception wins. The broad `staging`
  // substring rule below does NOT get this override.
  if (allowed.stagingHostnames.has(hostname) || extra.has(hostname)) {
    return {
      allowed: true,
      reason: 'Allowlisted staging host (explicit entry overrides forbidden substrings)',
      normalizedUrl: url.toString(),
      classification: 'staging',
    };
  }

  for (const banned of FORBIDDEN_SUBSTRINGS) {
    if (hostname.includes(banned)) {
      return {
        allowed: false,
        reason: `Hostname contains forbidden substring "${banned}"`,
      };
    }
  }

  if (hostname.includes(STAGING_SUBSTRING)) {
    return {
      allowed: true,
      reason: `Hostname contains "${STAGING_SUBSTRING}" — treated as authorized staging target`,
      normalizedUrl: url.toString(),
      classification: 'staging',
    };
  }

  if (isPrivateIpv4(hostname)) {
    return {
      allowed: false,
      reason: `Private network address ${hostname} is not in the allowlist`,
    };
  }

  return {
    allowed: false,
    reason: `Host ${hostname} is not localhost and not in the staging allowlist`,
  };
}

function ipv4ToInt(ip: string): number {
  const parts = ip.split('.').map((p) => Number(p));
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) {
    return -1;
  }
  return (
    ((parts[0]! << 24) >>> 0) +
    ((parts[1]! << 16) >>> 0) +
    ((parts[2]! << 8) >>> 0) +
    (parts[3]! >>> 0)
  );
}

function isPrivateIpv4(hostname: string): boolean {
  const asInt = ipv4ToInt(hostname);
  if (asInt < 0) return false;
  for (const [net, bits] of PRIVATE_RANGES_V4) {
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    if ((asInt & mask) === (net & mask)) {
      return true;
    }
  }
  return false;
}
