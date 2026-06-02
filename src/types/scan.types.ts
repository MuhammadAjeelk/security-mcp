export type ScanType = 'quick' | 'standard' | 'deep';

export type LoopMode = 'single-pass' | 'iterative';

export interface TestAccount {
  role: string;
  email?: string;
  token?: string;
  cookies?: Record<string, string>;
}

export interface ScanRequest {
  targetUrl: string;
  scanType: ScanType;
  maxDepth?: number;
  includeBrowserTests?: boolean;
  /** When true, run the active-but-safe probe library after the crawl. */
  includeActiveProbes?: boolean;
  /** When true, run the YAML template engine against the target. */
  includeTemplates?: boolean;
  /**
   * When true, run the server-side LLM-backed prompt loop too. Default: false.
   * Recommended off when calling from Claude Code / Cursor — the caller is
   * already an LLM. Turn on for CI / cron / headless contexts.
   */
  includeServerSidePromptLoop?: boolean;
  /** Optional pre-captured session (cookies + tokens) supplied by the caller. */
  session?: AuthSession;
  allowedHosts?: string[];
  testAccounts?: TestAccount[];
}

export interface AuthSession {
  cookies?: Record<string, string>;
  bearerToken?: string;
  /** Free-form notes about how the session was obtained. */
  origin?: string;
}

export interface ScanEvidence {
  targetUrl: string;
  scanType: ScanType;
  startedAt: string;
  completedAt: string;
  requestCount: number;
  pages: ScannedPage[];
  headers: Record<string, Record<string, string>>;
  cookies: Record<string, string[]>;
  forms: DiscoveredForm[];
  endpoints: DiscoveredEndpoint[];
  notes: string[];
  /**
   * Roles for which authenticated probing context was supplied.
   * Tokens and cookies themselves are NOT serialized into reports.
   */
  authenticatedRoles?: string[];
  /**
   * Per-role differential responses for discovered endpoints. Keyed by role
   * name. Values: list of probe outcomes (status + content-type + bytes only,
   * NOT full bodies). Used by access-control prompts to detect IDOR/BOLA.
   */
  roleProbes?: Record<string, RoleProbeResult[]>;
}

export interface RoleProbeResult {
  url: string;
  method: string;
  status: number;
  contentType?: string;
  bytes: number;
  redirected: boolean;
  error?: string;
}

export interface ScannedPage {
  url: string;
  status: number;
  contentType?: string;
  bytes: number;
  redirected: boolean;
  finalUrl: string;
  depth: number;
}

export interface DiscoveredForm {
  pageUrl: string;
  action?: string;
  method: string;
  fields: string[];
}

export interface DiscoveredEndpoint {
  url: string;
  method: string;
  source: 'crawler' | 'inline-script' | 'link';
}

export interface ValidateTargetResult {
  allowed: boolean;
  reason: string;
  normalizedUrl?: string;
  classification?: 'localhost' | 'staging';
}
