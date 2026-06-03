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
  /**
   * Deterministic attack-surface map derived from the crawl. Computed by
   * buildAttackSurface() so it is identical run-to-run for the same evidence.
   * Consumed by the expert-audit flow and rendered into reports.
   */
  attackSurface?: AttackSurface;
}

/**
 * One endpoint as seen by an attacker, with deterministically-derived flags
 * that drive which security goals are applicable to it.
 */
export interface AttackSurfaceEndpoint {
  url: string;
  method: string;
  /** Has a `?key=value` query string. */
  hasQueryParams: boolean;
  /** Path contains a numeric/UUID segment (IDOR/BOLA-shaped). */
  hasPathId: boolean;
  /** Any role saw a 401/403, or status varied across roles — looks protected. */
  authGated: boolean;
  /** A discovered <form> posts to this endpoint. */
  hasForm: boolean;
  /** Form/endpoint accepts file uploads. */
  isUpload: boolean;
  /** Path looks administrative/internal (admin, internal, debug, actuator…). */
  looksAdmin: boolean;
  /** Prompt-module ids whose checks apply to this endpoint. */
  applicableGoals: string[];
}

/** Catalog entry for a security goal (mirrors a prompt module). */
export interface AttackSurfaceGoal {
  id: string;
  title: string;
  category: string;
}

/** Deterministic inventory of everything an attacker can touch. */
export interface AttackSurface {
  generatedAt: string;
  totalEndpoints: number;
  withParams: number;
  withPathId: number;
  authGated: number;
  uploads: number;
  adminLike: number;
  forms: number;
  endpoints: AttackSurfaceEndpoint[];
  /** Full goal catalog (= the prompt registry) so coverage can be tracked against it. */
  goalCatalog: AttackSurfaceGoal[];
}

/**
 * One row of the goal-coverage matrix, filled in by the calling LLM during an
 * expert audit and passed back into generate_report.
 */
export interface CoverageRow {
  goalId: string;
  goalTitle?: string;
  status: 'clean' | 'vulnerable' | 'partial' | 'not-applicable' | 'not-tested';
  endpointsTested?: number;
  endpointsTotal?: number;
  /** For vulnerable/partial goals, the specific endpoints implicated. */
  endpoints?: string[];
  note?: string;
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
  source: 'crawler' | 'inline-script' | 'link' | 'well-known' | 'api-spec';
}

export interface ValidateTargetResult {
  allowed: boolean;
  reason: string;
  normalizedUrl?: string;
  classification?: 'localhost' | 'staging';
}
