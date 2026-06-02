import type { Confidence, Severity } from '../../types/finding.types.js';

export interface TemplateInfo {
  name: string;
  author?: string;
  severity: Severity;
  description?: string;
  tags?: string[];
  reference?: string[];
}

export type MatcherType = 'status' | 'word' | 'regex' | 'header';
export type MatcherCondition = 'and' | 'or';

export interface Matcher {
  type: MatcherType;
  status?: number[];
  words?: string[];
  regex?: string[];
  header?: string;
  /** Default condition: `or` (any match). */
  condition?: MatcherCondition;
  /** When true, the absence of the match is the trigger. */
  negative?: boolean;
  /** What part of the response to apply against. */
  part?: 'body' | 'header' | 'all';
  /** Case sensitivity for word matchers (default false). */
  caseSensitive?: boolean;
}

export interface Extractor {
  name: string;
  regex?: string[];
  part?: 'body' | 'header' | 'all';
}

export interface TemplateRequest {
  method?: string;
  /** Paths are appended to the target base URL. Each is treated as a separate request. */
  paths?: string[];
  headers?: Record<string, string>;
  body?: string;
  /** Default `or` — any matcher matches. */
  matchersCondition?: MatcherCondition;
  matchers: Matcher[];
  extractors?: Extractor[];
}

export interface SecurityTemplate {
  id: string;
  info: TemplateInfo;
  /** Default confidence emitted on match. */
  confidence?: Confidence;
  requests: TemplateRequest[];
}
