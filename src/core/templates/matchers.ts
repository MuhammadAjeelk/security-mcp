import type { Matcher } from './types.js';

export interface MatcherInput {
  status: number;
  headers: Record<string, string>;
  body: string;
}

export interface MatcherEvaluation {
  matched: boolean;
  hits: string[];
}

export function evaluateMatcher(matcher: Matcher, input: MatcherInput): MatcherEvaluation {
  const hits: string[] = [];
  let inner: boolean;

  switch (matcher.type) {
    case 'status': {
      const allowed = matcher.status ?? [];
      inner = allowed.includes(input.status);
      if (inner) hits.push(`status=${input.status}`);
      break;
    }
    case 'header': {
      const name = (matcher.header ?? '').toLowerCase();
      if (!name) {
        inner = false;
        break;
      }
      const found = input.headers[name];
      const expected = matcher.words ?? [];
      if (expected.length === 0) {
        inner = found !== undefined;
        if (inner) hits.push(`${name}=${found}`);
      } else {
        inner = found !== undefined && expected.some((w) => found.toLowerCase().includes(w.toLowerCase()));
        if (inner) hits.push(`${name}=${found}`);
      }
      break;
    }
    case 'word': {
      const words = matcher.words ?? [];
      const haystack = haystackFor(matcher, input);
      const cs = matcher.caseSensitive ?? false;
      const target = cs ? haystack : haystack.toLowerCase();
      const matches = words.filter((w) => target.includes(cs ? w : w.toLowerCase()));
      const cond: 'and' | 'or' = matcher.condition ?? 'or';
      inner = cond === 'and' ? matches.length === words.length : matches.length > 0;
      hits.push(...matches);
      break;
    }
    case 'regex': {
      const patterns = matcher.regex ?? [];
      const haystack = haystackFor(matcher, input);
      const matches: string[] = [];
      for (const p of patterns) {
        try {
          // Strip Nuclei-style inline flags (e.g. `(?im)`) — JS handles flags separately.
          const cleaned = p.replace(/^\(\?[a-z]+\)/, '');
          const re = new RegExp(cleaned, 'im');
          const m = re.exec(haystack);
          if (m) matches.push(m[0].slice(0, 200));
        } catch {
          // ignore invalid regex
        }
      }
      const cond: 'and' | 'or' = matcher.condition ?? 'or';
      inner = cond === 'and' ? matches.length === patterns.length : matches.length > 0;
      hits.push(...matches);
      break;
    }
    default:
      inner = false;
  }

  const final = matcher.negative ? !inner : inner;
  return { matched: final, hits };
}

function haystackFor(matcher: Matcher, input: MatcherInput): string {
  const part = matcher.part ?? 'body';
  if (part === 'header') {
    return Object.entries(input.headers)
      .map(([k, v]) => `${k}: ${v}`)
      .join('\n');
  }
  if (part === 'all') {
    const headers = Object.entries(input.headers)
      .map(([k, v]) => `${k}: ${v}`)
      .join('\n');
    return `${headers}\n\n${input.body}`;
  }
  return input.body;
}
