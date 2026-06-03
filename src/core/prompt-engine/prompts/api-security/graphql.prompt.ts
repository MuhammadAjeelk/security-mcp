import type { SecurityPrompt } from '../../types.js';
import { asScanEvidence } from '../../helpers.js';

export const graphqlPrompt: SecurityPrompt = {
  id: 'api.graphql',
  title: 'GraphQL abuse (introspection, auth, batching)',
  category: 'api',
  severityFocus: 'medium',
  prompt: [
    'Goal: Assess a GraphQL endpoint for the GraphQL-specific weaknesses that REST checks miss:',
    '1. Introspection enabled in production (hands attackers the full schema/attack map).',
    '2. Field-level authorization gaps — a query returning data the role should not see.',
    '3. Query batching / aliasing used to bypass rate limits or brute-force (e.g. login aliased 100x).',
    '4. Deeply nested / recursive queries enabling DoS (no depth/complexity limit).',
    '5. Mutations exposed without auth, or sensitive args (role, isAdmin) accepted (mass assignment).',
    '',
    'Evidence required: a /graphql (or /graphiql/api/graphql) endpoint; a successful introspection',
    'response; per-role differential on the same query if accounts are available.',
    '',
    'Method (non-destructive): send the minimal introspection query',
    '`{__schema{queryType{name} types{name}}}`. Read the schema to enumerate queries/mutations, then',
    'reason about which should be auth-gated. Do NOT run destructive mutations or huge nested queries.',
    '',
    'Output: severity medium for introspection-in-prod; high for an unauthenticated sensitive query/',
    'mutation; confidence high when proven against evidence.',
  ].join('\n'),
  heuristic(ctx) {
    const ev = asScanEvidence(ctx.evidence);
    if (!ev) return [];
    const gql = ev.endpoints.filter((e) => /graphql/i.test(e.url));
    if (gql.length === 0) return [];
    return [
      {
        title: 'GraphQL endpoint exposed',
        severity: 'low' as const,
        category: 'api',
        description:
          `A GraphQL endpoint was discovered (${gql[0]!.url}). Verify introspection is disabled in ` +
          'production and that field-level authorization, query depth/complexity limits, and ' +
          'batching protections are in place.',
        evidence: { endpoints: gql.map((g) => g.url).slice(0, 5) },
        impact: 'Schema disclosure and GraphQL-specific abuse (batching brute-force, nested-query DoS).',
        remediation:
          'Disable introspection in production, enforce per-field authorization, cap query depth/' +
          'complexity, and rate-limit by operation rather than by HTTP request.',
        confidence: 'medium' as const,
      },
    ];
  },
};
