import type { SecurityPrompt } from './types.js';

import { idorPrompt } from './prompts/access-control/idor.prompt.js';
import { bolaPrompt } from './prompts/access-control/bola.prompt.js';
import { bflaPrompt } from './prompts/access-control/bfla.prompt.js';
import { roleEscalationPrompt } from './prompts/access-control/role-escalation.prompt.js';
import { privilegeEscalationPrompt } from './prompts/access-control/privilege-escalation.prompt.js';

import { authBypassPrompt } from './prompts/authentication/auth-bypass.prompt.js';
import { jwtPrompt } from './prompts/authentication/jwt.prompt.js';
import { sessionPrompt } from './prompts/authentication/session.prompt.js';
import { passwordResetPrompt } from './prompts/authentication/password-reset.prompt.js';
import { magicLinkPrompt } from './prompts/authentication/magic-link.prompt.js';
import { oauthPrompt } from './prompts/authentication/oauth.prompt.js';

import { sqlInjectionPrompt } from './prompts/injection/sql-injection.prompt.js';
import { nosqlInjectionPrompt } from './prompts/injection/nosql-injection.prompt.js';
import { commandInjectionPrompt } from './prompts/injection/command-injection.prompt.js';
import { xssPrompt } from './prompts/injection/xss.prompt.js';
import { ssrfPrompt } from './prompts/injection/ssrf.prompt.js';
import { pathTraversalPrompt } from './prompts/injection/path-traversal.prompt.js';

import { rateLimitPrompt } from './prompts/api-security/rate-limit.prompt.js';
import { massAssignmentPrompt } from './prompts/api-security/mass-assignment.prompt.js';
import { excessiveDataExposurePrompt } from './prompts/api-security/excessive-data-exposure.prompt.js';
import { corsPrompt } from './prompts/api-security/cors.prompt.js';
import { csrfPrompt } from './prompts/api-security/csrf.prompt.js';
import { openRedirectPrompt } from './prompts/api-security/open-redirect.prompt.js';
import { webhookPrompt } from './prompts/api-security/webhook.prompt.js';
import { sensitiveDataPrompt } from './prompts/api-security/sensitive-data.prompt.js';
import { cachePoisoningPrompt } from './prompts/api-security/cache-poisoning.prompt.js';
import { deserializationPrompt } from './prompts/api-security/deserialization.prompt.js';

import { paymentAbusePrompt } from './prompts/business-logic/payment-abuse.prompt.js';
import { couponAbusePrompt } from './prompts/business-logic/coupon-abuse.prompt.js';
import { workflowBypassPrompt } from './prompts/business-logic/workflow-bypass.prompt.js';
import { raceConditionPrompt } from './prompts/business-logic/race-condition.prompt.js';

import { fileUploadPrompt } from './prompts/files/file-upload.prompt.js';
import { insecureFileAccessPrompt } from './prompts/files/insecure-file-access.prompt.js';

import { envLeakPrompt } from './prompts/config/env-leak.prompt.js';
import { debugEndpointPrompt } from './prompts/config/debug-endpoint.prompt.js';
import { securityHeadersPrompt } from './prompts/config/security-headers.prompt.js';
import { errorLeakagePrompt } from './prompts/config/error-leakage.prompt.js';

import { dependencyRiskPrompt } from './prompts/infrastructure/dependency-risk.prompt.js';
import { tenantIsolationPrompt } from './prompts/multi-tenant/tenant-isolation.prompt.js';

export const PROMPT_REGISTRY: readonly SecurityPrompt[] = Object.freeze([
  // access-control
  idorPrompt,
  bolaPrompt,
  bflaPrompt,
  roleEscalationPrompt,
  privilegeEscalationPrompt,
  // auth
  authBypassPrompt,
  jwtPrompt,
  sessionPrompt,
  passwordResetPrompt,
  magicLinkPrompt,
  oauthPrompt,
  // injection
  sqlInjectionPrompt,
  nosqlInjectionPrompt,
  commandInjectionPrompt,
  xssPrompt,
  ssrfPrompt,
  pathTraversalPrompt,
  // api-security
  rateLimitPrompt,
  massAssignmentPrompt,
  excessiveDataExposurePrompt,
  corsPrompt,
  csrfPrompt,
  openRedirectPrompt,
  webhookPrompt,
  sensitiveDataPrompt,
  cachePoisoningPrompt,
  deserializationPrompt,
  // business-logic
  paymentAbusePrompt,
  couponAbusePrompt,
  workflowBypassPrompt,
  raceConditionPrompt,
  // files
  fileUploadPrompt,
  insecureFileAccessPrompt,
  // configuration
  envLeakPrompt,
  debugEndpointPrompt,
  securityHeadersPrompt,
  errorLeakagePrompt,
  // infrastructure
  dependencyRiskPrompt,
  // multi-tenant
  tenantIsolationPrompt,
]);

export function getPromptsByCategory(category: SecurityPrompt['category']): SecurityPrompt[] {
  return PROMPT_REGISTRY.filter((p) => p.category === category);
}

export function getPromptById(id: string): SecurityPrompt | undefined {
  return PROMPT_REGISTRY.find((p) => p.id === id);
}
