import { validateTarget } from './target-policy.js';

export interface RedirectDecision {
  follow: boolean;
  reason: string;
}

/**
 * A redirect is followed only if the destination is itself a valid scan target
 * under the same policy used for the initial URL.
 */
export function evaluateRedirect(
  currentUrl: string,
  location: string,
  extraAllowedHosts?: string[],
): RedirectDecision {
  const absolute = resolveLocation(currentUrl, location);
  if (!absolute) {
    return { follow: false, reason: `Cannot resolve redirect target "${location}"` };
  }
  const decision = validateTarget(absolute, { extraAllowedHosts });
  if (!decision.allowed) {
    return { follow: false, reason: `Redirect blocked: ${decision.reason}` };
  }
  return { follow: true, reason: `Redirect to allowed ${decision.classification} target` };
}

function resolveLocation(currentUrl: string, location: string): string | null {
  try {
    return new URL(location, currentUrl).toString();
  } catch {
    return null;
  }
}
