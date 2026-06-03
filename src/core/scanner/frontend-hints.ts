/**
 * Derive candidate frontend origins for an API target. Signup/login UIs live on
 * the web app, not the API host, so when the target looks like an API origin we
 * suggest where the registration flow probably is. Pure / no network — the
 * caller (or the audit agent) validates scope and reachability.
 */
export function deriveFrontendCandidates(targetUrl: string): string[] {
  let u: URL;
  try {
    u = new URL(targetUrl);
  } catch {
    return [];
  }
  const host = u.hostname.toLowerCase();
  const proto = u.protocol === 'http:' ? 'http:' : 'https:';
  const out = new Set<string>();
  const add = (h: string) => {
    if (h && h !== host) out.add(`${proto}//${h}`);
  };

  // Strip a leading api / api-* / api. label → the app likely sits at the parent.
  const stripped = host.replace(/^api[-.]/, '');
  if (stripped !== host) {
    add(stripped); // staging.lynsi.net
    add(`app.${stripped}`);
    add(`www.${stripped}`);
    add(`dashboard.${stripped}`);
    add(`portal.${stripped}`);
  }

  // Common sibling subdomains on the same registrable-ish parent.
  const labels = host.split('.');
  if (labels.length >= 2) {
    const parent = labels.slice(-2).join('.');
    for (const sub of ['app', 'www', 'staging', 'dashboard', 'portal', 'web']) {
      add(`${sub}.${parent}`);
    }
    add(parent);
  }

  return [...out];
}

/** True when the target looks like an API origin rather than a web app. */
export function looksLikeApiHost(targetUrl: string): boolean {
  try {
    const u = new URL(targetUrl);
    return /^api[-.]/.test(u.hostname.toLowerCase()) || /\/api(\/|$)/.test(u.pathname);
  } catch {
    return false;
  }
}
