import { describe, it, expect } from 'vitest';
import { parseRobots, parseSitemap } from '../core/scanner/recon.js';
import { parseWordlist, isPresent } from '../core/scanner/content-discovery.js';
import { extractPathsFromJs, collectScriptUrls } from '../core/scanner/js-endpoint-extractor.js';

describe('recon: robots.txt parsing', () => {
  it('extracts Disallow paths and Sitemap directives, ignoring wildcards/catch-all', () => {
    const body = [
      'User-agent: *',
      'Disallow: /admin/',
      'Disallow: /internal/secret',
      'Allow: /public',
      'Disallow: /', // catch-all — ignored
      'Disallow: /search?*', // wildcard — ignored
      'Sitemap: http://localhost:3000/sitemap.xml',
      '# a comment',
    ].join('\n');
    const out = parseRobots(body, 'http://localhost:3000');
    expect(out.paths).toContain('http://localhost:3000/admin/');
    expect(out.paths).toContain('http://localhost:3000/internal/secret');
    expect(out.paths).toContain('http://localhost:3000/public');
    expect(out.paths).not.toContain('http://localhost:3000/');
    expect(out.paths.some((p) => p.includes('search'))).toBe(false);
    expect(out.sitemaps).toEqual(['http://localhost:3000/sitemap.xml']);
  });

  it('drops cross-origin paths', () => {
    const out = parseRobots('Disallow: https://evil.example/x', 'http://localhost:3000');
    expect(out.paths).toHaveLength(0);
  });
});

describe('recon: sitemap parsing', () => {
  it('extracts same-origin <loc> urls only', () => {
    const xml = `<?xml version="1.0"?><urlset>
      <url><loc>http://localhost:3000/a</loc></url>
      <url><loc>http://localhost:3000/b/c</loc></url>
      <url><loc>https://other.example/x</loc></url>
    </urlset>`;
    const out = parseSitemap(xml, 'http://localhost:3000');
    expect(out).toEqual(['http://localhost:3000/a', 'http://localhost:3000/b/c']);
  });
});

describe('content discovery: wordlist parsing', () => {
  it('strips comments, blanks, and dedupes', () => {
    const raw = '# header\n/admin\n\n/admin\n  /api/users  \n# trailing';
    expect(parseWordlist(raw)).toEqual(['/admin', '/api/users']);
  });
});

describe('content discovery: presence heuristic', () => {
  it('treats 404/410 as absent', () => {
    expect(isPresent(404, 100)).toBe(false);
    expect(isPresent(410, 100)).toBe(false);
  });
  it('treats 200/401/403 as present (protected resources are surface too)', () => {
    expect(isPresent(200, 100)).toBe(true);
    expect(isPresent(401, 100)).toBe(true);
    expect(isPresent(403, 100)).toBe(true);
  });
  it('treats 5xx as present (server error on a guessed path is a signal)', () => {
    expect(isPresent(500, 100)).toBe(true);
  });
  it('filters soft-404s that match the not-found baseline', () => {
    expect(isPresent(200, 512, { status: 200, length: 512 })).toBe(false);
    expect(isPresent(200, 999, { status: 200, length: 512 })).toBe(true);
  });
});

describe('js endpoint extraction', () => {
  it('pulls api/route literals and fetch/axios targets, ignores noise', () => {
    const js = `
      const a = "/api/users/123";
      fetch('/v2/orders');
      axios.post("/auth/login", body);
      const klass = "btn-primary";          // noise
      const t = "hello world";              // noise
      const g = '/graphql';
    `;
    const out = extractPathsFromJs(js);
    expect(out).toContain('/api/users/123');
    expect(out).toContain('/v2/orders');
    expect(out).toContain('/auth/login');
    expect(out).toContain('/graphql');
    expect(out).not.toContain('btn-primary');
    expect(out).not.toContain('hello world');
  });

  it('collects same-origin <script src> urls only', () => {
    const html = `<script src="/static/app.js"></script>
      <script src="https://cdn.example.com/vendor.js"></script>
      <script src="bundle.js?v=2"></script>`;
    const urls = collectScriptUrls(
      { 'http://localhost:3000/': html },
      'http://localhost:3000',
    );
    expect(urls).toContain('http://localhost:3000/static/app.js');
    expect(urls).toContain('http://localhost:3000/bundle.js?v=2');
    expect(urls.some((u) => u.includes('cdn.example.com'))).toBe(false);
  });
});
