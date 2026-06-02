import { readdir, readFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import yaml from 'js-yaml';
import type { SecurityTemplate } from './types.js';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

const BUNDLED_DIR = resolve(__dirname, '../../../templates');

export async function loadTemplatesFromDir(dirPath: string): Promise<SecurityTemplate[]> {
  const absolute = resolve(dirPath);
  let entries: string[];
  try {
    entries = await readdir(absolute);
  } catch {
    return [];
  }
  const out: SecurityTemplate[] = [];
  for (const entry of entries) {
    if (!/\.ya?ml$/i.test(entry)) continue;
    const filePath = join(absolute, entry);
    try {
      const raw = await readFile(filePath, 'utf8');
      const parsed = yaml.load(raw) as SecurityTemplate;
      if (!parsed || typeof parsed.id !== 'string' || !parsed.requests) {
        continue;
      }
      out.push(parsed);
    } catch {
      // skip malformed templates rather than failing the whole load
    }
  }
  return out;
}

export async function loadBundledTemplates(): Promise<SecurityTemplate[]> {
  return loadTemplatesFromDir(BUNDLED_DIR);
}
