import 'dotenv/config';
import { z } from 'zod';

const csv = (raw: string | undefined): string[] =>
  (raw ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

const EnvSchema = z.object({
  MCP_MODE: z.enum(['stdio', 'http']).default('stdio'),
  MCP_API_KEY: z.string().optional().default(''),
  ALLOWED_STAGING_HOSTS: z
    .string()
    .optional()
    .transform((v) => csv(v)),
  SCAN_TIMEOUT_MS: z.coerce.number().int().positive().default(10_000),
  SCAN_MAX_REQUESTS: z.coerce.number().int().positive().default(50),
  SCAN_MAX_DEPTH: z.coerce.number().int().min(0).max(10).default(2),
  PROMPT_LOOP_MAX_ITERATIONS: z.coerce.number().int().positive().default(3),
  REPORTS_DIR: z.string().default('./reports'),
  LLM_PROVIDER: z.enum(['mock', 'anthropic']).default('mock'),
  ANTHROPIC_API_KEY: z.string().optional().default(''),
  LLM_MODEL: z.string().default('claude-opus-4-7'),
  LLM_MAX_TOKENS: z.coerce.number().int().positive().default(1024),
});

export type Env = z.infer<typeof EnvSchema>;

let cached: Env | null = null;

export function getEnv(): Env {
  if (cached) return cached;
  const parsed = EnvSchema.safeParse(process.env);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ');
    throw new Error(`Invalid environment configuration: ${issues}`);
  }
  cached = parsed.data;
  return cached;
}

export function resetEnvCacheForTests(): void {
  cached = null;
}
