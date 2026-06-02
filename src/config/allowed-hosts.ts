import { getEnv } from './env.js';

export interface AllowedHostConfig {
  readonly localhostHostnames: ReadonlySet<string>;
  readonly stagingHostnames: ReadonlySet<string>;
}

const LOCALHOST_HOSTNAMES = new Set<string>(['localhost', '127.0.0.1', '::1', '[::1]']);

export function getAllowedHosts(): AllowedHostConfig {
  const env = getEnv();
  return {
    localhostHostnames: LOCALHOST_HOSTNAMES,
    stagingHostnames: new Set(env.ALLOWED_STAGING_HOSTS.map((h: string) => h.toLowerCase())),
  };
}
