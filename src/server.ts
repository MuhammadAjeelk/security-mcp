#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createMcpServer } from './mcp/server.js';
import { getEnv } from './config/env.js';
import { startHttpTransport } from './mcp/http-transport.js';

async function main(): Promise<void> {
  const env = getEnv();
  const server = createMcpServer();

  if (env.MCP_MODE === 'http') {
    await startHttpTransport(server, 3333);
    return;
  }

  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write('[security-mcp] stdio transport ready\n');
}

main().catch((err) => {
  process.stderr.write(`[security-mcp] fatal: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exit(1);
});
