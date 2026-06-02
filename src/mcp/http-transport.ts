import type { Server } from '@modelcontextprotocol/sdk/server/index.js';

/**
 * Scaffold for Streamable HTTP transport (hosted deployment).
 *
 * V1 ships with stdio only. When you're ready to host:
 *  1. `npm i express`
 *  2. Mount `StreamableHTTPServerTransport` from `@modelcontextprotocol/sdk/server/streamableHttp.js`
 *     against a POST/GET endpoint such as `/mcp`.
 *  3. Authenticate using MCP_API_KEY before letting the transport touch the server.
 *  4. Update the README + Claude Code / Cursor configs to use `type: "sse"` or
 *     `type: "http"` instead of `stdio`.
 *
 * This file intentionally throws so an unfinished hosted deployment fails loud.
 */
export async function startHttpTransport(_server: Server, _port: number): Promise<never> {
  throw new Error(
    'HTTP transport scaffold not implemented in V1. See src/mcp/http-transport.ts comments to enable.',
  );
}
