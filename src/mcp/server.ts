import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import {
  handleSecurityScan,
  securityScanInputSchema,
  securityScanToolDefinition,
} from './tools/security-scan.tool.js';
import {
  handleValidateTarget,
  validateTargetInputSchema,
  validateTargetToolDefinition,
} from './tools/validate-target.tool.js';
import {
  handlePromptLoop,
  promptLoopInputSchema,
  promptLoopToolDefinition,
} from './tools/prompt-loop.tool.js';
import {
  handleGenerateReport,
  reportInputSchema,
  reportToolDefinition,
} from './tools/report.tool.js';
import {
  handleListPrompts,
  listPromptsInputSchema,
  listPromptsToolDefinition,
} from './tools/list-prompts.tool.js';

export function createMcpServer(): Server {
  const server = new Server(
    { name: 'security-mcp', version: '0.1.0' },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      validateTargetToolDefinition,
      securityScanToolDefinition,
      listPromptsToolDefinition,
      promptLoopToolDefinition,
      reportToolDefinition,
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: args } = req.params;
    try {
      switch (name) {
        case 'validate_target': {
          const parsed = validateTargetInputSchema.parse(args ?? {});
          return jsonContent(handleValidateTarget(parsed));
        }
        case 'security_scan': {
          const parsed = securityScanInputSchema.parse(args ?? {});
          return jsonContent(await handleSecurityScan(parsed));
        }
        case 'list_security_prompts': {
          const parsed = listPromptsInputSchema.parse(args ?? {});
          return jsonContent(handleListPrompts(parsed));
        }
        case 'run_prompt_loop': {
          const parsed = promptLoopInputSchema.parse(args ?? {});
          return jsonContent(await handlePromptLoop(parsed));
        }
        case 'generate_report': {
          const parsed = reportInputSchema.parse(args ?? {});
          return jsonContent(await handleGenerateReport(parsed));
        }
        default:
          return jsonContent({ ok: false, error: `Unknown tool: ${name}` }, true);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return jsonContent({ ok: false, error: message }, true);
    }
  });

  return server;
}

function jsonContent(payload: unknown, isError = false) {
  return {
    isError,
    content: [
      {
        type: 'text' as const,
        text: JSON.stringify(payload, null, 2),
      },
    ],
  };
}
