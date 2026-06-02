export interface AuditEvent {
  timestamp: string;
  scanId: string;
  type: string;
  data: Record<string, unknown>;
}

export class AuditLogger {
  private readonly events: AuditEvent[] = [];

  constructor(public readonly scanId: string) {}

  event(type: string, data: Record<string, unknown> = {}): void {
    const ev: AuditEvent = {
      timestamp: new Date().toISOString(),
      scanId: this.scanId,
      type,
      data,
    };
    this.events.push(ev);
    // Emit to stderr so MCP stdio transport on stdout remains uncontaminated.
    process.stderr.write(`[audit] ${JSON.stringify(ev)}\n`);
  }

  list(): readonly AuditEvent[] {
    return this.events;
  }
}
