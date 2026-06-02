import { randomUUID } from 'node:crypto';
import type { JobRecord, JobRunner } from './types.js';

export class InMemoryJobRunner<TInput, TResult> implements JobRunner<TInput, TResult> {
  private readonly jobs = new Map<string, JobRecord<TResult>>();

  constructor(private readonly handler: (input: TInput) => Promise<TResult>) {}

  async enqueue(input: TInput): Promise<JobRecord<TResult>> {
    const id = randomUUID();
    const record: JobRecord<TResult> = {
      id,
      status: 'running',
      createdAt: new Date().toISOString(),
      startedAt: new Date().toISOString(),
    };
    this.jobs.set(id, record);
    try {
      const result = await this.handler(input);
      const completed: JobRecord<TResult> = {
        ...record,
        status: 'completed',
        completedAt: new Date().toISOString(),
        result,
      };
      this.jobs.set(id, completed);
      return completed;
    } catch (err) {
      const failed: JobRecord<TResult> = {
        ...record,
        status: 'failed',
        completedAt: new Date().toISOString(),
        error: err instanceof Error ? err.message : String(err),
      };
      this.jobs.set(id, failed);
      return failed;
    }
  }

  async get(id: string): Promise<JobRecord<TResult> | undefined> {
    return this.jobs.get(id);
  }
}
