import type { JobRecord, JobRunner } from './types.js';

/**
 * BullMQ-backed runner stub. Intentionally not implemented in V1 — the spec
 * defers queue work until in-memory becomes insufficient.
 *
 * To enable later:
 *   1. `npm i bullmq ioredis`
 *   2. Provide a Redis connection in env (REDIS_URL).
 *   3. Implement enqueue/get using the BullMQ Queue + Worker APIs.
 *   4. Mirror the JobRunner<TInput, TResult> contract so callers don't change.
 *
 * The stub throws on construction so accidental wiring fails loud rather than
 * silently using an unconfigured queue.
 */
export class BullMqJobRunner<TInput, TResult> implements JobRunner<TInput, TResult> {
  constructor() {
    throw new Error(
      'BullMQ job runner is not implemented in V1. Use InMemoryJobRunner or implement this class.',
    );
  }

  enqueue(_input: TInput): Promise<JobRecord<TResult>> {
    return Promise.reject(new Error('not implemented'));
  }

  get(_id: string): Promise<JobRecord<TResult> | undefined> {
    return Promise.reject(new Error('not implemented'));
  }
}
