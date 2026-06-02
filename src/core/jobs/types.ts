export type JobStatus = 'pending' | 'running' | 'completed' | 'failed';

export interface JobRecord<TResult> {
  id: string;
  status: JobStatus;
  createdAt: string;
  startedAt?: string;
  completedAt?: string;
  result?: TResult;
  error?: string;
}

export interface JobRunner<TInput, TResult> {
  enqueue(input: TInput): Promise<JobRecord<TResult>>;
  get(id: string): Promise<JobRecord<TResult> | undefined>;
}
