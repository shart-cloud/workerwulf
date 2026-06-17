export interface WorkerCode {
  compatibilityDate: string;
  compatibilityFlags?: string[];
  allowExperimental?: boolean;
  mainModule: string;
  modules: Record<string, string | { js?: string; cjs?: string; py?: string; text?: string; data?: ArrayBuffer; json?: unknown }>;
  globalOutbound?: Fetcher | null;
  env?: Record<string, unknown>;
  tails?: Fetcher[];
}

export interface WorkerStub {
  getEntrypoint(name?: string): Fetcher;
}

export interface WorkerLoader {
  load(code: WorkerCode): WorkerStub;
  get(id: string, factory: () => Promise<WorkerCode> | WorkerCode): WorkerStub;
}