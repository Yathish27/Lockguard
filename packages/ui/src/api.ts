import type { Job, Knowledge, Report } from './types';

const base = '/api';
async function req<T>(path: string, opts?: RequestInit): Promise<T> {
  const r = await fetch(base + path, opts);
  const text = await r.text();
  let data: unknown;
  try { data = text ? JSON.parse(text) : {}; } catch { data = { error: text }; }
  if (!r.ok) throw new Error((data as { error?: string })?.error || `HTTP ${r.status}`);
  return data as T;
}
const post = <T>(path: string, body?: unknown) => req<T>(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });

export interface ScanRequest {
  web?: { url: string; signingPage?: boolean | 'auto'; firstPartyDomains?: string[]; storageState?: unknown; useSavedBaseline?: boolean; ignoreHTTPSErrors?: boolean };
  repo?: { path: string };
  chain?: { addresses?: string[]; network?: string; rpcUrl?: string; knownDelegates?: string[]; knownSpenders?: string[]; policy?: string | null };
}

export const api = {
  health: () => req<{ ok: boolean; version: string }>('/health'),
  knowledge: () => req<Knowledge>('/knowledge'),
  startScan: (body: ScanRequest) => post<{ id: string }>('/scan', body),
  job: (id: string) => req<Job>(`/scan/${id}`),
  reportUrl: (id: string, fmt: 'json' | 'md' | 'sarif') => `${base}/scan/${id}/report.${fmt}`,
  policyTemplate: () => fetch(`${base}/policy/template`).then((r) => r.text()),
  sri: (url: string) => post<{ url: string; bytes: number; sha256: string; sha384: string; sha512: string; corsHeader: string | null; contentType: string | null; tag: string; warnings: string[] }>('/tools/sri', { url }),
  pinActions: (yaml: string, token?: string) => post<{ yaml: string; changes: { line: number; from: string; to: string; comment?: string; error?: string }[] }>('/tools/pin-actions', { yaml, token }),
  policyLint: (policy: string) => post<{ findings: import('./types').Finding[] }>('/tools/policy-lint', { policy }),
  revokeCalldata: (token: string, spender: string) => post<{ erc20: { to: string | null; data: string }; erc721: { data: string } }>('/tools/revoke-calldata', { token, spender }),
  labStatus: () => req<{ running: boolean; vulnerable: string | null; hardened: string | null; vendor: string | null }>('/lab/status'),
  labStart: () => post<{ running: boolean; vulnerable: string; hardened: string; vendor: string }>('/lab/start'),
  baselines: () => req<{ baselines: { host: string; createdAt: string; scripts: number }[] }>('/baselines'),
  saveBaseline: (jobId: string) => post<{ ok: boolean; file: string; host: string }>('/baselines/save', { jobId })
};

export async function pollJob(id: string, onUpdate: (j: Job) => void): Promise<Report> {
  for (;;) {
    const j = await api.job(id);
    onUpdate(j);
    if (j.status === 'done') return j.report!;
    if (j.status === 'error') throw new Error(j.error || 'scan failed');
    await new Promise((r) => setTimeout(r, 350));
  }
}
