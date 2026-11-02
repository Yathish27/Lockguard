import { randomUUID } from 'node:crypto';
import { runScan, type Report, type ScanTargets } from '@safetyfirst/core';
import { saveReport } from './store.js';

export interface Job {
  id: string;
  status: 'running' | 'done' | 'error';
  pct: number;
  message: string;
  log: Array<{ t: number; message: string; pct: number }>;
  startedAt: number;
  finishedAt?: number;
  report?: Report;
  error?: string;
  targetSummary: string;
}

const jobs = new Map<string, Job>();

export function startScan(targets: ScanTargets): Job {
  const id = randomUUID();
  const parts: string[] = [];
  if (targets.web) parts.push(`web:${safeHost(targets.web.url)}`);
  if (targets.repo) parts.push(`repo:${targets.repo.path}`);
  if (targets.chain) parts.push(`chain:${targets.chain.network}(${targets.chain.addresses?.length ?? 0})`);
  const job: Job = { id, status: 'running', pct: 0, message: 'starting', log: [], startedAt: Date.now(), targetSummary: parts.join(' · ') || 'scan' };
  jobs.set(id, job);
  runScan(targets, (message, pct) => {
    job.message = message;
    if (typeof pct === 'number') job.pct = Math.max(job.pct, Math.min(99, pct));
    job.log.push({ t: Date.now(), message, pct: job.pct });
    if (job.log.length > 400) job.log.splice(0, job.log.length - 400);
  }, { id })
    .then((report) => { job.report = report; job.status = 'done'; job.pct = 100; job.message = 'complete'; job.finishedAt = Date.now(); try { saveReport(id, report); } catch { /* ignore */ } })
    .catch((e) => { job.status = 'error'; job.error = e?.stack ?? e?.message ?? String(e); job.message = 'error'; job.finishedAt = Date.now(); });
  // prune
  if (jobs.size > 50) { const old = [...jobs.values()].sort((a, b) => a.startedAt - b.startedAt).slice(0, jobs.size - 50); for (const j of old) jobs.delete(j.id); }
  return job;
}
export function getJob(id: string): Job | undefined { return jobs.get(id); }
function safeHost(u: string): string { try { return new URL(u).host; } catch { return u; } }
