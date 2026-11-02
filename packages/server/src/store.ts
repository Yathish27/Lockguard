import { mkdirSync, readFileSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import type { Baseline } from '@safetyfirst/core';
import { baselineFileName } from '@safetyfirst/core';

/** Local, on-disk only. Nothing leaves the machine. */
export function dataDir(): string {
  const d = process.env.SAFETYFIRST_HOME || join(process.cwd(), '.safetyfirst');
  mkdirSync(join(d, 'baselines'), { recursive: true });
  mkdirSync(join(d, 'reports'), { recursive: true });
  return d;
}

export function saveBaseline(b: Baseline): string {
  const dir = join(dataDir(), 'baselines');
  const file = join(dir, baselineFileName(b.host));
  writeFileSync(file, JSON.stringify(b, null, 2));
  return file;
}
export function loadBaseline(host: string): Baseline | null {
  const file = join(dataDir(), 'baselines', baselineFileName(host));
  if (!existsSync(file)) return null;
  try { return JSON.parse(readFileSync(file, 'utf8')) as Baseline; } catch { return null; }
}
export function listBaselines(): Array<{ host: string; createdAt: string; scripts: number }> {
  const dir = join(dataDir(), 'baselines');
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((f) => f.endsWith('.json')).map((f) => {
    try { const b = JSON.parse(readFileSync(join(dir, f), 'utf8')) as Baseline; return { host: b.host, createdAt: b.createdAt, scripts: b.scripts.length }; } catch { return null; }
  }).filter((x): x is { host: string; createdAt: string; scripts: number } => !!x);
}
export function saveReport(id: string, report: unknown): string {
  const file = join(dataDir(), 'reports', `${id}.json`);
  writeFileSync(file, JSON.stringify(report, null, 2));
  return file;
}
