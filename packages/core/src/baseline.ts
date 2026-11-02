import type { Baseline, BaselineScript, ScriptObservation } from './types.js';

function normalize(url: string): string {
  try { const u = new URL(url); u.hash = ''; return u.toString(); } catch { return url; }
}
function stripQuery(url: string): string {
  try { const u = new URL(url); u.search = ''; u.hash = ''; return u.toString(); } catch { return url; }
}

export function buildBaseline(pageUrl: string, scripts: ScriptObservation[]): Baseline {
  const host = (() => { try { return new URL(pageUrl).hostname; } catch { return pageUrl; } })();
  return {
    version: 1,
    url: pageUrl,
    host,
    createdAt: new Date().toISOString(),
    scripts: scripts
      .filter((s) => s.sha256)
      .map<BaselineScript>((s) => ({ url: normalize(s.url), origin: s.origin, sha256: s.sha256!, sha384: s.sha384!, bytes: s.bytes }))
  };
}

export interface BaselineDiff {
  changed: Array<{ url: string; before: string; after: string; bytesBefore: number; bytesAfter: number; thirdParty: boolean }>;
  added: Array<{ url: string; sha256: string | null; bytes: number; thirdParty: boolean }>;
  removed: Array<{ url: string }>;
  unchanged: number;
}

export function diffBaseline(baseline: Baseline, scripts: ScriptObservation[]): BaselineDiff {
  const base = new Map(baseline.scripts.map((s) => [normalize(s.url), s]));
  const baseNoQuery = new Map(baseline.scripts.map((s) => [stripQuery(s.url), s]));
  const diff: BaselineDiff = { changed: [], added: [], removed: [], unchanged: 0 };
  const matched = new Set<string>();
  for (const s of scripts) {
    const key = normalize(s.url);
    const b = base.get(key) ?? baseNoQuery.get(stripQuery(s.url));
    if (!b) { diff.added.push({ url: s.url, sha256: s.sha256, bytes: s.bytes, thirdParty: s.thirdParty }); continue; }
    matched.add(normalize(b.url));
    if (s.sha256 && s.sha256 !== b.sha256) diff.changed.push({ url: s.url, before: b.sha256, after: s.sha256, bytesBefore: b.bytes, bytesAfter: s.bytes, thirdParty: s.thirdParty });
    else diff.unchanged++;
  }
  for (const b of baseline.scripts) if (!matched.has(normalize(b.url))) diff.removed.push({ url: b.url });
  return diff;
}

export function baselineFileName(host: string): string {
  return host.replace(/[^a-z0-9.-]/gi, '_') + '.json';
}
