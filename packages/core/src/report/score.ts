import type { Finding, Grade, KillChainSummary, ModuleResult, Report, Score, Severity } from '../types.js';
import { KILL_CHAINS, RULES } from '../knowledge/index.js';

const WEIGHTS: Record<Severity, number> = { critical: 30, high: 15, medium: 7, low: 3, info: 0 };
const RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export function scoreFindings(findings: Finding[]): Score {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let penalty = 0;
  for (const f of findings) { counts[f.severity]++; penalty += WEIGHTS[f.severity]; }
  const value = Math.max(0, 100 - penalty);
  const grade: Grade = value >= 90 ? 'A' : value >= 75 ? 'B' : value >= 60 ? 'C' : value >= 40 ? 'D' : 'F';
  return { value, grade, counts };
}

export function summarizeKillChains(modules: ModuleResult[]): KillChainSummary[] {
  const ran = new Set(modules.filter((m) => !m.errors.length || m.findings.length).map((m) => m.module));
  const all = modules.flatMap((m) => m.findings);
  return KILL_CHAINS.map((kc) => ({
    id: kc.id,
    name: kc.name,
    tagline: kc.tagline,
    incidentIds: kc.incidentIds,
    stages: kc.stages.map((st) => {
      const fs = all.filter((f) => st.rules.includes(f.id));
      const worst = fs.reduce<Severity | null>((w, f) => (w == null || RANK[f.severity] > RANK[w] ? f.severity : w), null);
      const anyModuleRan = st.rules.some((r) => ran.has(RULES[r].module));
      const status: 'open' | 'covered' | 'unknown' = worst && RANK[worst] >= 1 ? 'open' : anyModuleRan ? 'covered' : 'unknown';
      return { id: st.id, step: st.step, guardrail: st.guardrail, signal: st.signal, status, findingKeys: fs.map((f) => f.key), worst };
    })
  }));
}

export function assembleReport(partial: Omit<Report, 'overall' | 'killChains'>): Report {
  const all = partial.modules.flatMap((m) => m.findings);
  return { ...partial, overall: scoreFindings(all), killChains: summarizeKillChains(partial.modules) };
}
