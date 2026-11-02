import type { Report } from '../types.js';
import { INCIDENTS } from '../knowledge/index.js';

export function toMarkdown(report: Report): string {
  const L: string[] = [];
  L.push(`# Safetyfirst report`, '', `Generated ${report.createdAt} · overall score **${report.overall.value}/100 (${report.overall.grade})**`, '');
  L.push('| Module | Target | Score | Critical | High | Medium | Low | Info |', '|---|---|---|---|---|---|---|---|');
  for (const m of report.modules) L.push(`| ${m.module} | ${m.target} | ${m.score.value} (${m.score.grade}) | ${m.score.counts.critical} | ${m.score.counts.high} | ${m.score.counts.medium} | ${m.score.counts.low} | ${m.score.counts.info} |`);
  L.push('', '## Kill chains', '');
  for (const kc of report.killChains) {
    L.push(`### ${kc.name}`, '', `_${kc.tagline}_`, '', '| Step | Guardrail | Signal | Status |', '|---|---|---|---|');
    for (const s of kc.stages) L.push(`| ${s.step} | ${s.guardrail} | ${s.signal} | ${s.status === 'open' ? `🔴 open (${s.worst})` : s.status === 'covered' ? '🟢 covered' : '⚪ not scanned'} |`);
    L.push('');
  }
  L.push('## Findings', '');
  const all = report.modules.flatMap((m) => m.findings);
  for (const f of all) {
    L.push(`### [${f.severity.toUpperCase()}] ${f.id} · ${f.title}`, '', f.summary, '');
    if (f.incidentIds.length) L.push(`**Real incident:** ${f.incidentIds.map((i) => `${INCIDENTS[i]?.name ?? i} (${INCIDENTS[i]?.date ?? ''})`).join('; ')}`, '');
    L.push('**Evidence**', '');
    for (const e of f.evidence) L.push(`- \`${e.location}${e.line ? `:${e.line}` : ''}\` — ${e.detail}`);
    L.push('', `**Why it matters.** ${f.why}`, '', `**Fix.** ${f.fix.summary}`, '');
    f.fix.steps.forEach((s, i) => L.push(`${i + 1}. ${s}`));
    for (const sn of f.fix.snippets ?? []) L.push('', `_${sn.title}_`, '', '```' + sn.lang, sn.code, '```');
    L.push('');
  }
  for (const m of report.modules) if (m.errors.length) { L.push(`## Errors (${m.module})`, '', ...m.errors.map((e) => `- ${e}`), ''); }
  return L.join('\n');
}
