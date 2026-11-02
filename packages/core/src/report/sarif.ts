import type { Report, Severity } from '../types.js';
import { RULES } from '../knowledge/index.js';

const LEVEL: Record<Severity, 'error' | 'warning' | 'note' | 'none'> = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
const SCORE: Record<Severity, string> = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '0.5' };

export function toSarif(report: Report, repoRoot?: string): unknown {
  const rules = Object.values(RULES).map((r) => ({
    id: r.id,
    name: r.title.replace(/[^A-Za-z0-9]+/g, ''),
    shortDescription: { text: r.title },
    fullDescription: { text: r.why },
    help: { text: `${r.fix.summary}\n\n${r.fix.steps.map((s, i) => `${i + 1}. ${s}`).join('\n')}`, markdown: `**${r.fix.summary}**\n\n${r.fix.steps.map((s, i) => `${i + 1}. ${s}`).join('\n')}` },
    helpUri: r.references[0]?.url ?? 'https://github.com/Yathish27/Lockguard',
    defaultConfiguration: { level: LEVEL[r.severity] },
    properties: { 'security-severity': SCORE[r.severity], tags: ['security', r.killChain, r.module] }
  }));
  const results = report.modules.flatMap((m) =>
    m.findings.map((f) => {
      const first = f.evidence[0];
      const isFile = m.module === 'repo' && first && !/^https?:/.test(first.location);
      const uri = isFile ? first.location.replace(/\\/g, '/') : (first?.location && /^https?:/.test(first.location) ? first.location : m.target);
      const location: any = { physicalLocation: { artifactLocation: { uri, ...(isFile && repoRoot ? { uriBaseId: '%SRCROOT%' } : {}) } } };
      if (isFile && first?.line) location.physicalLocation.region = { startLine: first.line };
      return {
        ruleId: f.id,
        level: LEVEL[f.severity],
        message: { text: `${f.summary}${first ? ` — ${first.detail}` : ''}` },
        locations: [location],
        partialFingerprints: { lockguardKey: f.key },
        properties: { severity: f.severity, killChain: f.killChain, stage: f.stage, incidents: f.incidentIds }
      };
    })
  );
  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'Lockguard', version: report.tool.version, informationUri: 'https://github.com/Yathish27/Lockguard', rules } },
        results,
        ...(repoRoot ? { originalUriBaseIds: { '%SRCROOT%': { uri: 'file://' + repoRoot.replace(/\\/g, '/').replace(/\/?$/, '/') } } } : {})
      }
    ]
  };
}
