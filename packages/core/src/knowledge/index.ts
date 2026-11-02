import type { Evidence, Finding, Severity, Snippet } from '../types.js';
import { RULES } from './rules.js';

export * from './incidents.js';
export * from './killchains.js';
export * from './rules.js';

export interface MakeFindingOptions {
  key: string;
  summary: string;
  evidence: Evidence[];
  severity?: Severity;
  title?: string;
  tags?: string[];
  whySuffix?: string;
  extraSteps?: string[];
  extraSnippets?: Snippet[];
  fixSummary?: string;
}

export function makeFinding(ruleId: string, o: MakeFindingOptions): Finding {
  const rule = RULES[ruleId];
  if (!rule) throw new Error(`Unknown rule ${ruleId}`);
  return {
    id: rule.id,
    key: o.key,
    module: rule.module,
    title: o.title ?? rule.title,
    severity: o.severity ?? rule.severity,
    killChain: rule.killChain,
    stage: rule.stage,
    incidentIds: rule.incidentIds,
    summary: o.summary,
    why: o.whySuffix ? `${rule.why}\n\n${o.whySuffix}` : rule.why,
    evidence: o.evidence,
    fix: {
      ...rule.fix,
      summary: o.fixSummary ?? rule.fix.summary,
      steps: [...(o.extraSteps ?? []), ...rule.fix.steps],
      snippets: [...(o.extraSnippets ?? []), ...(rule.fix.snippets ?? [])]
    },
    references: rule.references,
    tags: o.tags ?? []
  };
}

export function bump(sev: Severity, levels = 1): Severity {
  const order: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
  const i = Math.min(order.length - 1, order.indexOf(sev) + levels);
  return order[i];
}
