import { randomUUID } from 'node:crypto';
import type { Progress, Report, ScanTargets } from './types.js';
import { scanWeb } from './scanners/web.js';
import { scanRepo } from './scanners/repo.js';
import { scanChain } from './scanners/chain.js';
import { assembleReport } from './report/score.js';

export const VERSION = '0.1.0';

export * from './types.js';
export * from './knowledge/index.js';
export { scanWeb, analyzeCsp, parseCsp, resolveBrowserPath, sortFindings, sevRank } from './scanners/web.js';
export { scanRepo } from './scanners/repo.js';
export { scanChain, NETWORKS, EXPLORERS, KNOWN_SPENDERS, approveZeroCalldata, setApprovalForAllFalseCalldata } from './scanners/chain.js';
export { lintSignerPolicy, parsePolicy, SIGNER_POLICY_TEMPLATE } from './scanners/policy.js';
export { scoreFindings, summarizeKillChains, assembleReport } from './report/score.js';
export { toSarif } from './report/sarif.js';
export { toMarkdown } from './report/markdown.js';
export { buildBaseline, diffBaseline, baselineFileName } from './baseline.js';
export type { BaselineDiff } from './baseline.js';
export { computeSri } from './tools/sri.js';
export type { SriResult } from './tools/sri.js';
export { pinActions } from './tools/pin-actions.js';
export type { PinResult, PinChange } from './tools/pin-actions.js';
export { isThirdParty, registrableDomain, categorizeHost, isLocalHost, isAddressLike } from './util/origin.js';
export { sriHash, sha256Hex } from './util/hash.js';
export { assertPublicUrl, isPrivateAddress } from './util/ssrf.js';

/** Run every requested module and assemble a report with kill-chain coverage. */
export async function runScan(targets: ScanTargets, onProgress: Progress = () => {}, opts: { id?: string } = {}): Promise<Report> {
  const modules: Report['modules'] = [];
  const total = [targets.web, targets.repo, targets.chain].filter(Boolean).length || 1;
  let done = 0;
  const sub = (label: string): Progress => (msg, pct) => onProgress(`[${label}] ${msg}`, Math.round(((done + (pct ?? 0) / 100) / total) * 100));
  if (targets.repo) { modules.push(await scanRepo(targets.repo, sub('repo'))); done++; }
  if (targets.web) { modules.push(await scanWeb(targets.web, sub('web'))); done++; }
  if (targets.chain) { modules.push(await scanChain(targets.chain, sub('chain'))); done++; }
  onProgress('Assembling report', 100);
  const { web, ...rest } = targets;
  const safeTargets: ScanTargets = { ...rest, ...(web ? { web: { ...web, storageState: web.storageState ? '[provided]' as any : undefined, baseline: web.baseline ? ({ ...web.baseline, scripts: [] }) : web.baseline } } : {}) };
  return assembleReport({ id: opts.id ?? randomUUID(), tool: { name: 'Lockguard', version: VERSION }, createdAt: new Date().toISOString(), targets: safeTargets, modules });
}
