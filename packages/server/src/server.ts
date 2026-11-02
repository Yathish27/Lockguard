import express, { type Request, type Response } from 'express';
import { readFileSync, existsSync, statSync } from 'node:fs';
import { join, dirname, resolve as pathResolve, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  computeSri, pinActions, lintSignerPolicy, SIGNER_POLICY_TEMPLATE, toMarkdown, toSarif,
  INCIDENT_LIST, KILL_CHAINS, RULE_LIST, VERSION, approveZeroCalldata, setApprovalForAllFalseCalldata,
  buildBaseline, scanWeb, type ScanTargets, type Report, isAddressLike
} from '@lockguard/core';
import { startScan, getJob } from './jobs.js';
import { labRouter } from './lab-control.js';
import { saveBaseline, loadBaseline, listBaselines } from './store.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const UI_DIR = [join(__dirname, '..', 'ui-dist'), join(__dirname, '..', '..', 'ui', 'dist')].find((p) => existsSync(join(p, 'index.html')));

export interface ServerOptions { port?: number; host?: string; allowRemote?: boolean }

export function createApp() {
  const HOSTED = process.env.LOCKGUARD_HOSTED === '1' || process.env.LOCKGUARD_HOSTED === 'true';
  const app = express();
  app.use(express.json({ limit: '8mb' }));
  app.disable('x-powered-by');
  // This tool runs locally; keep its own UI strictly same-origin.
  app.use((_req, res, next) => {
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    next();
  });

  const api = express.Router();
  api.get('/health', (_req, res) => res.json({ ok: true, version: VERSION }));
  api.get('/config', (_req, res) => res.json({ hosted: HOSTED, version: VERSION, modules: { web: true, repo: !HOSTED, chain: true }, lab: !HOSTED }));
  api.get('/knowledge', (_req, res) => res.json({ incidents: INCIDENT_LIST, killChains: KILL_CHAINS, rules: RULE_LIST, version: VERSION }));
  api.get('/policy/template', (_req, res) => res.type('text/yaml').send(SIGNER_POLICY_TEMPLATE));

  api.post('/scan', (req: Request, res: Response) => {
    try {
      const body = req.body ?? {};
      const targets: ScanTargets = {};
      if (body.repo?.path && HOSTED) return res.status(403).json({ error: 'Repository scanning reads a local filesystem, so it runs only in the local app. Install Lockguard and run `npx lockguard scan --repo .`.' });
      if (body.web?.url) {
        let baseline = body.web.baseline ?? null;
        if (body.web.useSavedBaseline && !baseline) baseline = loadBaseline(hostOf(body.web.url));
        targets.web = {
          url: String(body.web.url),
          signingPage: body.web.signingPage ?? 'auto',
          firstPartyDomains: arr(body.web.firstPartyDomains),
          storageState: body.web.storageState ?? undefined,
          baseline,
          settleMs: clampNum(body.web.settleMs, 0, 15000),
          timeoutMs: clampNum(body.web.timeoutMs, 5000, 120000),
          ignoreHTTPSErrors: HOSTED ? false : !!body.web.ignoreHTTPSErrors,
          blockPrivateHosts: HOSTED
        };
      }
      if (body.repo?.path && !HOSTED) targets.repo = { path: String(body.repo.path) };
      if (body.chain?.addresses?.length || body.chain?.policy) {
        targets.chain = {
          addresses: arr(body.chain.addresses),
          network: body.chain.network ?? 'mainnet',
          rpcUrl: body.chain.rpcUrl || undefined,
          lookbackBlocks: clampNum(body.chain.lookbackBlocks, 1000, 5_000_000),
          knownDelegates: arr(body.chain.knownDelegates),
          knownSpenders: arr(body.chain.knownSpenders),
          policy: body.chain.policy ?? null
        };
      }
      if (!targets.web && !targets.repo && !targets.chain) return res.status(400).json({ error: 'Nothing to scan. Provide at least one of web.url, repo.path, chain.addresses/policy.' });
      const job = startScan(targets);
      res.json({ id: job.id });
    } catch (e: any) {
      res.status(400).json({ error: e?.message ?? String(e) });
    }
  });

  api.get('/scan/:id', (req, res) => {
    const job = getJob(req.params.id);
    if (!job) return res.status(404).json({ error: 'unknown job' });
    const { report, ...rest } = job;
    res.json({ ...rest, report: job.status === 'done' ? report : undefined });
  });
  api.get('/scan/:id/stream', (req, res) => {
    const job = getJob(req.params.id);
    if (!job) return res.status(404).end();
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
    let last = -1;
    const tick = () => {
      if (job.log.length !== last || job.status !== 'running') {
        last = job.log.length;
        res.write(`data: ${JSON.stringify({ status: job.status, pct: job.pct, message: job.message })}\n\n`);
      }
      if (job.status !== 'running') { res.write(`event: done\ndata: ${JSON.stringify({ status: job.status })}\n\n`); clearInterval(iv); res.end(); }
    };
    const iv = setInterval(tick, 250);
    tick();
    req.on('close', () => clearInterval(iv));
  });

  api.get('/scan/:id/report.:fmt', (req, res) => {
    const job = getJob(req.params.id);
    if (!job?.report) return res.status(404).json({ error: 'no report' });
    const fmt = req.params.fmt;
    if (fmt === 'md') return res.type('text/markdown').attachment(`lockguard-${job.id}.md`).send(toMarkdown(job.report));
    if (fmt === 'sarif') return res.type('application/json').attachment(`lockguard-${job.id}.sarif`).send(JSON.stringify(toSarif(job.report, repoRootOf(job.report)), null, 2));
    return res.type('application/json').attachment(`lockguard-${job.id}.json`).send(JSON.stringify(job.report, null, 2));
  });

  // ---- hardening tools
  api.post('/tools/sri', async (req, res) => {
    try { res.json(await computeSri(String(req.body?.url ?? ''))); }
    catch (e: any) { res.status(400).json({ error: e?.message ?? String(e) }); }
  });
  api.post('/tools/pin-actions', async (req, res) => {
    try {
      const yaml = String(req.body?.yaml ?? '');
      if (!yaml.trim()) return res.status(400).json({ error: 'Provide workflow YAML in "yaml".' });
      res.json(await pinActions(yaml, { token: req.body?.token }));
    } catch (e: any) { res.status(400).json({ error: e?.message ?? String(e) }); }
  });
  api.post('/tools/policy-lint', (req, res) => {
    try { const findings = lintSignerPolicy(req.body?.policy ?? ''); res.json({ findings }); }
    catch (e: any) { res.status(400).json({ error: e?.message ?? String(e) }); }
  });
  api.post('/tools/revoke-calldata', (req, res) => {
    try {
      const spender = String(req.body?.spender ?? '');
      if (!isAddressLike(spender)) return res.status(400).json({ error: 'spender must be a 0x address' });
      res.json({ erc20: { to: req.body?.token ?? null, data: approveZeroCalldata(spender as `0x${string}`) }, erc721: { data: setApprovalForAllFalseCalldata(spender as `0x${string}`) } });
    } catch (e: any) { res.status(400).json({ error: e?.message ?? String(e) }); }
  });

  // ---- baselines
  api.get('/baselines', (_req, res) => res.json({ baselines: listBaselines() }));
  api.get('/baselines/:host', (req, res) => { const b = loadBaseline(req.params.host); if (!b) return res.status(404).json({ error: 'not found' }); res.json(b); });
  api.post('/baselines/save', (req, res) => {
    try {
      const jobId = req.body?.jobId; const url = req.body?.url;
      let baseline = req.body?.baseline;
      if (!baseline && jobId) { const job = getJob(jobId); const b = (job?.report?.modules.find((m) => m.module === 'web')?.meta as any)?.baselineCandidate; if (b) baseline = b; }
      if (!baseline && url) return res.status(400).json({ error: 'Provide a baseline object or a finished web jobId.' });
      if (!baseline) return res.status(400).json({ error: 'No baseline to save.' });
      const file = saveBaseline(baseline);
      res.json({ ok: true, file, host: baseline.host });
    } catch (e: any) { res.status(400).json({ error: e?.message ?? String(e) }); }
  });

  if (!HOSTED) api.use('/lab', labRouter());
  else api.use('/lab', (_req, res) => res.status(403).json({ error: 'The lab spins up local servers, so it runs only in the local app. Clone Lockguard and run it locally to use the lab.' }));

  app.use('/api', api);

  if (UI_DIR) {
    app.use(express.static(UI_DIR, { index: false, maxAge: '1h' }));
    app.get(/.*/, (_req, res) => res.sendFile(join(UI_DIR, 'index.html')));
  } else {
    app.get('/', (_req, res) => res.type('html').send('<h1>Lockguard API</h1><p>UI not built. Run <code>npm run build</code>, or use the dev server at :5173.</p>'));
  }
  return app;
}

function arr(v: unknown): string[] { return Array.isArray(v) ? v.map(String).map((s) => s.trim()).filter(Boolean) : typeof v === 'string' ? v.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean) : []; }
function clampNum(v: unknown, lo: number, hi: number): number | undefined { const n = Number(v); return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : undefined; }
function hostOf(u: string): string { try { return new URL(u).hostname; } catch { return u; } }
function repoRootOf(r: Report): string | undefined { return (r.modules.find((m) => m.module === 'repo')?.meta as any)?.root; }
