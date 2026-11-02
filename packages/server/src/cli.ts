#!/usr/bin/env node
import { createApp } from './server.js';
import { startScan, getJob } from './jobs.js';
import { toMarkdown, toSarif, type ScanTargets, type Report, type Severity } from '@lockguard/core';
import { writeFileSync, readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';

const RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function parseArgs(argv: string[]): Record<string, string | boolean | string[]> {
  const out: Record<string, string | boolean | string[]> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) out[key] = true;
      else { if (out[key]) out[key] = ([] as string[]).concat(out[key] as string | string[], next); else out[key] = next; i++; }
    }
  }
  return out;
}

const HELP = `Lockguard — see the weaknesses behind the Polymarket, Binance and Bybit attacks in your own site, repo and wallets.

Usage:
  lockguard ui [--port 4477] [--host 127.0.0.1] [--no-open]     Launch the UI (default command)
  lockguard scan [targets] [options]                             Run a scan from the terminal

Scan targets (any combination):
  --web <url>                 Scan a site you own (headless browser)
  --repo <path>               Scan a local repository
  --chain <addr>[,<addr>]     Scan EVM address(es); repeatable
  --policy <file>             Lint a signer policy (JSON/YAML)

Options:
  --network <id>              mainnet|base|arbitrum|optimism|polygon|bsc|sepolia (default mainnet)
  --rpc <url>                 Custom RPC endpoint
  --signing-page              Force signing-page severity escalation on the web scan
  --storage-state <file>      Playwright storage state (your own logged-in session) for the web scan
  --first-party <domain>      Extra domain you own (repeatable)
  --known-delegate <addr>     Approved EIP-7702 delegate (repeatable)
  --known-spender <addr>      Approved token spender (repeatable)
  --baseline <file>           Compare web scripts to a saved baseline
  --out <file>                Write JSON report
  --md <file>                 Write Markdown report
  --sarif <file>              Write SARIF (for GitHub code scanning)
  --fail-on <severity>        Exit non-zero if a finding at/above this severity exists (critical|high|medium|low)

Examples:
  lockguard ui
  lockguard scan --repo .
  lockguard scan --web https://app.example.com/trade --signing-page
  lockguard scan --chain 0xabc... --network mainnet
  lockguard scan --repo . --web https://example.com --fail-on high --sarif out.sarif
`;

function readFileArg(path: string): string {
  return readFileSync(path, 'utf8');
}

async function waitForJob(id: string): Promise<Report> {
  let lastPct = -1;
  for (;;) {
    const job = getJob(id)!;
    if (job.pct !== lastPct || job.status !== 'running') { lastPct = job.pct; process.stderr.write(`\r  ${String(job.pct).padStart(3)}%  ${job.message.slice(0, 80).padEnd(80)}`); }
    if (job.status === 'done') { process.stderr.write('\n'); return job.report!; }
    if (job.status === 'error') { process.stderr.write('\n'); throw new Error(job.error); }
    await new Promise((r) => setTimeout(r, 150));
  }
}

async function runUi(args: Record<string, string | boolean | string[]>) {
  const port = Number(args.port ?? process.env.PORT ?? 4477);
  const host = String(args.host ?? '127.0.0.1');
  const app = createApp();
  const server = createServer(app);
  await new Promise<void>((resolve, reject) => { server.on('error', reject); server.listen(port, host, resolve); });
  const url = `http://${host === '0.0.0.0' ? 'localhost' : host}:${port}`;
  console.log(`\n  Lockguard is running at ${url}\n`);
  console.log('  Scan only assets you own. Everything stays on this machine; there is no telemetry.\n');
  if (!args['no-open'] && process.env.LOCKGUARD_NO_OPEN !== '1') openBrowser(url);
}

function openBrowser(url: string) {
  const cmd = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'cmd' : 'xdg-open';
  const a = process.platform === 'win32' ? ['/c', 'start', '', url] : [url];
  try { spawn(cmd, a, { stdio: 'ignore', detached: true }).unref(); } catch { /* ignore */ }
}

async function runScanCli(args: Record<string, string | boolean | string[]>) {
  const targets: ScanTargets = {};
  if (args.web) targets.web = {
    url: String(args.web),
    signingPage: args['signing-page'] ? true : 'auto',
    firstPartyDomains: ([] as string[]).concat((args['first-party'] as string | string[]) ?? []),
    storageState: args['storage-state'] ? JSON.parse(readFileArg(String(args['storage-state']))) : undefined,
    baseline: args.baseline ? JSON.parse(readFileArg(String(args.baseline))) : null
  };
  if (args.repo) targets.repo = { path: String(args.repo) };
  const addrs = ([] as string[]).concat((args.chain as string | string[]) ?? []).flatMap((s) => String(s).split(','));
  if (addrs.length || args.policy) targets.chain = {
    addresses: addrs,
    network: (args.network ?? 'mainnet') as ScanTargets['chain'] extends infer C ? C extends { network: infer N } ? N : never : never,
    rpcUrl: args.rpc ? String(args.rpc) : undefined,
    knownDelegates: ([] as string[]).concat((args['known-delegate'] as string | string[]) ?? []),
    knownSpenders: ([] as string[]).concat((args['known-spender'] as string | string[]) ?? []),
    policy: args.policy ? readFileArg(String(args.policy)) : null
  };
  if (!targets.web && !targets.repo && !targets.chain) { console.error('Nothing to scan. See --help.'); process.exit(2); }

  const job = startScan(targets);
  const report = await waitForJob(job.id);

  for (const m of report.modules) {
    console.log(`\n  ${m.module.toUpperCase()}  ${m.target}`);
    console.log(`  score ${m.score.value}/100 (${m.score.grade})  —  ${sevLine(m.score.counts)}`);
    for (const f of m.findings) console.log(`    ${badge(f.severity)} ${f.id}  ${f.summary}`);
    for (const e of m.errors) console.log(`    ! ${e}`);
  }
  console.log(`\n  OVERALL  ${report.overall.value}/100 (${report.overall.grade})\n`);

  if (args.out) { writeFileSync(String(args.out), JSON.stringify(report, null, 2)); console.log(`  wrote ${args.out}`); }
  if (args.md) { writeFileSync(String(args.md), toMarkdown(report)); console.log(`  wrote ${args.md}`); }
  if (args.sarif) { const root = (report.modules.find((m) => m.module === 'repo')?.meta as { root?: string } | undefined)?.root; writeFileSync(String(args.sarif), JSON.stringify(toSarif(report, root), null, 2)); console.log(`  wrote ${args.sarif}`); }

  if (args['fail-on']) {
    const threshold = RANK[String(args['fail-on']) as Severity] ?? 3;
    const worst = report.modules.flatMap((m) => m.findings).reduce((w, f) => Math.max(w, RANK[f.severity]), 0);
    if (worst >= threshold) { console.error(`  fail-on ${String(args['fail-on'])}: findings at or above threshold.`); process.exit(1); }
  }
}

function badge(s: Severity): string { return { critical: 'CRIT', high: 'HIGH', medium: 'MED ', low: 'LOW ', info: 'INFO' }[s]; }
function sevLine(c: Record<Severity, number>): string { return `${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low, ${c.info} info`; }

async function main() {
  const [, , cmdRaw, ...rest] = process.argv;
  const cmd = cmdRaw && !cmdRaw.startsWith('--') ? cmdRaw : 'ui';
  const args = parseArgs(cmdRaw && cmdRaw.startsWith('--') ? [cmdRaw, ...rest] : rest);
  if (args.help || cmd === 'help') { console.log(HELP); return; }
  if (cmd === 'ui' || cmd === 'serve') return runUi(args);
  if (cmd === 'scan') return runScanCli(args);
  console.error(`Unknown command "${cmd}".\n`); console.log(HELP); process.exit(2);
}
main().catch((e) => { console.error('\n' + (e?.stack ?? e?.message ?? String(e))); process.exit(1); });
