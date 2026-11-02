import { useState } from 'react';
import { api, pollJob, type ScanRequest } from '../api';
import type { Job, Knowledge, Report, ModuleResult, Incident } from '../types';
import { Grade, SevCounts } from '../components/common';
import { FindingCard } from '../components/Finding';
import { KillChainMap } from '../components/KillChainMap';

const NETWORKS = ['mainnet', 'base', 'arbitrum', 'optimism', 'polygon', 'bsc', 'sepolia'];

export function Scan({ knowledge, labUrls, hosted = false }: { knowledge: Knowledge; labUrls: { vulnerable: string | null }; hosted?: boolean }) {
  const [useWeb, setUseWeb] = useState(true);
  const [useRepo, setUseRepo] = useState(false);
  const [useChain, setUseChain] = useState(false);
  const [url, setUrl] = useState('');
  const [signing, setSigning] = useState<'auto' | 'yes'>('auto');
  const [firstParty, setFirstParty] = useState('');
  const [useBaseline, setUseBaseline] = useState(false);
  const [storageState, setStorageState] = useState('');
  const [repoPath, setRepoPath] = useState('');
  const [addresses, setAddresses] = useState('');
  const [network, setNetwork] = useState('mainnet');
  const [rpc, setRpc] = useState('');
  const [knownDelegates, setKnownDelegates] = useState('');
  const [knownSpenders, setKnownSpenders] = useState('');
  const [policy, setPolicy] = useState('');

  const [job, setJob] = useState<Job | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState('');
  const [running, setRunning] = useState(false);
  const [savedBaseline, setSavedBaseline] = useState('');

  const incidents: Record<string, Incident> = Object.fromEntries(knowledge.incidents.map((i) => [i.id, i]));

  async function run() {
    setError(''); setReport(null); setRunning(true); setSavedBaseline('');
    const body: ScanRequest = {};
    if (useWeb && url.trim()) {
      body.web = { url: url.trim(), signingPage: signing === 'yes' ? true : 'auto', firstPartyDomains: splitList(firstParty), useSavedBaseline: useBaseline };
      if (storageState.trim()) { try { body.web.storageState = JSON.parse(storageState); } catch { setError('Storage state is not valid JSON.'); setRunning(false); return; } }
    }
    if (useRepo && repoPath.trim()) body.repo = { path: repoPath.trim() };
    if (useChain && (addresses.trim() || policy.trim())) body.chain = { addresses: splitList(addresses), network, rpcUrl: rpc.trim() || undefined, knownDelegates: splitList(knownDelegates), knownSpenders: splitList(knownSpenders), policy: policy.trim() || null };
    if (!body.web && !body.repo && !body.chain) { setError('Fill in at least one enabled target.'); setRunning(false); return; }
    try {
      const { id } = await api.startScan(body);
      const rep = await pollJob(id, setJob);
      setReport(rep);
    } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setRunning(false); }
  }

  async function saveBaseline() {
    if (!job) return;
    try { const r = await api.saveBaseline(job.id); setSavedBaseline(`Saved baseline for ${r.host}. Re-run with "compare to saved baseline" to catch drift.`); }
    catch (e) { setSavedBaseline('Could not save: ' + (e instanceof Error ? e.message : String(e))); }
  }

  return (
    <div>
      <div className="pagehead">
        <h1>Scan your own site, repo and wallets</h1>
        <p>Pick what to check. Everything runs on this machine and nothing is sent anywhere. Scan only assets you own.</p>
      </div>

      <div className="banner warn">Only scan targets you control. The web scan drives a real headless browser against the URL you give it.</div>
      {hosted && <div className="banner info">You are on the hosted Lockguard. The web and chain scanners work here (web targets must be public). Repo scanning and the lab run in the local app.</div>}

      <div className="card">
        <label className="check"><input type="checkbox" checked={useWeb} onChange={(e) => setUseWeb(e.target.checked)} /> <b>Web</b> — your site, for the Polymarket / Bybit vendor-script pattern</label>
        {useWeb && (
          <div style={{ marginTop: 12 }}>
            <div className="row">
              <div style={{ flex: 3 }}>
                <label>URL to scan</label>
                <input type="url" placeholder="https://app.yourdomain.com/trade" value={url} onChange={(e) => setUrl(e.target.value)} />
                {labUrls.vulnerable && <div className="hint">Try the lab: <button className="btn sm ghost" onClick={() => { setUrl(labUrls.vulnerable!); setSigning('yes'); }}>use the vulnerable lab build</button></div>}
              </div>
              <div style={{ flex: 1 }}>
                <label>Page type</label>
                <select value={signing} onChange={(e) => setSigning(e.target.value as 'auto' | 'yes')}>
                  <option value="auto">auto-detect</option>
                  <option value="yes">signing / trading page</option>
                </select>
              </div>
            </div>
            <div className="row" style={{ marginTop: 10 }}>
              <div><label>Extra first-party domains (optional)</label><input type="text" placeholder="cdn.yourdomain.com, assets.yourdomain.com" value={firstParty} onChange={(e) => setFirstParty(e.target.value)} /></div>
            </div>
            <label className="check" style={{ marginTop: 10 }}><input type="checkbox" checked={useBaseline} onChange={(e) => setUseBaseline(e.target.checked)} /> compare script hashes to the saved baseline (detects vendor swaps)</label>
            <details style={{ marginTop: 10 }}>
              <summary style={{ cursor: 'pointer', color: 'var(--muted)', fontSize: 13 }}>Scan as a logged-in user (optional storage state)</summary>
              <div style={{ marginTop: 8 }}>
                <label>Playwright storageState JSON from your own browser session</label>
                <textarea placeholder='{"cookies":[...],"origins":[...]}' value={storageState} onChange={(e) => setStorageState(e.target.value)} />
                <div className="hint">Export with <code>npx playwright codegen --save-storage=state.json your-site</code> after logging in. This reveals what the app stores after login (W4).</div>
              </div>
            </details>
          </div>
        )}
      </div>

      <div className="card">
        <label className="check" style={hosted ? { opacity: .55 } : undefined}><input type="checkbox" checked={useRepo && !hosted} disabled={hosted} onChange={(e) => setUseRepo(e.target.checked)} /> <b>Repo</b> — a local repository, for the TraderTraitor supply-chain entry point</label>
        {hosted && <div className="hint" style={{ marginTop: 8 }}>Repo scanning reads a local filesystem, so it runs in the local app: <code>npx lockguard scan --repo .</code></div>}
        {useRepo && !hosted && (
          <div style={{ marginTop: 12 }}>
            <label>Absolute path to the repository on this machine</label>
            <input type="text" placeholder="/home/you/code/your-exchange" value={repoPath} onChange={(e) => setRepoPath(e.target.value)} />
            <div className="hint">Checks install scripts, lockfiles, committed secrets, GitHub Actions pinning, OIDC vs static cloud keys, and dangerous workflows.</div>
          </div>
        )}
      </div>

      <div className="card">
        <label className="check"><input type="checkbox" checked={useChain} onChange={(e) => setUseChain(e.target.checked)} /> <b>Chain</b> — EVM addresses & signer policy, for the Binance signer-abuse pattern</label>
        {useChain && (
          <div style={{ marginTop: 12 }}>
            <div className="row">
              <div style={{ flex: 3 }}><label>Addresses (read-only, comma or newline separated)</label><input type="text" placeholder="0xabc..., 0xdef..." value={addresses} onChange={(e) => setAddresses(e.target.value)} /></div>
              <div style={{ flex: 1 }}><label>Network</label><select value={network} onChange={(e) => setNetwork(e.target.value)}>{NETWORKS.map((n) => <option key={n}>{n}</option>)}</select></div>
            </div>
            <div className="row" style={{ marginTop: 10 }}>
              <div><label>Custom RPC (optional, recommended)</label><input type="text" placeholder="https://..." value={rpc} onChange={(e) => setRpc(e.target.value)} /></div>
            </div>
            <div className="grid2" style={{ marginTop: 10 }}>
              <div><label>Delegates you approved (EIP-7702)</label><input type="text" placeholder="0x..." value={knownDelegates} onChange={(e) => setKnownDelegates(e.target.value)} /></div>
              <div><label>Spenders you approved</label><input type="text" placeholder="0x..." value={knownSpenders} onChange={(e) => setKnownSpenders(e.target.value)} /></div>
            </div>
            <div style={{ marginTop: 10 }}>
              <label>Signer policy to lint (optional, JSON or YAML)</label>
              <textarea placeholder="Paste a signer policy, or build one in the Harden tab." value={policy} onChange={(e) => setPolicy(e.target.value)} style={{ minHeight: 80 }} />
            </div>
            <div className="hint">Chain checks are read-only. A public RPC may rate-limit event scans; a dedicated RPC is more reliable.</div>
          </div>
        )}
      </div>

      <div style={{ display: 'flex', gap: 12, alignItems: 'center', margin: '4px 0 20px' }}>
        <button className="btn" onClick={run} disabled={running}>{running ? <><span className="spinner" /> &nbsp;Scanning…</> : 'Run scan'}</button>
        {running && job && <div style={{ flex: 1 }}><div className="progress"><div style={{ width: `${job.pct}%` }} /></div><div className="statline">{job.message}</div></div>}
      </div>

      {error && <div className="banner err">{error}</div>}

      {report && <Results report={report} incidents={incidents} jobId={job?.id} onSaveBaseline={saveBaseline} savedBaseline={savedBaseline} hasWeb={!!report.modules.find((m) => m.module === 'web')} />}
    </div>
  );
}

function Results({ report, incidents, jobId, onSaveBaseline, savedBaseline, hasWeb }: { report: Report; incidents: Record<string, Incident>; jobId?: string; onSaveBaseline: () => void; savedBaseline: string; hasWeb: boolean }) {
  const all = report.modules.flatMap((m) => m.findings);
  return (
    <div>
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 14 }}>
          <Grade grade={report.overall.grade} value={report.overall.value} />
          <SevCounts counts={report.overall.counts} />
          {jobId && (
            <div style={{ display: 'flex', gap: 8 }}>
              <a className="btn sm ghost" href={api.reportUrl(jobId, 'md')}>Markdown</a>
              <a className="btn sm ghost" href={api.reportUrl(jobId, 'json')}>JSON</a>
              <a className="btn sm ghost" href={api.reportUrl(jobId, 'sarif')}>SARIF</a>
            </div>
          )}
        </div>
        {hasWeb && jobId && (
          <div style={{ marginTop: 12, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
            <button className="btn sm ghost" onClick={onSaveBaseline}>Save current scripts as the approved baseline</button>
            {savedBaseline && <span className="hint" style={{ margin: 0 }}>{savedBaseline}</span>}
          </div>
        )}
      </div>

      <h3 style={{ margin: '24px 0 10px' }}>Kill-chain coverage</h3>
      <p style={{ color: 'var(--muted)', marginTop: 0 }}>Each attack as steps. A red dot means a finding leaves that step open.</p>
      <KillChainMap chains={report.killChains} />

      {report.modules.map((m) => <ModuleBlock key={m.module} m={m} incidents={incidents} />)}
    </div>
  );
}

function ModuleBlock({ m, incidents }: { m: ModuleResult; incidents: Record<string, Incident> }) {
  const label = m.module === 'web' ? 'Web' : m.module === 'repo' ? 'Repo' : 'Chain';
  return (
    <div style={{ marginTop: 24 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        <h3 style={{ margin: 0 }}>{label}</h3>
        <span className={`pill g-${m.score.grade}`} style={{ background: 'var(--card)' }}>{m.score.value}/100 ({m.score.grade})</span>
        <SevCounts counts={m.score.counts} />
      </div>
      <div className="hint" style={{ wordBreak: 'break-all' }}>{m.target}</div>
      {m.errors.length > 0 && <div className="banner err" style={{ marginTop: 10 }}>{m.errors.join(' · ')}</div>}
      {(m.meta as { sessionNote?: string; note?: string }).sessionNote && <div className="banner info" style={{ marginTop: 10 }}>{(m.meta as { sessionNote?: string }).sessionNote}</div>}
      <div style={{ marginTop: 12 }}>
        {m.findings.length === 0 && m.errors.length === 0 && <div className="banner ok">No findings in this module. {m.module === 'web' ? 'Save a baseline to catch the next vendor swap.' : ''}</div>}
        {m.findings.map((f) => <FindingCard key={f.key} f={f} incidents={incidents} />)}
      </div>
    </div>
  );
}

function splitList(s: string): string[] { return s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean); }
