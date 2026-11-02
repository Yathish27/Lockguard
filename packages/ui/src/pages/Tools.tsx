import { useEffect, useState } from 'react';
import { api } from '../api';
import type { Finding, Knowledge, Incident } from '../types';
import { Code, SevPill } from '../components/common';
import { FindingCard } from '../components/Finding';

type Tool = 'csp' | 'sri' | 'actions' | 'policy' | 'revoke';
const TOOLS: { id: Tool; label: string; desc: string }[] = [
  { id: 'csp', label: 'CSP builder', desc: 'Generate a strict, nonce-based Content Security Policy' },
  { id: 'sri', label: 'SRI generator', desc: 'Hash a script you load and get a ready script tag' },
  { id: 'actions', label: 'Pin GitHub Actions', desc: 'Rewrite uses: tags to commit SHAs' },
  { id: 'policy', label: 'Signer policy linter', desc: 'Find the gaps the Binance attack walked through' },
  { id: 'revoke', label: 'Approval revoke calldata', desc: 'Build the transaction to drop an approval' }
];

export function Tools({ knowledge }: { knowledge: Knowledge }) {
  const [tool, setTool] = useState<Tool>('csp');
  return (
    <div>
      <div className="pagehead">
        <h1>Harden</h1>
        <p>Hands-on tools that turn each finding into a fix. Everything runs locally.</p>
      </div>
      <div className="tabs">
        {TOOLS.map((t) => <button key={t.id} className={tool === t.id ? 'active' : ''} onClick={() => setTool(t.id)}>{t.label}</button>)}
      </div>
      {tool === 'csp' && <CspBuilder />}
      {tool === 'sri' && <SriTool />}
      {tool === 'actions' && <ActionsTool />}
      {tool === 'policy' && <PolicyTool knowledge={knowledge} />}
      {tool === 'revoke' && <RevokeTool />}
    </div>
  );
}

function CspBuilder() {
  const [api1, setApi] = useState('https://api.yourdomain.example');
  const [frame, setFrame] = useState('none');
  const [tt, setTt] = useState(true);
  const [report, setReport] = useState('https://yourdomain.example/csp-report');
  const connect = ["'self'", api1.trim()].filter(Boolean).join(' ');
  const directives = [
    "default-src 'self'",
    "script-src 'nonce-{SERVER_GENERATED_NONCE}' 'strict-dynamic'",
    "style-src 'self'",
    "img-src 'self' data:",
    `connect-src ${connect}`,
    "object-src 'none'",
    "base-uri 'none'",
    `frame-ancestors ${frame === 'none' ? "'none'" : "'self'"}`,
    "form-action 'self'",
    ...(tt ? ["require-trusted-types-for 'script'"] : []),
    ...(report ? ['report-to csp-endpoint'] : [])
  ];
  const policy = directives.join('; ');
  const express = `import crypto from 'node:crypto';
app.use((req, res, next) => {
  const nonce = crypto.randomBytes(16).toString('base64');
  res.locals.cspNonce = nonce;
  res.setHeader('Content-Security-Policy', [
${directives.map((d) => `    "${d.replace('{SERVER_GENERATED_NONCE}', "' + nonce + '")}"`).join(',\n').replace(/"'self'"/g, '"\'self\'"')}
  ].join('; '));
${report ? `  res.setHeader('Reporting-Endpoints', 'csp-endpoint="${report}"');\n` : ''}  next();
});
// then render: <script nonce="\${res.locals.cspNonce}" src="/app.js"></script>`;
  return (
    <div className="card">
      <h3>Strict CSP builder</h3>
      <p className="sub">A nonce-based policy with <code>strict-dynamic</code>. This is the control that stops a swapped vendor script from running and from exfiltrating data.</p>
      <div className="grid2">
        <div><label>Your API origin (connect-src)</label><input type="text" value={api1} onChange={(e) => setApi(e.target.value)} /></div>
        <div><label>Reporting endpoint</label><input type="text" value={report} onChange={(e) => setReport(e.target.value)} /></div>
      </div>
      <div className="row" style={{ marginTop: 10 }}>
        <label className="check"><input type="checkbox" checked={tt} onChange={(e) => setTt(e.target.checked)} /> require Trusted Types</label>
        <label className="check"><input type="radio" name="fr" checked={frame === 'none'} onChange={() => setFrame('none')} /> frame-ancestors none</label>
        <label className="check"><input type="radio" name="fr" checked={frame === 'self'} onChange={() => setFrame('self')} /> allow same-origin framing</label>
      </div>
      <h4 style={{ color: 'var(--muted2)', fontSize: 12, textTransform: 'uppercase', marginTop: 16 }}>Policy</h4>
      <Code code={policy} lang="text" title="Content-Security-Policy" />
      <Code code={express} lang="ts" title="Express middleware (fresh nonce per response)" />
      <div className="banner info">Roll this out in <code>Content-Security-Policy-Report-Only</code> first, fix what it reports, then enforce. Alert on a spike of violation reports: that is your earliest signal of a swapped script.</div>
    </div>
  );
}

function SriTool() {
  const [url, setUrl] = useState('');
  const [res, setRes] = useState<Awaited<ReturnType<typeof api.sri>> | null>(null);
  const [err, setErr] = useState(''); const [busy, setBusy] = useState(false);
  async function go() { setErr(''); setRes(null); setBusy(true); try { setRes(await api.sri(url.trim())); } catch (e) { setErr(e instanceof Error ? e.message : String(e)); } finally { setBusy(false); } }
  return (
    <div className="card">
      <h3>Subresource Integrity generator</h3>
      <p className="sub">Hash a script exactly as it is served and get a ready-to-paste tag. The browser will refuse any future version whose bytes differ.</p>
      <div style={{ display: 'flex', gap: 10 }}>
        <input type="url" placeholder="https://cdn.vendor.example/widget/4.2.1/widget.min.js" value={url} onChange={(e) => setUrl(e.target.value)} />
        <button className="btn" onClick={go} disabled={busy || !url.trim()}>{busy ? <span className="spinner" /> : 'Hash it'}</button>
      </div>
      {err && <div className="banner err" style={{ marginTop: 12 }}>{err}</div>}
      {res && (
        <div style={{ marginTop: 14 }}>
          <div className="kv" style={{ marginBottom: 10 }}>
            <span className="k">size</span><span className="v">{res.bytes} bytes</span>
            <span className="k">type</span><span className="v">{res.contentType || '—'}</span>
            <span className="k">CORS header</span><span className="v">{res.corsHeader || '— (SRI needs CORS for cross-origin; self-host instead)'}</span>
          </div>
          <Code code={res.tag} lang="html" title="Paste this tag" />
          <Code code={`sha256: ${res.sha256}\nsha384: ${res.sha384}\nsha512: ${res.sha512}`} lang="text" title="Hashes" />
          {res.warnings.map((w, i) => <div key={i} className="banner warn">{w}</div>)}
        </div>
      )}
    </div>
  );
}

function ActionsTool() {
  const [yaml, setYaml] = useState('');
  const [token, setToken] = useState('');
  const [res, setRes] = useState<Awaited<ReturnType<typeof api.pinActions>> | null>(null);
  const [err, setErr] = useState(''); const [busy, setBusy] = useState(false);
  async function go() { setErr(''); setRes(null); setBusy(true); try { setRes(await api.pinActions(yaml, token.trim() || undefined)); } catch (e) { setErr(e instanceof Error ? e.message : String(e)); } finally { setBusy(false); } }
  return (
    <div className="card">
      <h3>Pin GitHub Actions to commit SHAs</h3>
      <p className="sub">Paste a workflow. Lockguard resolves each <code>uses: owner/repo@tag</code> to the tag's commit SHA, which a maintainer (or an attacker with their token) cannot move.</p>
      <label>Workflow YAML</label>
      <textarea value={yaml} onChange={(e) => setYaml(e.target.value)} placeholder={'name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4'} style={{ minHeight: 160 }} />
      <details style={{ margin: '8px 0' }}><summary style={{ cursor: 'pointer', color: 'var(--muted)', fontSize: 13 }}>GitHub token (optional, avoids API rate limits)</summary><input type="text" placeholder="ghp_… (read-only; used only for api.github.com lookups)" value={token} onChange={(e) => setToken(e.target.value)} style={{ marginTop: 8 }} /></details>
      <button className="btn" onClick={go} disabled={busy || !yaml.trim()}>{busy ? <span className="spinner" /> : 'Pin actions'}</button>
      {err && <div className="banner err" style={{ marginTop: 12 }}>{err}</div>}
      {res && (
        <div style={{ marginTop: 14 }}>
          <p className="sub">{res.changes.filter((c) => !c.error).length} pinned, {res.changes.filter((c) => c.error).length} failed.</p>
          {res.changes.map((c, i) => (
            <div key={i} className="evid">
              <div className="loc">line {c.line}</div>
              {c.error ? <div style={{ color: 'var(--high)' }}>could not resolve: {c.error}</div> : <div><span style={{ color: 'var(--muted)' }}>{c.from.trim()}</span><br /><span style={{ color: 'var(--accent)' }}>→ {c.to.trim()}</span></div>}
            </div>
          ))}
          <Code code={res.yaml} lang="yaml" title="Pinned workflow" />
        </div>
      )}
    </div>
  );
}

function PolicyTool({ knowledge }: { knowledge: Knowledge }) {
  const [policy, setPolicy] = useState('');
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [err, setErr] = useState(''); const [busy, setBusy] = useState(false);
  const incidents: Record<string, Incident> = Object.fromEntries(knowledge.incidents.map((i) => [i.id, i]));
  async function loadTemplate() { setPolicy(await api.policyTemplate()); }
  async function go() { setErr(''); setFindings(null); setBusy(true); try { const r = await api.policyLint(policy); setFindings(r.findings); } catch (e) { setErr(e instanceof Error ? e.message : String(e)); } finally { setBusy(false); } }
  useEffect(() => { if (!policy) loadTemplate(); }, []); // eslint-disable-line
  return (
    <div className="card">
      <h3>Signer policy linter</h3>
      <p className="sub">Describe what each signing key is allowed to sign. The linter finds the gaps the Binance attack walked through: type-4 delegations allowed, no destination allowlist, no velocity caps, single-person policy changes.</p>
      <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}><button className="btn sm ghost" onClick={loadTemplate}>Load template</button></div>
      <textarea value={policy} onChange={(e) => setPolicy(e.target.value)} style={{ minHeight: 220 }} />
      <button className="btn" onClick={go} disabled={busy || !policy.trim()} style={{ marginTop: 8 }}>{busy ? <span className="spinner" /> : 'Lint policy'}</button>
      {err && <div className="banner err" style={{ marginTop: 12 }}>{err}</div>}
      {findings && (
        <div style={{ marginTop: 14 }}>
          {findings.length === 0 ? <div className="banner ok">No gaps found. This policy closes every check Lockguard knows about.</div> :
            <>
              <p className="sub">{findings.length} gap(s). Fix the critical and high ones first.</p>
              {findings.map((f) => <FindingCard key={f.key} f={f} incidents={incidents} />)}
            </>}
        </div>
      )}
    </div>
  );
}

function RevokeTool() {
  const [token, setToken] = useState('');
  const [spender, setSpender] = useState('');
  const [res, setRes] = useState<Awaited<ReturnType<typeof api.revokeCalldata>> | null>(null);
  const [err, setErr] = useState('');
  async function go() { setErr(''); setRes(null); try { setRes(await api.revokeCalldata(token.trim(), spender.trim())); } catch (e) { setErr(e instanceof Error ? e.message : String(e)); } }
  return (
    <div className="card">
      <h3>Approval revoke calldata</h3>
      <p className="sub">Build the exact transaction data to drop an approval. Send it from your own wallet or hardware signer.</p>
      <div className="grid2">
        <div><label>Token / collection address</label><input type="text" placeholder="0x… (ERC-20 token or NFT collection)" value={token} onChange={(e) => setToken(e.target.value)} /></div>
        <div><label>Spender / operator to revoke</label><input type="text" placeholder="0x…" value={spender} onChange={(e) => setSpender(e.target.value)} /></div>
      </div>
      <button className="btn" onClick={go} disabled={!spender.trim()} style={{ marginTop: 10 }}>Build calldata</button>
      {err && <div className="banner err" style={{ marginTop: 12 }}>{err}</div>}
      {res && (
        <div style={{ marginTop: 14 }}>
          <Code code={`// ERC-20: approve(spender, 0)\nto:   ${token || '<token address>'}\ndata: ${res.erc20.data}`} lang="text" title="Revoke an ERC-20 allowance" />
          <Code code={`// ERC-721/1155: setApprovalForAll(operator, false)\nto:   ${token || '<collection address>'}\ndata: ${res.erc721.data}`} lang="text" title="Revoke an NFT operator" />
          <Code code={`cast send ${token || '<token>'} "approve(address,uint256)" ${spender || '<spender>'} 0 --rpc-url $RPC --ledger`} lang="bash" title="Or with Foundry cast + a hardware wallet" />
        </div>
      )}
    </div>
  );
}
