import { useEffect, useState } from 'react';
import { api } from '../api';
import { Code } from '../components/common';

const REPO = 'https://github.com/Yathish27/Lockguard';
const GH = <svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor"><path d="M12 2C6.5 2 2 6.6 2 12.3c0 4.5 2.9 8.3 6.8 9.7.5.1.7-.2.7-.5v-1.7c-2.8.6-3.4-1.4-3.4-1.4-.5-1.2-1.1-1.5-1.1-1.5-.9-.6.1-.6.1-.6 1 .1 1.5 1 1.5 1 .9 1.6 2.4 1.1 3 .9.1-.7.3-1.1.6-1.4-2.2-.3-4.6-1.1-4.6-5 0-1.1.4-2 1-2.7-.1-.3-.4-1.3.1-2.7 0 0 .8-.3 2.7 1a9.3 9.3 0 0 1 5 0c1.9-1.3 2.7-1 2.7-1 .5 1.4.2 2.4.1 2.7.6.7 1 1.6 1 2.7 0 3.9-2.3 4.7-4.6 5 .4.3.7.9.7 1.9v2.8c0 .3.2.6.7.5 3.9-1.4 6.8-5.2 6.8-9.7C22 6.6 17.5 2 12 2z"/></svg>;

export function Lab({ onLabReady, mode = 'local' }: { onLabReady: (u: { vulnerable: string; hardened: string }) => void; mode?: 'local' | 'hosted' | 'static' }) {
  const [status, setStatus] = useState<{ running: boolean; vulnerable: string | null; hardened: string | null; vendor: string | null } | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const local = mode === 'local';

  useEffect(() => { if (local) api.labStatus().then(setStatus).catch(() => {}); }, [local]);

  async function start() {
    setBusy(true); setErr('');
    try { const r = await api.labStart(); setStatus({ ...r }); onLabReady({ vulnerable: r.vulnerable, hardened: r.hardened }); }
    catch (e) { setErr(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(false); }
  }

  return (
    <div>
      <div className="pagehead">
        <h1>Lab: watch the attack happen</h1>
        <p>A tiny exchange that runs entirely on your machine, in two builds. Flip the pretend vendor CDN to "compromised" and watch a third-party script drain the vulnerable build. The hardened build stops it. No real funds, no real keys, no real drainer code.</p>
      </div>

      {local ? (
        <div className="card">
          {!status?.running ? (
            <>
              <h3>Start the lab</h3>
              <p className="sub">Launches three local servers: a vulnerable build, a hardened build, and a "vendor CDN" you can compromise.</p>
              <button className="btn" onClick={start} disabled={busy}>{busy ? <><span className="spinner" /> &nbsp;Starting…</> : 'Start the lab'}</button>
              {err && <div className="banner err" style={{ marginTop: 12 }}>{err}</div>}
            </>
          ) : (
            <>
              <div className="banner ok">Lab is running. Open both builds and compare.</div>
              <div className="grid2">
                <div className="card" style={{ background: 'var(--critbg)', borderColor: '#5a2027' }}>
                  <h3 style={{ color: 'var(--crit)' }}>Vulnerable build</h3>
                  <p className="sub">Session token + API key in localStorage, a cross-origin vendor script with no SRI, no CSP.</p>
                  <a className="btn" href={status.vulnerable!} target="_blank" rel="noreferrer">Open vulnerable build →</a>
                </div>
                <div className="card" style={{ background: 'var(--card2)', borderColor: '#1c4a35' }}>
                  <h3 style={{ color: 'var(--accent)' }}>Hardened build</h3>
                  <p className="sub">HttpOnly session cookie, strict nonce CSP, real SRI on the vendor script, step-up for withdrawals.</p>
                  <a className="btn ghost" href={status.hardened!} target="_blank" rel="noreferrer">Open hardened build →</a>
                </div>
              </div>
              <p className="hint">Vendor CDN: <code>{status.vendor}</code>. You can scan the vulnerable build from the Scan tab to see the findings that explain all this.</p>
            </>
          )}
        </div>
      ) : (
        <div className="card" style={{ borderColor: '#1c4a35' }}>
          <h3>Run the lab on your machine</h3>
          <p className="sub">The lab starts three small local servers, so it runs on your own computer, not on this hosted page. It's open source — clone it and start it in about a minute. Nothing leaves your machine.</p>
          <ol className="steps" style={{ marginBottom: 6 }}>
            <li><b>Clone the repository</b> and install:</li>
          </ol>
          <Code lang="bash" title="1 · get the code" code={`git clone ${REPO}\ncd Lockguard\nnpm ci`} />
          <ol className="steps" start={2} style={{ margin: '10px 0 6px' }}>
            <li><b>Start the full app</b>, then open the Lab tab and click “Start the lab”:</li>
          </ol>
          <Code lang="bash" title="2 · run the app" code={`npm run build\nnpm start            # opens http://localhost:4477 → Lab tab → Start the lab`} />
          <ol className="steps" start={3} style={{ margin: '10px 0 6px' }}>
            <li>Or start <b>just the lab</b> on its own — it prints the three URLs to open:</li>
          </ol>
          <Code lang="bash" title="just the lab" code={`npm run lab
#   vulnerable build : http://127.0.0.1:4478
#   hardened build   : http://127.0.0.1:4479
#   vendor CDN       : http://127.0.0.1:4480`} />
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginTop: 14 }}>
            <a className="btn" href={REPO} target="_blank" rel="noreferrer">{GH} &nbsp;Get it on GitHub</a>
          </div>
          <p className="hint" style={{ marginTop: 10 }}>Windows note: if <code>npm run build</code> hits a rollup error, use <code>npm ci</code> on a clean checkout (see the README); the lab itself needs no browser install.</p>
        </div>
      )}

      <div className="card">
        <h3>How the attack plays out</h3>
        <ol className="steps">
          <li>Open the <b>vulnerable</b> build and click <b>Log in</b>. It stores a session token and a trading API key in <code>localStorage</code>, the way the Polymarket front-end kept trading keys in the browser.</li>
          <li>Click <b>Serve malicious analytics.js</b>. This flips the pretend vendor CDN to serve a swapped script, the way DebugBear's script was swapped on 29 October 2026.</li>
          <li>Reload the page. The swapped script reads the token out of <code>localStorage</code>, calls the exchange's own withdraw API as you, and rewrites the screen. The balance goes to the attacker.</li>
          <li>Now do the same on the <b>hardened</b> build. The session is an HttpOnly cookie the script cannot read, the browser refuses the swapped script because its hash no longer matches the pinned SRI value, and withdrawals need a step-up token. The attack fails at three layers.</li>
        </ol>
      </div>

      <div className="banner info">Everything here is a self-contained simulation against its own in-memory balance. It contains no real exploit code and cannot touch anything outside the lab.</div>
    </div>
  );
}
