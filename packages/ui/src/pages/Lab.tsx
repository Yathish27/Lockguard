import { useEffect, useState } from 'react';
import { api } from '../api';

export function Lab({ onLabReady }: { onLabReady: (u: { vulnerable: string; hardened: string }) => void }) {
  const [status, setStatus] = useState<{ running: boolean; vulnerable: string | null; hardened: string | null; vendor: string | null } | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  useEffect(() => { api.labStatus().then(setStatus).catch(() => {}); }, []);

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

      <div className="card">
        <h3>How to run the attack</h3>
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
