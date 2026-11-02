import type { Knowledge } from '../types';

export function Overview({ knowledge, go }: { knowledge: Knowledge; go: (tab: string) => void }) {
  return (
    <div>
      <div className="pagehead">
        <h1>Neither hack broke a smart contract.</h1>
        <p>On 29 October 2026, two attacks landed on the same day. Polymarket lost about $2.7M when a third-party analytics script was swapped for one that read trading keys out of logged-in browsers. Binance lost billions when its hot wallet was handed to an attacker's contract through a signed delegation. Both came through things developers wire up every day: a vendor script, a signing pipeline, a laptop with credentials on it. Safetyfirst checks your own site, repo and wallets for those exact weaknesses.</p>
      </div>

      <div className="grid3">
        <div className="card">
          <h3 style={{ color: 'var(--crit)' }}>Web</h3>
          <p className="sub">The Polymarket / Bybit vendor-script pattern.</p>
          <p style={{ fontSize: 13, color: 'var(--muted)' }}>Third-party scripts with your users' authority, missing SRI, weak CSP, secrets in the browser, script drift.</p>
          <button className="btn sm" onClick={() => go('scan')}>Scan a site</button>
        </div>
        <div className="card">
          <h3 style={{ color: 'var(--high)' }}>Repo</h3>
          <p className="sub">The TraderTraitor entry point.</p>
          <p style={{ fontSize: 13, color: 'var(--muted)' }}>Install scripts, loose lockfiles, committed tokens, unpinned actions, static cloud keys, dangerous workflows.</p>
          <button className="btn sm" onClick={() => go('scan')}>Scan a repo</button>
        </div>
        <div className="card">
          <h3 style={{ color: 'var(--med)' }}>Chain</h3>
          <p className="sub">The Binance signer-abuse pattern.</p>
          <p style={{ fontSize: 13, color: 'var(--muted)' }}>EIP-7702 delegations, unlimited approvals, and a signer policy linter for the gaps the delegation walked through.</p>
          <button className="btn sm" onClick={() => go('scan')}>Scan addresses</button>
        </div>
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <h3>See it in five minutes</h3>
        <p className="sub">Start the lab, watch a swapped vendor script drain a fake exchange, then open the hardened build and watch the same attack fail.</p>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          <button className="btn" onClick={() => go('lab')}>Open the lab</button>
          <button className="btn ghost" onClick={() => go('tools')}>Harden something now</button>
          <button className="btn ghost" onClick={() => go('learn')}>Read the incidents</button>
        </div>
      </div>

      <div className="foothint">Open source · MIT · runs entirely on your machine · no telemetry · scan only what you own. Knowledge base version {knowledge.version}.</div>
    </div>
  );
}
