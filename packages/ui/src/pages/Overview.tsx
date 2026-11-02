import type { Knowledge } from '../types';

const REPO = 'https://github.com/Yathish27/Lockguard';

/* tiny inline icons (no deps) */
const I = {
  shield: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3l7 3v5c0 4.5-3 8-7 9-4-1-7-4.5-7-9V6l7-3z"/><path d="M9 12l2 2 4-4"/></svg>,
  lock: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="4" y="11" width="16" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>,
  code: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M16 18l6-6-6-6M8 6l-6 6 6 6"/></svg>,
  globe: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.5 2.5 15 0 18M12 3c-2.5 2.5-2.5 15 0 18"/></svg>,
  chain: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10 13a5 5 0 0 0 7 0l2-2a5 5 0 0 0-7-7l-1 1"/><path d="M14 11a5 5 0 0 0-7 0l-2 2a5 5 0 0 0 7 7l1-1"/></svg>,
  eye: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>,
  search: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>,
  wrench: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14.7 6.3a4 4 0 0 0 5 5L22 9a6 6 0 0 1-8 7l-6 6-3-3 6-6a6 6 0 0 1 7-8l-2.3 2.3z"/></svg>,
  script: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M8 14h5"/></svg>,
  laptop: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="4" y="5" width="16" height="11" rx="2"/><path d="M2 20h20"/></svg>,
  pen: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z"/></svg>,
  check: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round"><path d="M20 6L9 17l-5-5"/></svg>,
  home: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 11l9-7 9 7"/><path d="M5 10v10h14V10"/></svg>,
  people: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="9" cy="8" r="3.5"/><path d="M2 20a7 7 0 0 1 14 0"/><path d="M17 5a3 3 0 0 1 0 6M22 20a7 7 0 0 0-5-6.7"/></svg>,
  gear: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1"/></svg>,
  github: <svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.5 2 2 6.6 2 12.3c0 4.5 2.9 8.3 6.8 9.7.5.1.7-.2.7-.5v-1.7c-2.8.6-3.4-1.4-3.4-1.4-.5-1.2-1.1-1.5-1.1-1.5-.9-.6.1-.6.1-.6 1 .1 1.5 1 1.5 1 .9 1.6 2.4 1.1 3 .9.1-.7.3-1.1.6-1.4-2.2-.3-4.6-1.1-4.6-5 0-1.1.4-2 1-2.7-.1-.3-.4-1.3.1-2.7 0 0 .8-.3 2.7 1a9.3 9.3 0 0 1 5 0c1.9-1.3 2.7-1 2.7-1 .5 1.4.2 2.4.1 2.7.6.7 1 1.6 1 2.7 0 3.9-2.3 4.7-4.6 5 .4.3.7.9.7 1.9v2.8c0 .3.2.6.7.5 3.9-1.4 6.8-5.2 6.8-9.7C22 6.6 17.5 2 12 2z"/></svg>
};

export function Overview({ knowledge, go, mode = 'local' }: { knowledge: Knowledge; go: (tab: string) => void; mode?: 'local' | 'hosted' | 'static' }) {
  const canScan = mode === 'local' || mode === 'hosted';

  const primary = mode === 'local'
    ? { label: 'Watch a live attack', act: () => go('lab') }
    : mode === 'hosted'
      ? { label: 'Scan your site', act: () => go('scan') }
      : { label: 'See the live attack', act: () => go('lab') };
  const secondary = mode === 'local'
    ? { label: 'Scan your stack', act: () => go('scan') }
    : { label: 'Explore the checks', act: () => go('learn') };

  return (
    <div className="landing">
      {/* HERO */}
      <section className="hero">
        <span className="eyebrow"><span className="dotlive" /> Open source · Free · Runs on your machine</span>
        <h1>The biggest crypto hacks of 2026 never broke a line of code.</h1>
        <p className="lead">
          They slipped in through a third-party script on a website, a signing system that approved a bad transaction, and a developer's laptop —
          the ordinary things every team wires up without a second thought. <b style={{ color: 'var(--text)' }}>Lockguard</b> checks your own
          website, code and wallets for those exact weak spots, shows you the real hack each one maps to, and hands you the fix.
        </p>
        <div className="cta">
          <button className="btn lg" onClick={primary.act}>{primary.label}</button>
          <button className="btn ghost lg" onClick={secondary.act}>{secondary.label}</button>
          <a className="btn ghost lg" href={REPO} target="_blank" rel="noreferrer">{I.github} GitHub</a>
        </div>
        <div className="trustrow">
          <span>{I.check} No account needed</span>
          <span>{I.check} Nothing leaves your machine</span>
          <span>{I.check} No telemetry</span>
          <span>{I.check} MIT licensed</span>
        </div>
      </section>

      {/* THE PROBLEM */}
      <section className="section">
        <div className="section-head">
          <div className="kicker">The problem</div>
          <h2>Billions gone, and not one smart contract was exploited</h2>
          <p>Three of the largest thefts in crypto history came through the plumbing around the code, not the code itself.</p>
        </div>
        <div className="stats">
          <div className="stat">
            <div className="amount">$6.3B</div>
            <div className="who">Binance · Oct 2026</div>
            <div className="how">A signing system approved one transaction that handed a hot wallet to an attacker's contract. The key never leaked.</div>
            <div className="when">EIP-7702 delegation abuse</div>
          </div>
          <div className="stat">
            <div className="amount">$2.7M</div>
            <div className="who">Polymarket · Oct 2026</div>
            <div className="how">An analytics script from an outside vendor was swapped for one that read trading keys straight out of logged-in browsers.</div>
            <div className="when">Third-party script injection</div>
          </div>
          <div className="stat">
            <div className="amount">$1.5B</div>
            <div className="who">Bybit · Feb 2025</div>
            <div className="how">A developer's machine was compromised and planted code changed what the signers saw. They approved a swap they never intended.</div>
            <div className="when">Supply-chain / signer tampering</div>
          </div>
        </div>
      </section>

      {/* EVERYDAY THINGS */}
      <section className="section">
        <div className="section-head">
          <div className="kicker">Why it matters to you</div>
          <h2>The way in was something you set up every day</h2>
          <p>If your product moves money or holds a login worth stealing, you already have all three of these.</p>
        </div>
        <div className="pointrow">
          <div className="point">
            <div className="ic">{I.script}</div>
            <h4>A script on your website</h4>
            <p>Analytics, chat, a tag manager. It runs with the same power as your own code and can read what your users' browsers hold.</p>
          </div>
          <div className="point">
            <div className="ic">{I.pen}</div>
            <h4>A signing pipeline</h4>
            <p>The system that approves transactions. If it will sign something it never should, one bad request empties the wallet.</p>
          </div>
          <div className="point">
            <div className="ic">{I.laptop}</div>
            <h4>A developer's laptop</h4>
            <p>A fake job test or a poisoned package runs on install and steals the keys and tokens that reach everything else.</p>
          </div>
        </div>
      </section>

      {/* HOW IT HELPS */}
      <section className="section">
        <div className="section-head">
          <div className="kicker">How Lockguard helps</div>
          <h2>See it, scan for it, fix it</h2>
          <p>You only act on a weakness once you understand the attack behind it and can see the fix. Lockguard puts all three on one screen.</p>
        </div>
        <div className="steprow">
          <div className="step">
            <div className="num">1</div>
            <h4>See the attack happen</h4>
            <p>A safe, local lab runs a tiny exchange and lets a swapped vendor script drain it — then shows the same attack failing once it's hardened. No real funds, no real exploit code.</p>
          </div>
          <div className="step">
            <div className="num">2</div>
            <h4>Scan your own stack</h4>
            <p>Point it at your website, a code repository, or your wallet addresses. It finds the exact weak spots the real hacks used, scored and grouped by attack.</p>
          </div>
          <div className="step">
            <div className="num">3</div>
            <h4>Fix it, with the real story</h4>
            <p>Every finding names the real incident it maps to, explains why it matters in plain terms, and gives you a copy-paste fix.</p>
          </div>
        </div>
      </section>

      {/* THREE MODULES */}
      <section className="section">
        <div className="section-head">
          <div className="kicker">What it checks</div>
          <h2>Three checks, three real attacks</h2>
          <p>Each maps to a documented 2025–2026 incident where that exact gap was the way in.</p>
        </div>
        <div className="feat">
          <div className="feature web">
            <div className="ficon">{I.globe}</div>
            <h3>Your website</h3>
            <p className="maps">The Polymarket / Bybit vendor-script pattern</p>
            <ul>
              <li>Third-party scripts running with your users' authority</li>
              <li>Missing Subresource Integrity and weak Content Security Policy</li>
              <li>Session tokens or API keys readable by any script</li>
              <li>Drift alerts when a vendor's script silently changes</li>
            </ul>
            <div className="ftail">
              {canScan ? <button className="btn sm" onClick={() => go('scan')}>{I.search} Scan a site</button>
                : <div className="hint" style={{ margin: 0 }}>Run locally: <code>npx lockguard</code></div>}
            </div>
          </div>
          <div className="feature repo">
            <div className="ficon">{I.code}</div>
            <h3>Your code</h3>
            <p className="maps">The developer-and-CI compromise entry point</p>
            <ul>
              <li>Dependencies that run code the moment you install them</li>
              <li>Committed tokens, keys and loose lockfiles</li>
              <li>Build actions pinned to a movable tag instead of a fixed commit</li>
              <li>Long-lived cloud keys where short-lived ones belong</li>
            </ul>
            <div className="ftail">
              {mode === 'local' ? <button className="btn sm" onClick={() => go('scan')}>{I.search} Scan a repo</button>
                : <div className="hint" style={{ margin: 0 }}>Local: <code>npx lockguard scan --repo .</code></div>}
            </div>
          </div>
          <div className="feature chain">
            <div className="ficon">{I.chain}</div>
            <h3>Your wallets</h3>
            <p className="maps">The Binance signer-abuse pattern</p>
            <ul>
              <li>EIP-7702 delegations handing an address to other code</li>
              <li>Unlimited token approvals left open to spenders</li>
              <li>A signer-policy linter for the gaps a bad delegation walks through</li>
              <li>Read-only — it never asks for a key or a signature</li>
            </ul>
            <div className="ftail">
              {canScan ? <button className="btn sm" onClick={() => go('scan')}>{I.search} Scan addresses</button>
                : <div className="hint" style={{ margin: 0 }}>Run locally to scan</div>}
            </div>
          </div>
        </div>
      </section>

      {/* FOR ORGANIZATIONS */}
      <section className="section">
        <div className="section-head">
          <div className="kicker">For your team</div>
          <h2>Built to run inside your organization</h2>
          <p>Open source and self-contained, so you can point it at production config and real addresses without anything leaving your network.</p>
        </div>
        <div className="orgrow">
          <div className="orgcard"><div className="ic">{I.home}</div><h4>Runs on your machine</h4><p>No account, no sign-up, no data sent anywhere. The only network calls are the ones you ask for.</p></div>
          <div className="orgcard"><div className="ic">{I.shield}</div><h4>Open source, auditable</h4><p>MIT licensed. Read every check, see exactly what it does, and add your own.</p></div>
          <div className="orgcard"><div className="ic">{I.gear}</div><h4>Fits your pipeline</h4><p>A CLI and a GitHub Action with JSON, Markdown and SARIF output, so findings land in code scanning.</p></div>
          <div className="orgcard"><div className="ic">{I.people}</div><h4>Shareable with the team</h4><p>Every report explains the risk and the fix in plain terms, so it's not just for the security expert.</p></div>
        </div>
      </section>

      {/* CTA BAND */}
      <section className="ctaband">
        <h2>Test it on your own stack in minutes</h2>
        <p>Clone it, run one command, and point it at what you own. For a quick look, the live lab shows the whole attack and its fix without installing anything.</p>
        <div className="cmd"><span className="prompt">$</span> git clone {REPO}</div>
        <div className="cmd"><span className="prompt">$</span> npm ci &amp;&amp; npm start</div>
        <div className="cta" style={{ marginTop: 22 }}>
          <button className="btn lg" onClick={primary.act}>{primary.label}</button>
          <a className="btn ghost lg" href={REPO} target="_blank" rel="noreferrer">{I.github} Star on GitHub</a>
        </div>
      </section>

      <div className="landing-foot">
        Lockguard · open source under the MIT license · runs entirely on your machine · no telemetry · scan only what you own.
        <br />Knowledge base version {knowledge.version} · maps to real incidents, sources cited in the repo.
      </div>
    </div>
  );
}
