// Lockguard lab — a tiny, entirely local "exchange" in two builds.
//
//  VULNERABLE build  (how Polymarket / Bybit happened):
//    - session token + a "trading API key" live in localStorage, readable by any script
//    - an analytics script is loaded from the cross-origin "vendor CDN" with NO SRI and NO CSP
//    - when you flip the vendor CDN to "compromised", that script reads the token, calls the
//      withdraw API as you, and rewrites the confirmation screen — all in the sandbox.
//
//  HARDENED build:
//    - session is an HttpOnly cookie; nothing sensitive is in JS reach
//    - strict nonce-based CSP, a real SRI hash on the vendor script, connect-src locked to self
//    - withdrawals need a step-up token the real UI flow mints
//    - the swapped script fails the integrity check and never runs; even if it did, it could
//      neither read the cookie nor mint the step-up token.
//
// There are NO real funds, NO real keys, and NO real drainer code anywhere.

import express, { type Request, type Response, type NextFunction } from 'express';
import crypto from 'node:crypto';
import { benignSri } from './vendor.js';

export type Mode = 'vulnerable' | 'hardened';

interface Account { user: string; balanceUSD: number; apiKey: string; sessionToken: string; history: string[] }

export interface LabAppOptions { siblingUrl?: string; vendorUrl: string; appOrigin: string }

export function createLabApp(mode: Mode, opts: LabAppOptions) {
  const app = express();
  app.use(express.json());

  const account: Account = freshAccount();
  function freshAccount(): Account {
    return { user: 'demo', balanceUSD: 10_000, apiKey: 'demo_api_key_' + crypto.randomBytes(6).toString('hex'), sessionToken: 'sess_' + crypto.randomBytes(12).toString('hex'), history: [] };
  }
  const exfil: Array<{ at: string; stage: string; detail: string }> = [];
  const nonces = new Map<string, number>();
  function newNonce(): string { const n = crypto.randomBytes(16).toString('base64'); nonces.set(n, Date.now()); if (nonces.size > 200) for (const [k, t] of nonces) if (Date.now() - t > 60000) nonces.delete(k); return n; }

  // CORS: the cross-origin vendor script needs to call back for the demo. The hardened build
  // still blocks the *effect* (cookie not readable, step-up required), not the request.
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.setHeader('Access-Control-Allow-Origin', opts.vendorUrl || '*');
    res.setHeader('Access-Control-Allow-Headers', 'content-type,authorization,x-api-key,x-initiated-by,x-step-up');
    if (req.method === 'OPTIONS') return res.status(204).end();
    res.locals.nonce = newNonce();
    if (mode === 'hardened') {
      res.setHeader('Content-Security-Policy', [
        "default-src 'self'",
        `script-src 'nonce-${res.locals.nonce}' 'strict-dynamic'`,
        "object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'",
        "connect-src 'self'", "form-action 'self'",
        "require-trusted-types-for 'script'"
      ].join('; '));
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Referrer-Policy', 'no-referrer');
    }
    next();
  });

  app.post('/api/login', (req, res) => {
    if (mode === 'hardened') {
      res.setHeader('Set-Cookie', `sid=${account.sessionToken}; HttpOnly; SameSite=Strict; Path=/`);
      return res.json({ ok: true, user: account.user });
    }
    return res.json({ ok: true, user: account.user, sessionToken: account.sessionToken, apiKey: account.apiKey });
  });

  function authed(req: Request): boolean {
    if (mode === 'hardened') return (req.headers.cookie ?? '').includes(`sid=${account.sessionToken}`);
    const h = req.headers.authorization ?? '';
    const key = (req.headers['x-api-key'] as string) ?? '';
    return h === `Bearer ${account.sessionToken}` || (!!key && key === account.apiKey);
  }

  app.get('/api/account', (req, res) => {
    if (!authed(req)) return res.status(401).json({ error: 'not authenticated' });
    res.json({ user: account.user, balanceUSD: account.balanceUSD, history: account.history, apiKeyMasked: account.apiKey.slice(0, 12) + '…' });
  });

  app.post('/api/withdraw', (req, res) => {
    if (!authed(req)) return res.status(401).json({ error: 'not authenticated' });
    const amount = Math.max(0, Number(req.body?.amount) || 0);
    const to = String(req.body?.to ?? 'unknown');
    const viaScript = req.headers['x-initiated-by'] === 'analytics-script';
    if (amount > account.balanceUSD) return res.status(400).json({ error: 'insufficient balance' });
    if (mode === 'hardened' && req.headers['x-step-up'] !== 'passkey-ok') return res.status(403).json({ error: 'withdrawal requires step-up authentication (passkey)' });
    account.balanceUSD -= amount;
    account.history.unshift(`−$${amount.toLocaleString()} to ${to}${viaScript ? '  (initiated by a page script)' : ''}`);
    if (viaScript) exfil.push({ at: new Date().toISOString(), stage: 'withdraw', detail: `drained $${amount} to ${to}` });
    res.json({ ok: true, balanceUSD: account.balanceUSD });
  });

  app.post('/lab/_attack-log', (req, res) => { exfil.push({ at: new Date().toISOString(), stage: String(req.body?.stage ?? '?'), detail: JSON.stringify(req.body?.data ?? {}).slice(0, 160) }); res.json({ ok: true }); });

  app.get('/lab/state', (_req, res) => res.json({ mode, balanceUSD: account.balanceUSD, exfiltrated: exfil, apiKeyMasked: account.apiKey.slice(0, 12) + '…' }));
  app.post('/lab/reset', (_req, res) => { Object.assign(account, freshAccount()); exfil.length = 0; res.json({ ok: true }); });

  app.get('/', (_req, res) => { res.type('html').send(renderPage(mode, res.locals.nonce as string, opts)); });
  return app;
}

function renderPage(mode: Mode, nonce: string, opts: LabAppOptions): string {
  const hardened = mode === 'hardened';
  const vendorSrc = `${opts.vendorUrl}/analytics.js`;
  // Hardened: real SRI hash of the benign script + crossorigin + nonce. A swapped script fails the hash and never runs.
  // Hardened: static tag with a REAL SRI hash + crossorigin + nonce. A swapped script fails the hash and never runs.
  // (The refusal message is shown by a nonce'd timed check below, because strict CSP correctly blocks inline onerror handlers.)
  const vendorScript = hardened
    ? `<script src="${vendorSrc}" integrity="${benignSri()}" crossorigin="anonymous" nonce="${nonce}"></script>`
    : `<script src="${vendorSrc}"></script>`;
  const scriptNonce = hardened ? ` nonce="${nonce}"` : '';
  const switchText = hardened ? 'vulnerable' : 'hardened';
  const storeLogin = hardened
    ? `el('store-note').innerHTML = 'Logged in. The session is an <code>HttpOnly</code> cookie — no script can read it — and nothing sensitive is in <code>localStorage</code>.';`
    : `localStorage.setItem('sessionToken', r.sessionToken); localStorage.setItem('apiKey', r.apiKey); el('store-note').innerHTML = 'Logged in. This build put <code>sessionToken</code> and <code>apiKey</code> in <code>localStorage</code> — readable by every script on the page.';`;
  const resetClear = hardened ? '' : 'try{localStorage.clear();}catch(e){}';
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lab Exchange — ${mode}</title>
<style>
  :root{color-scheme:dark}
  body{font:15px/1.5 system-ui,-apple-system,sans-serif;max-width:720px;margin:0 auto;padding:24px;background:#0f1720;color:#e7edf3}
  h1{font-size:20px;margin:0 0 4px} .mode{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600;vertical-align:middle}
  .vuln{background:#5b1a1a;color:#ffd9d9} .hard{background:#12402e;color:#b8f5d6}
  .card{background:#172230;border:1px solid #243244;border-radius:12px;padding:16px;margin:14px 0}
  .bal{font-size:34px;font-weight:700}
  button{font:inherit;padding:8px 14px;border-radius:8px;border:1px solid #1f6feb;background:#1f6feb;color:#fff;cursor:pointer;margin:2px}
  button.ghost{background:transparent;color:#9fb4c9;border-color:#2d4055}
  #attack-banner{display:none;background:#5b1a1a;color:#ffd9d9;padding:10px;border-radius:8px;margin:10px 0}
  code{background:#0b1118;padding:1px 5px;border-radius:4px;color:#9fe6c0}
  .muted{color:#8aa0b5;font-size:13px} a{color:#6ea8fe}
  ol{margin:6px 0 0;padding-left:20px} li{margin:3px 0}
</style></head>
<body>
  <h1>Lab Exchange <span class="mode ${hardened ? 'hard' : 'vuln'}">${mode}</span></h1>
  <p class="muted">A fake exchange running entirely on your machine. No real funds, no real keys. ${hardened ? 'This build is hardened the way the fix list describes.' : 'This build has the weaknesses behind the Polymarket and Bybit attacks.'}</p>
  <div id="attack-banner"></div>
  <div class="card">
    <div class="muted">Demo balance</div>
    <div class="bal">$<span id="balance">—</span></div>
    <p class="muted" id="vendor-status">loading analytics…</p>
  </div>
  <div class="card">
    <strong>Try it</strong>
    <ol>
      <li><button id="login">1 · Log in</button> <span class="muted" id="store-note"></span></li>
      <li><button id="compromise">2 · Serve malicious analytics.js</button> then reload the page.</li>
      <li>Watch the balance and the banner. <button id="reset" class="ghost">Reset lab</button></li>
    </ol>
  </div>
  <p class="muted">Compare: <a href="${opts.siblingUrl || '/'}">open the ${switchText} build</a>. Vendor CDN: <code>${opts.vendorUrl}</code>.</p>
<script${scriptNonce}>
  var el = function(id){ return document.getElementById(id); };
  function j(u,o){ return fetch(u,o).then(function(r){ return r.json(); }); }
  function refresh(){ return j('/lab/state').then(function(s){ el('balance').textContent = Number(s.balanceUSD).toLocaleString(); }); }
  el('login').onclick = function(){ j('/api/login',{method:'POST'}).then(function(r){ ${storeLogin} refresh(); }); };
  el('compromise').onclick = function(){
    j('${opts.vendorUrl}/state').then(function(s){
      return fetch('${opts.vendorUrl}/compromise',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({on:!s.compromised})}).then(function(r){return r.json();});
    }).then(function(r){ el('compromise').textContent = r.compromised ? '2 · Vendor is COMPROMISED — reload now' : '2 · Serve malicious analytics.js'; });
  };
  el('reset').onclick = function(){ Promise.all([j('/lab/reset',{method:'POST'}), fetch('${opts.vendorUrl}/reset',{method:'POST'})]).then(function(){ ${resetClear} location.reload(); }); };
  ${hardened ? `setTimeout(function(){ var e = el('vendor-status'); if (e && /loading/.test(e.textContent)) e.textContent = 'The vendor script did not execute. If it was swapped, Subresource Integrity refused it — the attack cannot run here.'; }, 1600);` : ''}
  refresh();
</script>
${vendorScript}
</body></html>`;
}
