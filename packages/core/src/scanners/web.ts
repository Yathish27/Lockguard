import { chromium, type Browser, type Response } from 'playwright';
import { existsSync } from 'node:fs';
import type { Baseline, Evidence, Finding, ModuleResult, Progress, ScriptObservation, Severity, WebTarget } from '../types.js';
import { makeFinding, bump } from '../knowledge/index.js';
import { isThirdParty, isLocalHost, categorizeHost } from '../util/origin.js';
import { sha256Hex, sriHash, mask } from '../util/hash.js';
import { scoreFindings } from '../report/score.js';
import { buildBaseline, diffBaseline } from '../baseline.js';

const CANDIDATE_BROWSERS = [
  '/opt/pw-browsers/chromium',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  '/usr/bin/google-chrome',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  'C:/Program Files/Google/Chrome/Application/chrome.exe'
];

/** Use Playwright's own Chromium when present; otherwise fall back to a system browser so the tool still runs. */
export function resolveBrowserPath(): string | undefined {
  const env = process.env.SAFETYFIRST_BROWSER_PATH;
  if (env && existsSync(env)) return env;
  try {
    const p = chromium.executablePath();
    if (p && existsSync(p)) return undefined;
  } catch { /* ignore */ }
  for (const c of CANDIDATE_BROWSERS) if (existsSync(c)) return c;
  return undefined;
}

export interface CspAnalysis {
  enforced: string | null;
  reportOnly: string | null;
  meta: string | null;
  directives: Record<string, string[]>;
  problems: Array<{ severity: Severity; detail: string }>;
  trustedTypes: boolean;
}

export function parseCsp(policy: string): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const part of policy.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) continue;
    const [name, ...values] = tokens;
    out[name.toLowerCase()] = values.map((v) => v.toLowerCase() === v ? v : v);
  }
  return out;
}

export function analyzeCsp(enforced: string | null, reportOnly: string | null, meta: string | null, signingPage: boolean): CspAnalysis {
  const active = enforced ?? meta;
  const problems: CspAnalysis['problems'] = [];
  const directives = active ? parseCsp(active) : {};
  const sev = (s: Severity): Severity => (signingPage ? bump(s) : s);

  if (!active && !reportOnly) {
    problems.push({ severity: sev('high'), detail: 'No Content-Security-Policy header or meta tag. Any script from anywhere can run and send data anywhere.' });
    return { enforced, reportOnly, meta, directives, problems, trustedTypes: false };
  }
  if (!active && reportOnly) {
    problems.push({ severity: sev('high'), detail: 'Only Content-Security-Policy-Report-Only is set. Nothing is blocked.' });
    Object.assign(directives, parseCsp(reportOnly));
  }
  const scriptSrc = directives['script-src'] ?? directives['default-src'] ?? null;
  const lower = (arr: string[] | null) => (arr ?? []).map((s) => s.toLowerCase());
  const ss = lower(scriptSrc);
  const hasNonceOrHash = ss.some((s) => s.startsWith("'nonce-") || s.startsWith("'sha256-") || s.startsWith("'sha384-") || s.startsWith("'sha512-"));
  const strictDynamic = ss.includes("'strict-dynamic'");

  if (!scriptSrc) {
    problems.push({ severity: sev('high'), detail: 'Neither script-src nor default-src is set: scripts are unrestricted.' });
  } else {
    if (ss.includes("'unsafe-inline'") && !hasNonceOrHash) problems.push({ severity: sev('high'), detail: "script-src allows 'unsafe-inline' without nonces or hashes: any injected inline script runs." });
    if (ss.includes("'unsafe-eval'")) problems.push({ severity: 'medium', detail: "script-src allows 'unsafe-eval'." });
    if (!strictDynamic) {
      const wild = ss.filter((s) => s === '*' || s === 'https:' || s === 'http:' || s === 'data:' || /^https?:\/\/\*$/.test(s) || /^\*\./.test(s));
      if (wild.length) problems.push({ severity: sev('high'), detail: `script-src contains wildcard sources (${wild.join(' ')}): effectively any script is allowed.` });
      if (!hasNonceOrHash) problems.push({ severity: 'medium', detail: "script-src is a host allowlist without nonces or 'strict-dynamic'. A compromised allowed host (Polymarket's vendor was an allowed host) still runs. Prefer nonces + 'strict-dynamic'." });
    }
  }
  const objectSrc = directives['object-src'] ?? directives['default-src'];
  if (!objectSrc || !lower(objectSrc).includes("'none'")) problems.push({ severity: 'medium', detail: "object-src is not 'none' (plugin content can execute script)." });
  if (!directives['base-uri']) problems.push({ severity: 'low', detail: 'base-uri is missing (base tag injection can redirect relative script URLs).' });
  const connect = directives['connect-src'] ?? directives['default-src'];
  if (!connect) problems.push({ severity: sev('medium'), detail: 'connect-src is not restricted: a malicious script can send stolen data anywhere. This is the exfiltration control.' });
  else if (lower(connect).some((s) => s === '*' || s === 'https:' || s === 'http:')) problems.push({ severity: sev('medium'), detail: `connect-src allows wildcard destinations (${connect.join(' ')}): exfiltration is not restricted.` });
  if (!directives['form-action']) problems.push({ severity: 'low', detail: 'form-action is missing (forms can be re-pointed to attacker hosts).' });
  if (!directives['frame-ancestors']) problems.push({ severity: 'low', detail: 'frame-ancestors is missing (clickjacking; X-Frame-Options can compensate).' });
  if (!directives['report-uri'] && !directives['report-to']) problems.push({ severity: 'low', detail: 'No report-uri / report-to: you will not see violations, which are your earliest signal of a swapped script.' });
  const tt = directives['require-trusted-types-for']?.map((s) => s.toLowerCase()).includes("'script'") ?? false;
  return { enforced, reportOnly, meta, directives, problems, trustedTypes: tt };
}

const SIGNING_PATH = /(trade|swap|withdraw|send|sign|wallet|bridge|transfer|stake|vault|portfolio|exchange|markets?|checkout|payment)/i;
const SIGNING_TEXT = ['withdraw', 'connect wallet', 'sign in', 'sign message', 'approve', 'seed phrase', 'private key', 'api key', 'metamask', 'walletconnect', 'deposit', 'transfer', 'swap', 'place order', 'buy', 'sell'];

const KEYISH = /(token|jwt|session|auth|secret|api[-_]?key|apikey|private|mnemonic|seed|credential|passw|bearer|refresh|access)/i;
const JWT = /^eyJ[\w-]{6,}\.[\w-]{6,}\.[\w-]{6,}$/;
const HEXKEY = /^(0x)?[0-9a-fA-F]{64}$/;
const MNEMONIC = /^([a-z]+\s+){11,23}[a-z]+$/;
const JSON_SECRET = /"(access_?token|id_?token|refresh_?token|api_?key|apiKey|secret|privateKey|private_key|mnemonic|seed|session_?token|sessionToken|authToken|auth_?token|jwt|token)"\s*:\s*"([^"]{8,})"/i;
const COOKIE_SESSION_NAME = /^(connect\.sid|phpsessid|jsessionid|sid|ssid|sessid|session|sess|auth|token|jwt|__host-|__secure-|_?csrf)/i;

interface StorageHit { store: 'localStorage' | 'sessionStorage' | 'cookie'; name: string; kind: 'key-material' | 'session-token' | 'api-key' | 'auth-ish'; preview: string; flags: string[] }

function classifyStorage(store: 'localStorage' | 'sessionStorage', key: string, value: string): StorageHit | null {
  const v = (value ?? '').trim();
  const k = key;
  const flags: string[] = [];
  if (HEXKEY.test(v) && /(priv|key|secret|seed|mnemonic|wallet)/i.test(k)) return { store, name: k, kind: 'key-material', preview: mask(v), flags: ['64-hex value under a key-like name'] };
  if (MNEMONIC.test(v) && v.split(/\s+/).length >= 12) return { store, name: k, kind: 'key-material', preview: mask(v, 6), flags: ['looks like a BIP-39 mnemonic'] };
  if (/(mnemonic|seed[_-]?phrase|private[_-]?key)/i.test(k) && v.length >= 16) return { store, name: k, kind: 'key-material', preview: mask(v), flags: ['key-like name'] };
  if (JWT.test(v)) return { store, name: k, kind: 'session-token', preview: mask(v, 10), flags: ['JWT value'] };
  const js = v.length < 200_000 ? v.match(JSON_SECRET) : null;
  if (js) {
    const field = js[1];
    const kind = /api/i.test(field) ? 'api-key' : /(private|mnemonic|seed)/i.test(field) ? 'key-material' : 'session-token';
    return { store, name: `${k} → ${field}`, kind, preview: mask(js[2], 6), flags: ['secret-looking field inside JSON value'] };
  }
  if (/(api[-_]?key|apikey|api[-_]?secret)/i.test(k) && v.length >= 12) return { store, name: k, kind: 'api-key', preview: mask(v), flags: ['API-key-like name'] };
  if (/(token|jwt|session|secret|bearer|refresh)/i.test(k) && v.length >= 16) return { store, name: k, kind: 'session-token', preview: mask(v), flags: ['token-like name'] };
  if (/(auth|credential|passw)/i.test(k) && v.length >= 8) return { store, name: k, kind: 'auth-ish', preview: mask(v), flags: ['auth-like name'] };
  return null;
}

export async function scanWeb(target: WebTarget, onProgress: Progress = () => {}): Promise<ModuleResult> {
  const startedAt = new Date().toISOString();
  const errors: string[] = [];
  const findings: Finding[] = [];
  const url = target.url;
  const timeout = target.timeoutMs ?? 45_000;
  const settleMs = target.settleMs ?? 3000;
  const firstParty = target.firstPartyDomains ?? [];
  let browser: Browser | null = null;

  const meta: Record<string, unknown> = { url };
  try {
    onProgress('Launching headless Chromium', 2);
    const executablePath = resolveBrowserPath();
    browser = await chromium.launch({
      headless: true,
      executablePath,
      args: ['--no-sandbox', '--disable-background-networking', '--disable-component-update', '--no-first-run', '--no-default-browser-check', '--disable-sync', '--disable-features=Translate,OptimizationHints']
    });
    const context = await browser.newContext({
      storageState: (target.storageState as any) ?? undefined,
      ignoreHTTPSErrors: target.ignoreHTTPSErrors ?? false,
      userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36 Safetyfirst/0.1 (+https://github.com/Yathish27/Lockguard)'
    });
    const page = await context.newPage();

    const scriptResponses = new Map<string, { status: number; body: Buffer | null; headers: Record<string, string>; frameIsMain: boolean }>();
    const pending: Promise<void>[] = [];
    const consoleErrors: string[] = [];
    page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(m.text().slice(0, 300)); });
    page.on('response', (res: Response) => {
      const req = res.request();
      if (req.resourceType() !== 'script') return;
      const frameIsMain = req.frame() === page.mainFrame();
      const p = (async () => {
        let body: Buffer | null = null;
        try { body = await res.body(); } catch { body = null; }
        scriptResponses.set(res.url(), { status: res.status(), body, headers: res.headers(), frameIsMain });
      })();
      pending.push(p);
    });

    onProgress(`Loading ${url}`, 10);
    const mainResp = await page.goto(url, { waitUntil: 'load', timeout });
    await page.waitForLoadState('networkidle', { timeout: 8000 }).catch(() => {});
    await page.waitForTimeout(settleMs);
    await Promise.allSettled(pending);

    const finalUrl = page.url();
    const headers = mainResp ? Object.fromEntries(Object.entries(mainResp.headers()).map(([k, v]) => [k.toLowerCase(), v])) : {};
    const title = await page.title().catch(() => '');
    const pageIsHttps = finalUrl.startsWith('https:');
    const pageHost = new URL(finalUrl).hostname;
    const local = isLocalHost(pageHost);
    meta.finalUrl = finalUrl; meta.title = title; meta.status = mainResp?.status() ?? null;

    onProgress('Inspecting DOM, storage and cookies', 45);
    const dom = await page.evaluate(() => {
      const scripts = Array.from(document.scripts).map((s) => ({
        src: s.src || null,
        integrity: s.integrity || null,
        crossOrigin: s.crossOrigin,
        nonce: !!s.nonce,
        type: s.type || null,
        inlineLength: s.src ? 0 : (s.textContent || '').length
      }));
      const metas = Array.from(document.querySelectorAll('meta[http-equiv]')) as HTMLMetaElement[];
      const metaCsp = metas.filter((m) => m.httpEquiv.toLowerCase() === 'content-security-policy').map((m) => m.content);
      const text = (document.body?.innerText || '').toLowerCase().slice(0, 200_000);
      const inputs = Array.from(document.querySelectorAll('input')).map((i) => `${i.name || ''} ${i.id || ''} ${i.placeholder || ''}`.toLowerCase());
      const w = window as any;
      return {
        scripts,
        metaCsp,
        text,
        inputs,
        iframes: document.querySelectorAll('iframe').length,
        forms: document.forms.length,
        hasEthereum: !!w.ethereum,
        hasWeb3: !!(w.Web3 || w.ethers || w.solana || w.phantom),
        local: Object.entries(localStorage) as [string, string][],
        session: Object.entries(sessionStorage) as [string, string][]
      };
    });
    const cookies = await context.cookies();

    // ---- signing-page heuristic
    const signals: string[] = [];
    if (SIGNING_PATH.test(new URL(finalUrl).pathname)) signals.push(`URL path looks transactional (${new URL(finalUrl).pathname})`);
    const textHits = SIGNING_TEXT.filter((t) => dom.text.includes(t));
    if (textHits.length >= 2) signals.push(`page text mentions: ${textHits.slice(0, 6).join(', ')}`);
    if (dom.hasEthereum || dom.hasWeb3) signals.push('wallet provider detected in page (window.ethereum / web3 library)');
    if (dom.inputs.some((i) => /(address|amount|recipient|destination|0x)/.test(i))) signals.push('inputs for address / amount / recipient');
    if (cookies.length || dom.local.length) signals.push('authenticated or stateful session present');
    const signingPage = target.signingPage === true ? true : target.signingPage === false ? false : signals.length >= 2;
    meta.signingPage = signingPage; meta.signingSignals = signals;

    // ---- script inventory
    const observations: ScriptObservation[] = [];
    const seen = new Set<string>();
    const domBySrc = new Map<string, (typeof dom.scripts)[number]>();
    for (const s of dom.scripts) if (s.src) domBySrc.set(s.src, s);
    const allUrls = new Set<string>([...scriptResponses.keys(), ...domBySrc.keys()]);
    for (const su of allUrls) {
      if (seen.has(su) || su.startsWith('data:') || su.startsWith('blob:')) continue;
      seen.add(su);
      const r = scriptResponses.get(su);
      if (r && !r.frameIsMain) continue;
      let origin = ''; let host = '';
      try { const u = new URL(su); origin = u.origin; host = u.hostname; } catch { continue; }
      const third = isThirdParty(finalUrl, su, firstParty);
      const d = domBySrc.get(su);
      const cat = third ? categorizeHost(host) : null;
      observations.push({
        url: su,
        origin,
        thirdParty: third,
        inDom: !!d,
        integrity: d?.integrity ?? null,
        crossOrigin: d?.crossOrigin ?? null,
        nonce: d?.nonce ?? false,
        status: r?.status ?? null,
        bytes: r?.body?.length ?? 0,
        sha256: r?.body ? sha256Hex(r.body) : null,
        sha384: r?.body ? sriHash(r.body, 'sha384') : null,
        category: cat?.category ?? null,
        categoryRisk: cat?.risk ?? null
      });
    }
    const inlineScripts = dom.scripts.filter((s) => !s.src && s.inlineLength > 0);
    meta.scripts = observations;
    meta.inlineScripts = inlineScripts.length;
    meta.iframes = dom.iframes;
    meta.withSession = !!target.storageState;
    const thirdParty = observations.filter((o) => o.thirdParty);
    const byOrigin = new Map<string, ScriptObservation[]>();
    for (const o of thirdParty) byOrigin.set(o.origin, [...(byOrigin.get(o.origin) ?? []), o]);
    meta.thirdPartyOrigins = [...byOrigin.keys()];

    onProgress('Evaluating findings', 70);

    // ---- W8 transport
    if (!pageIsHttps && !local) {
      findings.push(makeFinding('W8', {
        key: `W8:${finalUrl}`,
        summary: 'The page itself is served over plain HTTP.',
        severity: signingPage ? 'critical' : 'high',
        evidence: [{ location: finalUrl, detail: 'Document loaded without TLS; anyone on the path can rewrite the HTML and every script in it.' }]
      }));
    }
    const httpScripts = observations.filter((o) => o.url.startsWith('http:') && !isLocalHost(new URL(o.url).hostname));
    if (httpScripts.length && pageIsHttps === false && !local) {
      findings.push(makeFinding('W8', {
        key: `W8:scripts:${finalUrl}`,
        summary: `${httpScripts.length} script(s) load over plain HTTP.`,
        evidence: httpScripts.slice(0, 20).map((o) => ({ location: o.url, detail: 'Unauthenticated script transport.' }))
      }));
    }

    // ---- W1 third-party origins
    for (const [origin, list] of byOrigin) {
      const host = new URL(origin).hostname;
      const cat = categorizeHost(host);
      let sev: Severity = cat ? (cat.risk === 'critical' ? 'critical' : cat.risk === 'high' ? 'high' : cat.risk === 'medium' ? 'medium' : 'low') : 'low';
      if (signingPage && sev !== 'critical') sev = bump(sev);
      const dynamic = list.filter((o) => !o.inDom).length;
      const ev: Evidence[] = list.slice(0, 15).map((o) => ({
        location: o.url,
        detail: [o.inDom ? 'script tag in DOM' : 'injected at runtime (no DOM tag at load)', o.integrity ? 'has SRI' : 'no SRI', o.bytes ? `${o.bytes} bytes` : 'body not captured', o.sha256 ? `sha256 ${o.sha256.slice(0, 16)}…` : ''].filter(Boolean).join(' · ')
      }));
      if (cat) ev.unshift({ location: origin, detail: `${cat.category}: ${cat.note}` });
      findings.push(makeFinding('W1', {
        key: `W1:${origin}`,
        summary: `${host} executes ${list.length} script(s) on this page${cat ? ` (${cat.category})` : ''}${signingPage ? ' — and this looks like a signing / trading page' : ''}.`,
        severity: sev,
        evidence: ev,
        tags: [cat?.category ?? 'third-party', ...(dynamic ? ['dynamic-injection'] : []), ...(signingPage ? ['signing-page'] : [])]
      }));
    }

    // ---- W2 SRI
    for (const o of thirdParty) {
      if (o.integrity) continue;
      const sev: Severity = signingPage ? 'critical' : 'high';
      const snippet = o.sha384
        ? [{ title: 'Exact tag for the script as served right now (verify with the vendor before trusting it)', lang: 'html', code: `<script src="${o.url}"\n        integrity="${o.sha384}"\n        crossorigin="anonymous"></script>` }]
        : [];
      findings.push(makeFinding('W2', {
        key: `W2:${o.url}`,
        summary: o.inDom ? `${new URL(o.url).hostname} script has no integrity attribute.` : `${new URL(o.url).hostname} script is injected at runtime, so it cannot carry SRI.`,
        severity: sev,
        evidence: [{ location: o.url, detail: o.inDom ? `script tag without integrity${o.crossOrigin ? '' : ' (and without crossorigin)'}` : 'Loaded by another script; no tag to annotate. Replace the loader on this page.' }],
        extraSnippets: snippet,
        tags: o.inDom ? [] : ['dynamic-injection']
      }));
    }

    // ---- W3 CSP
    const csp = analyzeCsp(headers['content-security-policy'] ?? null, headers['content-security-policy-report-only'] ?? null, dom.metaCsp[0] ?? null, signingPage);
    meta.csp = { enforced: csp.enforced, reportOnly: csp.reportOnly, meta: csp.meta, directives: csp.directives, trustedTypes: csp.trustedTypes };
    if (csp.problems.length) {
      const worst = csp.problems.reduce<Severity>((w, p) => (sevRank(p.severity) > sevRank(w) ? p.severity : w), 'info');
      findings.push(makeFinding('W3', {
        key: `W3:${finalUrl}`,
        summary: !csp.enforced && !csp.meta ? (csp.reportOnly ? 'CSP is report-only; nothing is enforced.' : 'No Content Security Policy at all.') : `CSP present but ${csp.problems.length} weakness(es).`,
        severity: worst,
        evidence: csp.problems.map((p) => ({ location: finalUrl, detail: `[${p.severity}] ${p.detail}` })).concat(csp.enforced ? [{ location: 'Content-Security-Policy', detail: csp.enforced.slice(0, 600) }] : [])
      }));
    }

    // ---- W5 Trusted Types
    if (!csp.trustedTypes) {
      findings.push(makeFinding('W5', {
        key: `W5:${finalUrl}`,
        summary: "require-trusted-types-for 'script' is not set.",
        severity: thirdParty.length ? 'medium' : 'low',
        evidence: [{ location: finalUrl, detail: 'DOM sinks (innerHTML, script.src, eval) accept arbitrary strings.' }]
      }));
    }

    // ---- W4 secrets readable by JS
    const hits: StorageHit[] = [];
    for (const [k, v] of dom.local) { const h = classifyStorage('localStorage', k, v); if (h) hits.push(h); }
    for (const [k, v] of dom.session) { const h = classifyStorage('sessionStorage', k, v); if (h) hits.push(h); }
    const cookieRows = cookies.map((c) => ({ name: c.name, domain: c.domain, httpOnly: c.httpOnly, secure: c.secure, sameSite: c.sameSite, expires: c.expires }));
    meta.cookies = cookieRows;
    meta.storageKeys = { localStorage: dom.local.map(([k]) => k), sessionStorage: dom.session.map(([k]) => k) };
    for (const c of cookies) {
      const sessionLike = COOKIE_SESSION_NAME.test(c.name) || KEYISH.test(c.name) || JWT.test(c.value);
      if (!sessionLike || /csrf|xsrf/i.test(c.name)) continue;
      const flags: string[] = [];
      if (!c.httpOnly) flags.push('no HttpOnly (document.cookie can read it)');
      if (!c.secure && pageIsHttps) flags.push('no Secure');
      if (c.sameSite === 'None' || !c.sameSite) flags.push(`SameSite=${c.sameSite ?? 'unset'}`);
      if (!c.httpOnly) hits.push({ store: 'cookie', name: c.name, kind: JWT.test(c.value) || c.value.length >= 16 ? 'session-token' : 'auth-ish', preview: mask(c.value, 6), flags });
    }
    for (const h of hits) {
      const sev: Severity = h.kind === 'key-material' ? 'critical' : h.kind === 'session-token' || h.kind === 'api-key' ? 'critical' : 'high';
      const what = h.kind === 'key-material' ? 'Wallet key material' : h.kind === 'api-key' ? 'An API key' : h.kind === 'session-token' ? 'A session token' : 'Credential-like data';
      findings.push(makeFinding('W4', {
        key: `W4:${h.store}:${h.name}`,
        summary: `${what} is readable by any script on the page (${h.store} "${h.name}").`,
        severity: sev,
        evidence: [{ location: `${h.store}: ${h.name}`, detail: `${h.flags.join('; ')}. Value preview: ${h.preview}` }],
        tags: [h.kind, h.store],
        extraSteps: h.kind === 'key-material' ? ['This is key material in web storage. Rotate the wallet now and move funds from a clean device.'] : []
      }));
    }
    if (!target.storageState && !hits.length) meta.sessionNote = 'Scanned without a login session. Export a Playwright storage state from your own logged-in browser and rescan to check what the app stores after login.';

    // ---- W6 baseline drift
    const baselineNow = buildBaseline(finalUrl, observations);
    meta.baselineCandidate = baselineNow;
    if (target.baseline) {
      const diff = diffBaseline(target.baseline, observations);
      meta.baselineDiff = diff;
      for (const c of diff.changed) {
        findings.push(makeFinding('W6', {
          key: `W6:changed:${c.url}`,
          summary: `${new URL(c.url).hostname} script content changed since the approved baseline.`,
          severity: c.thirdParty ? 'critical' : 'medium',
          evidence: [{ location: c.url, detail: `baseline sha256 ${c.before.slice(0, 16)}… → now ${c.after.slice(0, 16)}… (${c.bytesBefore} → ${c.bytesAfter} bytes)` }],
          tags: c.thirdParty ? ['third-party', 'drift'] : ['first-party', 'drift']
        }));
      }
      for (const n of diff.added) {
        findings.push(makeFinding('W6', {
          key: `W6:new:${n.url}`,
          summary: `New ${n.thirdParty ? 'third-party' : 'first-party'} script not in the approved baseline: ${new URL(n.url).hostname}.`,
          severity: n.thirdParty ? 'high' : 'low',
          evidence: [{ location: n.url, detail: `sha256 ${n.sha256?.slice(0, 16) ?? '?'}… · ${n.bytes} bytes` }],
          tags: ['drift', 'new-script']
        }));
      }
      if (diff.removed.length) {
        findings.push(makeFinding('W6', {
          key: `W6:removed:${finalUrl}`,
          summary: `${diff.removed.length} baseline script(s) no longer load.`,
          severity: 'info',
          evidence: diff.removed.map((r) => ({ location: r.url, detail: 'present in baseline, absent now' })),
          tags: ['drift']
        }));
      }
    } else {
      findings.push(makeFinding('W6', {
        key: `W6:nobaseline:${pageHost}`,
        summary: `No approved script baseline for ${pageHost} yet. Save one to detect the next vendor swap.`,
        severity: 'info',
        evidence: [{ location: finalUrl, detail: `${observations.length} script(s) observed (${thirdParty.length} third-party). Review them, then save as baseline.` }],
        tags: ['needs-baseline']
      }));
    }

    // ---- W7 headers
    if (pageIsHttps && !local) {
      const missing: string[] = [];
      if (!headers['strict-transport-security']) missing.push('Strict-Transport-Security');
      if (!headers['x-content-type-options']) missing.push('X-Content-Type-Options');
      if (!headers['referrer-policy']) missing.push('Referrer-Policy');
      if (!headers['permissions-policy']) missing.push('Permissions-Policy');
      if (!headers['x-frame-options'] && !csp.directives['frame-ancestors']) missing.push('X-Frame-Options / frame-ancestors');
      if (!headers['cross-origin-opener-policy']) missing.push('Cross-Origin-Opener-Policy');
      if (missing.length) {
        findings.push(makeFinding('W7', {
          key: `W7:${finalUrl}`,
          summary: `${missing.length} hardening header(s) missing: ${missing.join(', ')}.`,
          evidence: missing.map((m) => ({ location: finalUrl, detail: `${m} not set` }))
        }));
      }
    }
    meta.headers = pick(headers, ['content-security-policy', 'content-security-policy-report-only', 'strict-transport-security', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy', 'cross-origin-opener-policy', 'reporting-endpoints', 'report-to', 'server']);
    meta.consoleErrors = consoleErrors.slice(0, 20);
    onProgress('Web scan complete', 100);
  } catch (e: any) {
    errors.push(`web: ${e?.message ?? String(e)}`);
  } finally {
    await browser?.close().catch(() => {});
  }

  return {
    module: 'web',
    target: url,
    startedAt,
    finishedAt: new Date().toISOString(),
    findings: sortFindings(findings),
    score: scoreFindings(findings),
    meta,
    errors
  };
}

function pick(obj: Record<string, string>, keys: string[]) {
  const out: Record<string, string> = {};
  for (const k of keys) if (obj[k] != null) out[k] = obj[k];
  return out;
}
export function sevRank(s: Severity): number {
  return ({ critical: 4, high: 3, medium: 2, low: 1, info: 0 } as const)[s];
}
export function sortFindings(f: Finding[]): Finding[] {
  return [...f].sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || a.id.localeCompare(b.id));
}
