const TWO_LEVEL_TLDS = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'co.jp', 'ne.jp', 'or.jp', 'com.au', 'net.au', 'org.au', 'co.nz',
  'co.in', 'com.br', 'com.mx', 'com.sg', 'co.za', 'com.ar', 'com.tr', 'co.kr', 'com.cn', 'com.hk', 'com.tw', 'co.id', 'com.my'
]);

export function isLocalHost(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, '');
  return (
    h === 'localhost' || h.endsWith('.localhost') || h === '0.0.0.0' || h === '::1' ||
    /^127\./.test(h) || /^10\./.test(h) || /^192\.168\./.test(h) || /^172\.(1[6-9]|2\d|3[01])\./.test(h) || /^\d+\.\d+\.\d+\.\d+$/.test(h)
  );
}

export function registrableDomain(host: string): string {
  const h = host.toLowerCase();
  if (isLocalHost(h)) return h;
  const parts = h.split('.');
  if (parts.length <= 2) return h;
  const lastTwo = parts.slice(-2).join('.');
  if (TWO_LEVEL_TLDS.has(lastTwo)) return parts.slice(-3).join('.');
  return lastTwo;
}

/** First-party = same registrable domain. For localhost / IPs, same origin (port matters). */
export function isThirdParty(pageUrl: string, scriptUrl: string, extraFirstParty: string[] = []): boolean {
  let p: URL, s: URL;
  try { p = new URL(pageUrl); s = new URL(scriptUrl); } catch { return true; }
  if (isLocalHost(p.hostname) || isLocalHost(s.hostname)) return p.origin !== s.origin;
  const pd = registrableDomain(p.hostname);
  const sd = registrableDomain(s.hostname);
  if (pd === sd) return false;
  return !extraFirstParty.some((d) => sd === registrableDomain(d) || s.hostname === d.toLowerCase());
}

export interface HostCategory { category: string; risk: 'critical' | 'high' | 'medium' | 'low'; note: string }

const CATEGORIES: Array<{ match: RegExp; cat: HostCategory }> = [
  { match: /(^|\.)polyfill\.io$/, cat: { category: 'known-compromised host', risk: 'critical', note: 'polyfill.io served malicious code to 100k+ sites in 2024. Remove.' } },
  { match: /(^|\.)debugbear\.com$/, cat: { category: 'performance monitoring', risk: 'high', note: 'The vendor involved in the Polymarket incident (29 Oct 2026). Pin, SRI, and keep off trading pages.' } },
  { match: /(^|\.)googletagmanager\.com$/, cat: { category: 'tag manager (remote-configured loader)', risk: 'high', note: 'Loads whatever the container config says. Cannot be integrity-checked.' } },
  { match: /(^|\.)segment\.(com|io)$/, cat: { category: 'tag manager (remote-configured loader)', risk: 'high', note: 'Remote-configured destinations load arbitrary scripts.' } },
  { match: /(^|\.)(tealiumiq|ensighten|adobedtm|launch\.adobe)\.com$/, cat: { category: 'tag manager (remote-configured loader)', risk: 'high', note: 'Remote-configured loader.' } },
  { match: /(^|\.)(hotjar|fullstory|logrocket|mouseflow|smartlook|clarity\.ms|contentsquare|heap\.io|heapanalytics)\.(com|io|ms|net)$|clarity\.ms$/, cat: { category: 'session replay (records DOM and input)', risk: 'high', note: 'Session replay ships what users type and see to a third party.' } },
  { match: /(^|\.)(intercom(cdn)?|crisp\.chat|zdassets|zendesk|hubspot|hs-scripts|drift|tawk\.to|freshchat|livechatinc)\.(com|chat|to|io)$/, cat: { category: 'chat / support widget', risk: 'medium', note: 'Full DOM access; move to a sandboxed iframe.' } },
  { match: /(^|\.)(google-analytics|googleadservices|doubleclick|googlesyndication|facebook|connect\.facebook\.net|snap|tiktok|twitter|ads-twitter|linkedin|licdn|bing|criteo|taboola|outbrain)\.(com|net)$/, cat: { category: 'analytics / advertising', risk: 'medium', note: 'No place on authenticated or signing pages.' } },
  { match: /(^|\.)(cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|esm\.sh|skypack\.dev)$/, cat: { category: 'public package CDN', risk: 'medium', note: 'Fine if pinned to a version with SRI; dangerous as "latest".' } },
  { match: /(^|\.)(sentry-cdn|browser\.sentry-cdn|datadoghq|dd-browser|newrelic|nr-data|bugsnag|rollbar|speedcurve|raygun)\.(com|net|io)$/, cat: { category: 'error / performance monitoring', risk: 'medium', note: 'Observability SDKs see request bodies and DOM; pin and SRI.' } },
  { match: /(^|\.)(static\.cloudflareinsights\.com|plausible\.io|umami\.is|posthog\.com|i\.posthog\.com|us\.i\.posthog\.com|mixpanel|amplitude)\.(com|io|is)$|cloudflareinsights\.com$|plausible\.io$|posthog\.com$/, cat: { category: 'analytics', risk: 'low', note: 'Prefer self-hosting or a server-side integration on sensitive pages.' } },
  { match: /(^|\.)(recaptcha|gstatic|hcaptcha|challenges\.cloudflare)\.(com|net)$|hcaptcha\.com$/, cat: { category: 'bot protection', risk: 'low', note: 'Usually necessary; isolate on the pages that need it.' } },
  { match: /(^|\.)(js\.stripe\.com|checkout\.stripe\.com|pay\.google\.com|applepay\.cdn-apple\.com|moonpay|transak|ramp\.network)\b/, cat: { category: 'payments / on-ramp', risk: 'medium', note: 'Pin and SRI; confirm the vendor serves immutable versions.' } },
  { match: /(^|\.)(walletconnect|reown|web3modal|rainbow\.me|coinbase|metamask\.io|safe\.global)\.(com|org|me|io|global)$|walletconnect\.(com|org)$|safe\.global$/, cat: { category: 'wallet connector', risk: 'high', note: 'This script talks to the signer. Self-host a pinned build; Bybit was drained through a tampered Safe{Wallet} bundle.' } }
];

export function categorizeHost(host: string): HostCategory | null {
  const h = host.toLowerCase();
  for (const { match, cat } of CATEGORIES) if (match.test(h)) return cat;
  return null;
}

export function isAddressLike(s: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(s.trim());
}
