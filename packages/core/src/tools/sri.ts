import { createHash } from 'node:crypto';

export interface SriResult { url: string; bytes: number; contentType: string | null; sha256: string; sha384: string; sha512: string; corsHeader: string | null; cacheControl: string | null; tag: string; warnings: string[] }

export async function computeSri(url: string, opts: { maxBytes?: number; timeoutMs?: number } = {}): Promise<SriResult> {
  const u = new URL(url);
  if (!/^https?:$/.test(u.protocol)) throw new Error('Only http(s) URLs');
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), opts.timeoutMs ?? 20_000);
  try {
    const res = await fetch(u, { signal: ctrl.signal, redirect: 'follow', headers: { 'user-agent': 'Safetyfirst/0.1 SRI generator' } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length > (opts.maxBytes ?? 15_000_000)) throw new Error('File too large');
    const h = (a: string) => `${a}-${createHash(a).update(buf).digest('base64')}`;
    const cors = res.headers.get('access-control-allow-origin');
    const warnings: string[] = [];
    if (!cors) warnings.push('No Access-Control-Allow-Origin header: browsers require CORS for SRI on cross-origin scripts. Ask the vendor, or self-host.');
    if (!/\/\d+\.\d+|@\d+\.\d+|v\d+\.\d+|[a-f0-9]{8,}/i.test(u.pathname)) warnings.push('The URL does not look version-pinned. SRI on a mutable URL will break the moment the vendor ships an update (which is the point), so pin a version.');
    const cc = res.headers.get('cache-control');
    return { url: res.url, bytes: buf.length, contentType: res.headers.get('content-type'), sha256: h('sha256'), sha384: h('sha384'), sha512: h('sha512'), corsHeader: cors, cacheControl: cc, tag: `<script src="${res.url}" integrity="${h('sha384')}" crossorigin="anonymous"></script>`, warnings };
  } finally {
    clearTimeout(t);
  }
}
