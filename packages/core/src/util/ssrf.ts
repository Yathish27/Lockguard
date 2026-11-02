import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

/** Private, loopback, link-local and cloud-metadata ranges that a hosted scanner must refuse. */
function isPrivateIPv4(ip: string): boolean {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n))) return true;
  const [a, b] = p;
  return (
    a === 0 || a === 10 || a === 127 ||
    (a === 169 && b === 254) ||            // link-local + cloud metadata (169.254.169.254)
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) ||  // CGNAT
    a >= 224                                // multicast / reserved
  );
}
function isPrivateIPv6(ip: string): boolean {
  const l = ip.toLowerCase();
  if (l === '::1' || l === '::') return true;
  if (l.startsWith('fe80') || l.startsWith('fc') || l.startsWith('fd')) return true; // link-local, unique-local
  if (l.startsWith('::ffff:')) return isPrivateIPv4(l.slice(7));                       // IPv4-mapped
  return false;
}
export function isPrivateAddress(ip: string): boolean {
  const v = isIP(ip);
  return v === 4 ? isPrivateIPv4(ip) : v === 6 ? isPrivateIPv6(ip) : true;
}

export interface UrlCheck { ok: boolean; reason?: string }

/**
 * For a publicly hosted scanner: allow only http(s) to a public host.
 * Resolves the hostname and rejects if any resolved address is private/internal,
 * which blocks SSRF to cloud metadata and internal services.
 */
export async function assertPublicUrl(raw: string): Promise<UrlCheck> {
  let u: URL;
  try { u = new URL(raw); } catch { return { ok: false, reason: 'Not a valid URL.' }; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return { ok: false, reason: 'Only http(s) URLs are allowed.' };
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (/^(localhost|.*\.localhost)$/i.test(host)) return { ok: false, reason: 'localhost is not allowed on the hosted scanner. Run Lockguard locally to scan internal hosts you own.' };
  if (isIP(host)) { if (isPrivateAddress(host)) return { ok: false, reason: 'Private / internal IP addresses are not allowed on the hosted scanner.' }; return { ok: true }; }
  let addrs: { address: string }[] = [];
  try { addrs = await lookup(host, { all: true }); } catch { return { ok: false, reason: `Could not resolve ${host}.` }; }
  if (!addrs.length) return { ok: false, reason: `Could not resolve ${host}.` };
  for (const a of addrs) if (isPrivateAddress(a.address)) return { ok: false, reason: `${host} resolves to a private/internal address; not allowed on the hosted scanner.` };
  return { ok: true };
}
