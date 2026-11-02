import { createServer, type Server } from 'node:http';
import { createLabApp, type Mode } from './app.js';
import { createVendorApp } from './vendor.js';

export { createLabApp } from './app.js';
export type { Mode } from './app.js';
export { createVendorApp, BENIGN_ANALYTICS, MALICIOUS_ANALYTICS, benignSri } from './vendor.js';

export interface LabHandle { vulnerable: string; hardened: string; vendor: string; close: () => void }

/**
 * Start the lab: a vulnerable build, a hardened build, and a cross-origin "vendor CDN".
 * Default ports 4478 (vulnerable), 4479 (hardened), 4480 (vendor).
 */
export async function startLab(opts: { vulnPort?: number; hardPort?: number; vendorPort?: number; host?: string } = {}): Promise<LabHandle> {
  const host = opts.host ?? '127.0.0.1';
  const vulnPort = opts.vulnPort ?? Number(process.env.LAB_VULN_PORT ?? 4478);
  const hardPort = opts.hardPort ?? Number(process.env.LAB_HARD_PORT ?? 4479);
  const vendorPort = opts.vendorPort ?? Number(process.env.LAB_VENDOR_PORT ?? 4480);
  const urls = { vulnerable: `http://${host}:${vulnPort}`, hardened: `http://${host}:${hardPort}`, vendor: `http://${host}:${vendorPort}` };

  const vendor = createVendorApp();
  const servers: Server[] = [];
  const listen = (app: import('express').Express, port: number) => new Promise<void>((resolve, reject) => { const s = createServer(app); s.on('error', reject); s.listen(port, host, resolve); servers.push(s); });
  const vuln = createLabApp('vulnerable', { siblingUrl: urls.hardened, vendorUrl: urls.vendor, appOrigin: urls.vulnerable });
  const hard = createLabApp('hardened', { siblingUrl: urls.vulnerable, vendorUrl: urls.vendor, appOrigin: urls.hardened });
  await Promise.all([listen(vendor.app, vendorPort), listen(vuln, vulnPort), listen(hard, hardPort)]);
  return { ...urls, close: () => servers.forEach((s) => s.close()) };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  startLab().then((l) => {
    console.log(`\n  Lockguard lab`);
    console.log(`    vulnerable build : ${l.vulnerable}`);
    console.log(`    hardened build   : ${l.hardened}`);
    console.log(`    vendor CDN       : ${l.vendor}  (flip this to "compromised" from either build)\n`);
    console.log('  Everything is local. No real funds, no real keys, no real drainer code.\n');
  }).catch((e) => { console.error(e); process.exit(1); });
}
