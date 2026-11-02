import { Router } from 'express';
import { startLab, type LabHandle } from '@safetyfirst/lab';

/** Lets the Safetyfirst UI start the lab on demand and link to both builds + the vendor CDN. */
export function labRouter(): Router {
  const r = Router();
  let lab: LabHandle | null = null;
  let starting: Promise<void> | null = null;

  r.get('/status', (_req, res) => res.json({ running: !!lab, vulnerable: lab?.vulnerable ?? null, hardened: lab?.hardened ?? null, vendor: lab?.vendor ?? null }));
  r.post('/start', async (_req, res) => {
    try {
      if (!lab && !starting) starting = (async () => { lab = await startLab(); })().finally(() => { starting = null; });
      if (starting) await starting;
      res.json({ running: true, vulnerable: lab!.vulnerable, hardened: lab!.hardened, vendor: lab!.vendor });
    } catch (e: unknown) {
      res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
    }
  });
  r.post('/stop', (_req, res) => { lab?.close(); lab = null; res.json({ running: false }); });
  return r;
}
