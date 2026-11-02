// Bake the knowledge base into the UI so the static (no-backend) build still has incidents,
// kill chains and the full rule catalog. Run before the Vite build.
import { INCIDENT_LIST, KILL_CHAINS, RULE_LIST, VERSION } from '@lockguard/core';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const out = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'packages', 'ui', 'src', 'generated', 'knowledge.json');
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, JSON.stringify({ incidents: INCIDENT_LIST, killChains: KILL_CHAINS, rules: RULE_LIST, version: VERSION }));
console.log('wrote', out);
