import { existsSync, readdirSync, statSync } from 'node:fs';
import { join, resolve, basename } from 'node:path';
import { parse as parseYaml } from 'yaml';
import type { Evidence, Finding, ModuleResult, Progress, RepoTarget, Severity } from '../types.js';
import { makeFinding } from '../knowledge/index.js';
import { readText, readJson, listRepoFiles, lineOf, gitTracked } from '../util/fs.js';
import { mask } from '../util/hash.js';
import { scoreFindings } from '../report/score.js';
import { sortFindings } from './web.js';

type PkgJson = { name?: string; dependencies?: Record<string, string>; devDependencies?: Record<string, string>; optionalDependencies?: Record<string, string>; scripts?: Record<string, string>; packageManager?: string; pnpm?: any; trustedDependencies?: string[]; workspaces?: string[] | { packages?: string[] } };

interface SecretPattern { name: string; re: RegExp; severity: Severity; files?: RegExp; kind: string }
const SECRET_PATTERNS: SecretPattern[] = [
  { name: 'npm access token', re: /\bnpm_[A-Za-z0-9]{36}\b/g, severity: 'critical', kind: 'npm-token' },
  { name: 'npm _authToken literal', re: /_authToken\s*=\s*(?!\$\{)([A-Za-z0-9._\-]{16,})/g, severity: 'critical', files: /\.(npmrc|yarnrc(\.yml)?)$/, kind: 'npm-token' },
  { name: 'GitHub token', re: /\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{80,})\b/g, severity: 'critical', kind: 'github-token' },
  { name: 'AWS access key id', re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, severity: 'critical', kind: 'aws-key' },
  { name: 'AWS secret access key', re: /aws_?secret_?access_?key\s*[=:]\s*["']?([A-Za-z0-9/+]{40})\b/gi, severity: 'critical', kind: 'aws-key' },
  { name: 'Slack token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, severity: 'high', kind: 'slack-token' },
  { name: 'Stripe live secret', re: /\bsk_live_[A-Za-z0-9]{16,}\b/g, severity: 'critical', kind: 'stripe-key' },
  { name: 'Private key block', re: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----/g, severity: 'critical', kind: 'private-key' },
  { name: 'EVM private key', re: /\b(PRIVATE_KEY|PRIV_KEY|DEPLOYER_KEY|DEPLOYER_PRIVATE_KEY|WALLET_KEY|SIGNER_KEY|HOT_WALLET_KEY)\s*[=:]\s*["']?(0x)?[0-9a-fA-F]{64}\b/g, severity: 'critical', kind: 'wallet-key' },
  { name: 'Mnemonic', re: /\b(MNEMONIC|SEED_PHRASE|SEED)\s*[=:]\s*["']?([a-z]+ ){11,23}[a-z]+["']?/g, severity: 'critical', kind: 'wallet-key' },
  { name: 'Google API key', re: /\bAIza[0-9A-Za-z_\-]{35}\b/g, severity: 'high', kind: 'google-key' },
  { name: 'Generic secret assignment in .env', re: /^(?!#)\s*([A-Z0-9_]*(SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|APIKEY|PRIVATE)[A-Z0-9_]*)\s*=\s*["']?([^\s"'#]{12,})/gm, severity: 'medium', files: /(^|\/)\.env(\.[^/]*)?$/, kind: 'env-secret' }
];
const SKIP_SECRET_FILES = /(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?|\.min\.(js|css)|\.map|\.(png|jpe?g|gif|webp|svg|ico|woff2?|ttf|eot|pdf|zip|gz|tgz|tar|mp4|mp3|wasm|jar|class|exe|dll|so|dylib))$/i;
const EXAMPLE_ENV = /\.env\.(example|sample|template|dist|defaults?)$/i;

export async function scanRepo(target: RepoTarget, onProgress: Progress = () => {}): Promise<ModuleResult> {
  const startedAt = new Date().toISOString();
  const root = resolve(target.path);
  const findings: Finding[] = [];
  const errors: string[] = [];
  const meta: Record<string, unknown> = { root };
  try {
    if (!existsSync(root) || !statSync(root).isDirectory()) throw new Error(`Not a directory: ${root}`);
    onProgress(`Reading ${root}`, 5);
    const pkg = readJson<PkgJson>(join(root, 'package.json'));
    const npmrc = readText(join(root, '.npmrc')) ?? '';
    const yarnrcYml = readText(join(root, '.yarnrc.yml')) ?? '';
    const pnpmWorkspace = readText(join(root, 'pnpm-workspace.yaml'));
    const pnpmWs = pnpmWorkspace ? safeYaml(pnpmWorkspace) : null;

    // ------------------------------------------------------------ lockfiles & package manager
    const lockfiles = ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lockb', 'bun.lock'].filter((f) => existsSync(join(root, f)));
    const pm = pkg?.packageManager?.split('@')[0] ?? (lockfiles.includes('pnpm-lock.yaml') ? 'pnpm' : lockfiles.includes('yarn.lock') ? 'yarn' : lockfiles.some((l) => l.startsWith('bun')) ? 'bun' : 'npm');
    meta.packageManager = pm; meta.lockfiles = lockfiles; meta.isNodeProject = !!pkg;

    // ------------------------------------------------------------ R1 install scripts
    onProgress('Checking install scripts and script policy', 15);
    const installScriptPkgs = new Map<string, string>(); // name -> source
    const lock = readJson<any>(join(root, 'package-lock.json')) ?? readJson<any>(join(root, 'npm-shrinkwrap.json'));
    if (lock?.packages) {
      for (const [p, info] of Object.entries<any>(lock.packages)) {
        if (p && info?.hasInstallScript) installScriptPkgs.set(p.replace(/^.*node_modules\//, ''), 'package-lock.json (hasInstallScript)');
      }
    }
    if (existsSync(join(root, 'pnpm-lock.yaml'))) {
      const pl = safeYaml(readText(join(root, 'pnpm-lock.yaml'), 50_000_000) ?? '');
      for (const [p, info] of Object.entries<any>(pl?.packages ?? {})) if (info?.requiresBuild) installScriptPkgs.set(p.replace(/^\//, '').replace(/@[^@/]+$/, (m) => m), 'pnpm-lock.yaml (requiresBuild)');
    }
    const nm = join(root, 'node_modules');
    let walkedNodeModules = 0;
    if (existsSync(nm)) {
      const dirs: string[] = [];
      for (const e of safeReaddir(nm)) {
        if (e.startsWith('.')) continue;
        if (e.startsWith('@')) for (const s of safeReaddir(join(nm, e))) dirs.push(join(e, s));
        else dirs.push(e);
      }
      for (const d of dirs.slice(0, 6000)) {
        const pj = readJson<PkgJson>(join(nm, d, 'package.json'));
        walkedNodeModules++;
        const sc = pj?.scripts ?? {};
        const hooks = ['preinstall', 'install', 'postinstall'].filter((h) => sc[h]);
        if (hooks.length) installScriptPkgs.set(pj?.name ?? d.replace(/\\/g, '/'), `node_modules (${hooks.join(', ')}: ${hooks.map((h) => sc[h]).join(' && ').slice(0, 120)})`);
      }
    }
    const policy: string[] = [];
    if (/^\s*ignore-scripts\s*=\s*true/m.test(npmrc)) policy.push('.npmrc ignore-scripts=true');
    if (/^\s*enableScripts\s*:\s*false/m.test(yarnrcYml)) policy.push('.yarnrc.yml enableScripts: false');
    const onlyBuilt = pnpmWs?.onlyBuiltDependencies ?? pkg?.pnpm?.onlyBuiltDependencies;
    if (Array.isArray(onlyBuilt)) policy.push(`pnpm onlyBuiltDependencies allowlist (${onlyBuilt.length})`);
    if (Array.isArray(pkg?.trustedDependencies) || pm === 'bun') policy.push(pm === 'bun' ? 'bun blocks lifecycle scripts by default' : 'bun trustedDependencies allowlist');
    meta.installScriptPolicy = policy; meta.installScriptPackages = [...installScriptPkgs.entries()].map(([name, source]) => ({ name, source }));
    if (pkg) {
      const list = [...installScriptPkgs.entries()];
      const ev: Evidence[] = list.slice(0, 25).map(([name, source]) => ({ location: name, detail: source }));
      if (!policy.length) {
        ev.unshift({ location: '.npmrc', detail: existsSync(join(root, '.npmrc')) ? 'present but no ignore-scripts=true' : 'missing (no ignore-scripts policy)' });
        findings.push(makeFinding('R1', {
          key: 'R1:policy',
          summary: list.length
            ? `${list.length} dependenc${list.length === 1 ? 'y runs' : 'ies run'} install scripts and nothing blocks them (${pm}).`
            : `No install-script policy. Any new dependency can run code on install (${pm}).${!lock && !existsSync(nm) ? ' Install-script inventory needs a lockfile or node_modules.' : ''}`,
          severity: list.length ? 'high' : 'medium',
          evidence: ev
        }));
      } else if (list.length) {
        findings.push(makeFinding('R1', {
          key: 'R1:allowlisted',
          summary: `${list.length} dependenc${list.length === 1 ? 'y has' : 'ies have'} install scripts; a script policy is in place (${policy.join(', ')}). Confirm each one is intentionally allowlisted.`,
          severity: 'low',
          evidence: ev
        }));
      }
    }

    // ------------------------------------------------------------ R7 registry proxy / release age
    if (pkg) {
      const registryLine = npmrc.match(/^\s*registry\s*=\s*(\S+)/m)?.[1];
      const proxy = registryLine && !/registry\.npmjs\.org/.test(registryLine);
      const minAge = /^\s*minimum-release-age\s*=\s*\d+/m.test(npmrc) || pnpmWs?.minimumReleaseAge || pkg?.pnpm?.minimumReleaseAge;
      meta.registry = { registry: registryLine ?? 'https://registry.npmjs.org/ (default)', proxy: !!proxy, minimumReleaseAge: !!minAge };
      if (!proxy || !minAge) {
        findings.push(makeFinding('R7', {
          key: 'R7:registry',
          summary: !proxy && !minAge ? 'Installs come straight from the public registry with no minimum release age.' : !proxy ? 'A minimum release age is set but installs still go straight to the public registry.' : 'A registry proxy is configured but no minimum release age.',
          severity: !proxy && !minAge ? 'medium' : 'low',
          evidence: [{ location: '.npmrc', detail: `registry: ${registryLine ?? 'default public'}; minimum release age: ${minAge ? 'set' : 'not set'}` }]
        }));
      }
    }

    // ------------------------------------------------------------ R2 lockfile / ranges / CI install
    onProgress('Checking lockfile discipline', 30);
    const workflowDir = join(root, '.github', 'workflows');
    const workflowFiles = existsSync(workflowDir) ? safeReaddir(workflowDir).filter((f) => /\.ya?ml$/.test(f)).map((f) => join(workflowDir, f)) : [];
    const workflows = workflowFiles.map((f) => ({ path: f, rel: f.slice(root.length + 1).replace(/\\/g, '/'), text: readText(f) ?? '', doc: safeYaml(readText(f) ?? '') }));
    meta.workflows = workflows.map((w) => w.rel);
    if (pkg) {
      const ev: Evidence[] = [];
      let sev: Severity = 'low';
      if (!lockfiles.length) { ev.push({ location: 'package.json', detail: 'No lockfile (package-lock.json / pnpm-lock.yaml / yarn.lock) found.' }); sev = 'high'; }
      if (/^\s*package-lock\s*=\s*false/m.test(npmrc)) { ev.push({ location: '.npmrc', detail: 'package-lock=false disables lockfile generation.', line: lineOf(npmrc, 'package-lock') }); sev = 'high'; }
      const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}), ...(pkg.optionalDependencies ?? {}) };
      const pkgText = readText(join(root, 'package.json')) ?? '';
      for (const [n, r] of Object.entries(deps)) {
        if (/^(\*|latest|x|>=.*)$/.test(r.trim()) || /^(git(\+\w+)?:|https?:|github:)/.test(r) || /\/.+#/.test(r)) {
          ev.push({ location: 'package.json', detail: `"${n}": "${r}" resolves to anything${/^(git|https?|github)/.test(r) ? ' (URL dependency: no registry provenance)' : ''}`, line: lineOf(pkgText, `"${n}"`) });
          if (sev === 'low') sev = 'medium';
        }
      }
      for (const w of workflows) {
        const lines = w.text.split(/\r?\n/);
        lines.forEach((l, i) => {
          if (/\bnpm\s+(install|i)\b(?!.*(-g|--global|--no-save))/.test(l) && !/npm ci/.test(l)) { ev.push({ location: w.rel, detail: `CI runs "${l.trim().slice(0, 100)}" instead of npm ci (lockfile may be rewritten).`, line: i + 1 }); if (sev === 'low') sev = 'medium'; }
          if (/\byarn\s+(install)?\b/.test(l) && /yarn( install)?\s*$/.test(l.trim()) && !/--(immutable|frozen-lockfile)/.test(l)) { ev.push({ location: w.rel, detail: `CI runs "${l.trim()}" without --immutable / --frozen-lockfile.`, line: i + 1 }); if (sev === 'low') sev = 'medium'; }
        });
      }
      if (ev.length) findings.push(makeFinding('R2', { key: 'R2:lockfile', summary: !lockfiles.length ? 'No lockfile: every install resolves fresh.' : `${ev.length} lockfile-discipline issue(s).`, severity: sev, evidence: ev }));
    }

    // ------------------------------------------------------------ R3 / R4 / R6 / R8 workflows
    onProgress('Checking GitHub Actions workflows', 45);
    const unpinned: Evidence[] = [];
    let unpinnedThirdParty = 0;
    const staticKeys: Evidence[] = [];
    const dangerous: Evidence[] = [];
    const perms: Evidence[] = [];
    let oidcSeen = false;
    for (const w of workflows) {
      const lines = w.text.split(/\r?\n/);
      const triggers = triggerNames(w.doc);
      lines.forEach((l, i) => {
        const m = l.match(/^\s*-?\s*uses:\s*["']?([^\s"'#]+)/);
        if (m) {
          const ref = m[1];
          if (!ref.startsWith('./') && !ref.startsWith('docker://')) {
            const [repoPart, version] = ref.split('@');
            if (!version || !/^[0-9a-f]{40}$/i.test(version)) {
              const org = repoPart.split('/')[0];
              const firstParty = org === 'actions' || org === 'github';
              if (!firstParty) unpinnedThirdParty++;
              unpinned.push({ location: w.rel, line: i + 1, detail: `${ref} — ${version ? `mutable ref "${version}"` : 'no ref'}${firstParty ? ' (GitHub-owned; lower risk, still pin)' : ''}` });
            }
          }
        }
        if (/\b(aws-access-key-id|aws-secret-access-key)\s*:/.test(l) || /\bAWS_SECRET_ACCESS_KEY\s*:/.test(l)) staticKeys.push({ location: w.rel, line: i + 1, detail: `AWS static credential: ${l.trim().slice(0, 100)}` });
        if (/\b(credentials_json|service_account_key|GOOGLE_CREDENTIALS|GCP_SA_KEY)\s*:/.test(l)) staticKeys.push({ location: w.rel, line: i + 1, detail: `GCP service-account key: ${l.trim().slice(0, 100)}` });
        if (/\b(creds|client-secret|AZURE_CREDENTIALS|AZURE_CLIENT_SECRET)\s*:/.test(l)) staticKeys.push({ location: w.rel, line: i + 1, detail: `Azure static credential: ${l.trim().slice(0, 100)}` });
        if (/\b(NPM_TOKEN|NODE_AUTH_TOKEN)\s*:\s*\$\{\{\s*secrets\./.test(l)) staticKeys.push({ location: w.rel, line: i + 1, detail: `Long-lived npm token in CI (prefer npm trusted publishing via OIDC): ${l.trim().slice(0, 100)}` });
        if (/role-to-assume|workload_identity_provider|id-token:\s*write/.test(l)) oidcSeen = true;
        if (triggers.includes('pull_request_target') && /ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)/.test(l)) dangerous.push({ location: w.rel, line: i + 1, detail: 'pull_request_target workflow checks out the PR head: untrusted code runs with repository secrets.' });
        if (triggers.some((t) => ['pull_request_target', 'issue_comment', 'issues', 'discussion', 'discussion_comment', 'workflow_run', 'pull_request_review', 'pull_request_review_comment'].includes(t)) && /\$\{\{\s*github\.event\.(issue|pull_request|comment|review|discussion)\.[^}]*(title|body|head\.ref|head_ref|label\.name|user\.login)/.test(l) && /^\s*(run:|-\s*run:|\s+\S)/.test(l) && !/^\s*[A-Z_]+:\s*\$\{\{/.test(l)) dangerous.push({ location: w.rel, line: i + 1, detail: `Event-controlled text interpolated into a shell line: ${l.trim().slice(0, 100)}` });
      });
      const p = w.doc?.permissions;
      if (p === 'write-all') perms.push({ location: w.rel, line: lineOf(w.text, 'write-all'), detail: 'permissions: write-all' });
      else if (p == null && /secrets\./.test(w.text)) perms.push({ location: w.rel, detail: 'No top-level permissions block (GITHUB_TOKEN gets the repository default, often write).' });
    }
    meta.oidc = oidcSeen;
    if (unpinned.length) findings.push(makeFinding('R4', { key: 'R4:actions', summary: `${unpinned.length} action reference(s) pinned by tag or branch (${unpinnedThirdParty} third-party).`, severity: unpinnedThirdParty ? 'high' : 'medium', evidence: unpinned.slice(0, 40) }));
    if (staticKeys.length) findings.push(makeFinding('R3', { key: 'R3:static-keys', summary: `${staticKeys.length} static credential reference(s) in CI${oidcSeen ? ' (OIDC is also used elsewhere; finish the migration)' : ''}.`, evidence: staticKeys.slice(0, 40) }));
    if (dangerous.length) findings.push(makeFinding('R6', { key: 'R6:workflows', summary: `${dangerous.length} dangerous workflow pattern(s).`, evidence: dangerous.slice(0, 40) }));
    if (perms.length) findings.push(makeFinding('R8', { key: 'R8:permissions', summary: `${perms.length} workflow(s) with broad or default token permissions.`, evidence: perms.slice(0, 40) }));

    // ------------------------------------------------------------ R5 committed secrets
    onProgress('Scanning for committed tokens and keys', 60);
    const { files, usedGit } = listRepoFiles(root);
    meta.filesScanned = files.length; meta.usedGit = usedGit;
    const secretEv: Evidence[] = [];
    const kinds = new Set<string>();
    let worst: Severity = 'low';
    const RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    for (const rel of files) {
      if (SKIP_SECRET_FILES.test(rel)) continue;
      const full = join(root, rel);
      const text = readText(full, 1_000_000);
      if (text == null || text.includes('\u0000')) continue;
      const isExample = EXAMPLE_ENV.test(rel) || /example|sample|fixture|test|spec|mock/i.test(basename(rel)) && !/\.env$/.test(rel);
      for (const pat of SECRET_PATTERNS) {
        if (pat.files && !pat.files.test(rel)) continue;
        if (pat.kind === 'env-secret' && isExample) continue;
        pat.re.lastIndex = 0;
        let m: RegExpExecArray | null;
        let count = 0;
        while ((m = pat.re.exec(text)) && count < 5) {
          count++;
          const line = text.slice(0, m.index).split('\n').length;
          const sev: Severity = isExample && pat.kind !== 'env-secret' ? 'medium' : pat.severity;
          if (RANK[sev] > RANK[worst]) worst = sev;
          kinds.add(pat.kind);
          secretEv.push({ location: rel, line, detail: `${pat.name}${isExample ? ' (in an example/test file; still rotate if real)' : ''}: ${mask(m[0].replace(/\s+/g, ' '), 8)}` });
        }
      }
    }
    for (const envName of ['.env', '.env.local', '.env.production']) {
      const tracked = gitTracked(root, envName);
      if (existsSync(join(root, envName)) && tracked !== false) {
        secretEv.push({ location: envName, detail: tracked ? 'committed to git' : 'present (no git; make sure it is ignored)' });
        if (RANK['high'] > RANK[worst]) worst = 'high';
        kinds.add('env-file');
      }
    }
    if (secretEv.length) {
      const rotate: string[] = [];
      if (kinds.has('npm-token')) rotate.push('npm token: revoke at npmjs.com → Access Tokens, then check your packages for versions you did not publish.');
      if (kinds.has('github-token')) rotate.push('GitHub token: revoke in Settings → Developer settings; review the audit log for use.');
      if (kinds.has('aws-key')) rotate.push('AWS key: deactivate in IAM, check CloudTrail for its activity, then delete it.');
      if (kinds.has('wallet-key') || kinds.has('private-key')) rotate.push('Private key / mnemonic: move funds to a new wallet from a clean device; the key is burned.');
      findings.push(makeFinding('R5', {
        key: 'R5:secrets',
        summary: `${secretEv.length} secret-looking value(s) in the tree (${[...kinds].join(', ')}).`,
        severity: worst,
        evidence: secretEv.slice(0, 60),
        extraSteps: rotate
      }));
    }

    // ------------------------------------------------------------ own lifecycle scripts (informational, tagged on R1)
    if (pkg?.scripts) {
      const own = ['preinstall', 'install', 'postinstall', 'prepare'].filter((h) => pkg.scripts![h]);
      const netty = own.filter((h) => /(curl|wget|Invoke-WebRequest|iwr|bash -c|sh -c|\| *sh|\| *bash)/.test(pkg.scripts![h]));
      meta.ownLifecycleScripts = own.map((h) => ({ hook: h, command: pkg.scripts![h] }));
      if (netty.length) findings.push(makeFinding('R1', {
        key: 'R1:own-scripts',
        summary: `This package's own ${netty.join('/')} script downloads or pipes to a shell.`,
        severity: 'medium',
        evidence: netty.map((h) => ({ location: 'package.json', detail: `${h}: ${pkg.scripts![h]}`, line: lineOf(readText(join(root, 'package.json')) ?? '', `"${h}"`) })),
        tags: ['own-package']
      }));
    }
    if (!pkg) meta.note = 'No package.json at this path. Only workflow and secret checks ran.';
    onProgress('Repo scan complete', 100);
  } catch (e: any) {
    errors.push(`repo: ${e?.message ?? String(e)}`);
  }
  return { module: 'repo', target: root, startedAt, finishedAt: new Date().toISOString(), findings: sortFindings(findings), score: scoreFindings(findings), meta, errors };
}

function safeYaml(text: string): any {
  try { return parseYaml(text, { uniqueKeys: false }); } catch { return null; }
}
function safeReaddir(dir: string): string[] {
  try { return readdirSync(dir); } catch { return []; }
}
function triggerNames(doc: any): string[] {
  const on = doc?.on ?? doc?.[true as any];
  if (!on) return [];
  if (typeof on === 'string') return [on];
  if (Array.isArray(on)) return on.map(String);
  if (typeof on === 'object') return Object.keys(on);
  return [];
}
