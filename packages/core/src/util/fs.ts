import { readdirSync, statSync, readFileSync, existsSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { execFileSync } from 'node:child_process';

export const DEFAULT_IGNORE_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'out', '.next', '.nuxt', '.turbo', 'coverage', '.cache', '.parcel-cache', 'vendor', '.venv', 'venv', '__pycache__', '.safetyfirst', 'target']);

export function readText(path: string, maxBytes = 1_000_000): string | null {
  try {
    const st = statSync(path);
    if (!st.isFile() || st.size > maxBytes) return null;
    return readFileSync(path, 'utf8');
  } catch {
    return null;
  }
}

export function readJson<T = unknown>(path: string): T | null {
  const t = readText(path, 50_000_000);
  if (t == null) return null;
  try { return JSON.parse(t) as T; } catch { return null; }
}

export function loadIgnorePatterns(root: string): string[] {
  const t = readText(join(root, '.safetyfirstignore'));
  if (!t) return [];
  return t.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
}

function globToRegex(glob: string): RegExp {
  const esc = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*\*/g, '§§').replace(/\*/g, '[^/]*').replace(/§§/g, '.*').replace(/\?/g, '.');
  return new RegExp(`^${esc}`);
}

export function isIgnored(relPath: string, patterns: string[]): boolean {
  const p = relPath.split(sep).join('/');
  return patterns.some((pat) => {
    const clean = pat.replace(/^\.?\//, '').replace(/\/$/, '');
    if (!clean) return false;
    if (p === clean || p.startsWith(clean + '/')) return true;
    return globToRegex(clean).test(p);
  });
}

/** Files to consider: tracked + untracked-but-not-ignored if git is available, else a filtered walk. */
export function listRepoFiles(root: string, maxFiles = 20_000): { files: string[]; usedGit: boolean } {
  const patterns = loadIgnorePatterns(root);
  if (existsSync(join(root, '.git'))) {
    try {
      const out = execFileSync('git', ['-C', root, 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], { maxBuffer: 64 * 1024 * 1024 });
      const files = out.toString('utf8').split('\0').filter(Boolean).filter((f) => !isIgnored(f, patterns)).slice(0, maxFiles);
      return { files, usedGit: true };
    } catch {
      /* fall through */
    }
  }
  const files: string[] = [];
  const walk = (dir: string) => {
    if (files.length >= maxFiles) return;
    let entries: string[] = [];
    try { entries = readdirSync(dir); } catch { return; }
    for (const e of entries) {
      const full = join(dir, e);
      const rel = relative(root, full);
      if (isIgnored(rel, patterns)) continue;
      let st; try { st = statSync(full); } catch { continue; }
      if (st.isDirectory()) { if (!DEFAULT_IGNORE_DIRS.has(e)) walk(full); }
      else if (st.isFile()) files.push(rel);
      if (files.length >= maxFiles) return;
    }
  };
  walk(root);
  return { files, usedGit: false };
}

export function lineOf(text: string, needle: string | RegExp, from = 0): number | undefined {
  const lines = text.split(/\r?\n/);
  for (let i = from; i < lines.length; i++) {
    if (typeof needle === 'string' ? lines[i].includes(needle) : needle.test(lines[i])) return i + 1;
  }
  return undefined;
}

export function gitTracked(root: string, rel: string): boolean | null {
  if (!existsSync(join(root, '.git'))) return null;
  try {
    execFileSync('git', ['-C', root, 'ls-files', '--error-unmatch', rel], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}
