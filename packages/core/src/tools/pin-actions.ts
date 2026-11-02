export interface PinChange { line: number; from: string; to: string; comment?: string; error?: string }
export interface PinResult { yaml: string; changes: PinChange[] }

const USES_RE = /^(\s*-?\s*uses:\s*["']?)([^\s"'#@]+)@([^\s"'#]+)(["']?)(\s*(#.*)?)$/;

/** Rewrite `uses: owner/repo@tag` to `uses: owner/repo@<sha> # tag` by resolving refs through the GitHub API. */
export async function pinActions(yaml: string, opts: { token?: string; fetchImpl?: typeof fetch } = {}): Promise<PinResult> {
  const f = opts.fetchImpl ?? fetch;
  const cache = new Map<string, Promise<string>>();
  const headers: Record<string, string> = { accept: 'application/vnd.github+json', 'user-agent': 'Lockguard/0.1 action pinner', 'x-github-api-version': '2022-11-28' };
  const token = opts.token ?? process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;
  if (token) headers.authorization = `Bearer ${token}`;

  const gh = async (path: string) => {
    const r = await f(`https://api.github.com${path}`, { headers });
    if (r.status === 404) return null;
    if (!r.ok) throw new Error(`GitHub API ${r.status} for ${path}${r.status === 403 ? ' (rate limited? set GITHUB_TOKEN)' : ''}`);
    return r.json() as Promise<any>;
  };
  const resolve = (repo: string, ref: string): Promise<string> => {
    const key = `${repo}@${ref}`;
    if (!cache.has(key)) {
      cache.set(key, (async () => {
        const [owner, name] = repo.split('/');
        const tag = await gh(`/repos/${owner}/${name}/git/ref/tags/${encodeURIComponent(ref)}`);
        if (tag?.object) {
          if (tag.object.type === 'tag') { const t = await gh(`/repos/${owner}/${name}/git/tags/${tag.object.sha}`); if (t?.object?.sha) return t.object.sha; }
          return tag.object.sha;
        }
        const head = await gh(`/repos/${owner}/${name}/git/ref/heads/${encodeURIComponent(ref)}`);
        if (head?.object?.sha) return head.object.sha;
        const commit = await gh(`/repos/${owner}/${name}/commits/${encodeURIComponent(ref)}`);
        if (commit?.sha) return commit.sha;
        throw new Error(`could not resolve ${repo}@${ref}`);
      })());
    }
    return cache.get(key)!;
  };

  const lines = yaml.split(/\r?\n/);
  const changes: PinChange[] = [];
  await Promise.all(lines.map(async (line, i) => {
    const m = line.match(USES_RE);
    if (!m) return;
    const [, prefix, action, ref, quote, trailing] = m;
    if (action.startsWith('./') || action.startsWith('docker://')) return;
    if (/^[0-9a-f]{40}$/i.test(ref)) return;
    const repo = action.split('/').slice(0, 2).join('/');
    try {
      const sha = await resolve(repo, ref);
      const comment = trailing?.trim().startsWith('#') ? trailing.trim() : `# ${ref}`;
      const to = `${prefix}${action}@${sha}${quote} ${comment}`;
      changes.push({ line: i + 1, from: line, to, comment: ref });
      lines[i] = to;
    } catch (e: any) {
      changes.push({ line: i + 1, from: line, to: line, error: e?.message ?? String(e) });
    }
  }));
  changes.sort((a, b) => a.line - b.line);
  return { yaml: lines.join('\n'), changes };
}
