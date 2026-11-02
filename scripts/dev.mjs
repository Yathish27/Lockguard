// Contributor dev loop: TypeScript watch build + server (auto-restart) + Vite UI with /api proxy.
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';

const procs = [];
function run(name, cmd, args, opts = {}) {
  const p = spawn(cmd, args, { stdio: 'inherit', shell: process.platform === 'win32', ...opts });
  p.on('exit', (code) => { if (code && code !== 0) console.error(`[dev] ${name} exited with ${code}`); });
  procs.push(p);
  return p;
}
process.on('SIGINT', () => { for (const p of procs) p.kill('SIGINT'); process.exit(0); });

if (!existsSync('packages/server/dist/cli.js')) {
  console.log('[dev] first build...');
  await new Promise((res) => run('tsc', 'npx', ['tsc', '-b']).on('exit', res));
}
run('tsc', 'npx', ['tsc', '-b', '--watch', '--preserveWatchOutput']);
run('server', 'node', ['--watch', 'packages/server/dist/cli.js', 'ui', '--no-open']);
run('ui', 'npm', ['run', 'dev', '-w', '@lockguard/ui']);
console.log('\n[dev] UI (hot reload): http://localhost:5173   API: http://127.0.0.1:4477\n');
