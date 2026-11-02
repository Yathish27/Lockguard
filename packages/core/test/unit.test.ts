import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  isThirdParty, registrableDomain, categorizeHost, isAddressLike,
  lintSignerPolicy, SIGNER_POLICY_TEMPLATE, parseCsp,
  scoreFindings, diffBaseline, buildBaseline, makeFinding, toSarif, toMarkdown,
  approveZeroCalldata, setApprovalForAllFalseCalldata, summarizeKillChains,
  RULE_LIST, INCIDENT_LIST, KILL_CHAINS, type Finding, type ScriptObservation, type ModuleResult
} from '@safetyfirst/core';
import { analyzeCsp } from '@safetyfirst/core';

test('registrable domain + third-party detection', () => {
  assert.equal(registrableDomain('a.b.example.com'), 'example.com');
  assert.equal(registrableDomain('foo.co.uk'), 'foo.co.uk');
  assert.equal(registrableDomain('a.foo.co.uk'), 'foo.co.uk');
  assert.equal(isThirdParty('https://app.example.com/x', 'https://cdn.example.com/y.js'), false);
  assert.equal(isThirdParty('https://app.example.com/x', 'https://evil.net/y.js'), true);
  assert.equal(isThirdParty('https://app.example.com/x', 'https://evil.net/y.js', ['evil.net']), false);
  // localhost compares by origin (port matters)
  assert.equal(isThirdParty('http://127.0.0.1:4478/', 'http://127.0.0.1:4480/a.js'), true);
  assert.equal(isThirdParty('http://127.0.0.1:4478/', 'http://127.0.0.1:4478/a.js'), false);
});

test('host categorization flags known-risky vendors', () => {
  assert.equal(categorizeHost('cdn.polyfill.io')?.risk, 'critical');
  assert.equal(categorizeHost('www.googletagmanager.com')?.category.includes('tag manager'), true);
  assert.equal(categorizeHost('app.safe.global')?.category, 'wallet connector');
  assert.equal(categorizeHost('totally-unknown-vendor.example'), null);
});

test('address validation + revoke calldata', () => {
  assert.equal(isAddressLike('0x' + 'a'.repeat(40)), true);
  assert.equal(isAddressLike('0xzz'), false);
  const data = approveZeroCalldata(('0x' + 'b'.repeat(40)) as `0x${string}`);
  assert.ok(data.startsWith('0x095ea7b3'));
  assert.equal(data.length, 2 + 8 + 64 + 64);
  assert.ok(setApprovalForAllFalseCalldata(('0x' + 'b'.repeat(40)) as `0x${string}`).startsWith('0xa22cb465'));
});

test('CSP analysis catches weak policies', () => {
  const none = analyzeCsp(null, null, null, false);
  assert.ok(none.problems.some((p) => p.detail.includes('No Content-Security-Policy')));
  const unsafe = analyzeCsp("script-src 'self' 'unsafe-inline'; object-src 'none'", null, null, false);
  assert.ok(unsafe.problems.some((p) => p.detail.includes('unsafe-inline')));
  const wild = analyzeCsp("script-src 'self' https: *", null, null, false);
  assert.ok(wild.problems.some((p) => p.detail.includes('wildcard')));
  const strict = analyzeCsp("default-src 'self'; script-src 'nonce-abc' 'strict-dynamic'; object-src 'none'; base-uri 'none'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; require-trusted-types-for 'script'; report-to x", null, null, false);
  assert.equal(strict.trustedTypes, true);
  assert.equal(strict.problems.length, 0, 'strict policy should have no problems: ' + JSON.stringify(strict.problems));
  // signing page escalates severity of a missing CSP
  const sign = analyzeCsp(null, null, null, true);
  assert.ok(sign.problems.length > 0);
  assert.equal(parseCsp("script-src 'self' x.com")['script-src'].length, 2);
});

test('signer policy linter: template is clean-ish, bad policy is caught', () => {
  const tmpl = lintSignerPolicy(SIGNER_POLICY_TEMPLATE);
  // template should have no critical/high gaps
  assert.equal(tmpl.filter((f) => f.severity === 'critical' || f.severity === 'high').length, 0, 'template should be clean of crit/high: ' + JSON.stringify(tmpl.map((f) => f.summary)));
  const bad = lintSignerPolicy({ version: 1, signers: [{ id: 'hot', address: '0x' + '1'.repeat(40), role: 'hot', allowedTxTypes: [0, 2, 4] }] });
  assert.ok(bad.some((f) => f.tags.includes('P01') && f.severity === 'critical'), 'type-4 must be critical');
  assert.ok(bad.some((f) => f.tags.includes('P05')), 'missing velocity caps');
  assert.ok(bad.some((f) => f.tags.includes('P12')), 'missing circuit breaker');
  assert.ok(bad.some((f) => f.tags.includes('P13')), 'single-person policy change');
});

test('scoring and grades', () => {
  const mk = (sev: Finding['severity']): Finding => makeFinding('W3', { key: 'k' + Math.random(), summary: 's', severity: sev, evidence: [] });
  assert.equal(scoreFindings([]).grade, 'A');
  assert.equal(scoreFindings([mk('critical')]).grade, 'C'); // 100-30=70 => C
  const many = scoreFindings([mk('critical'), mk('critical'), mk('critical'), mk('high')]);
  assert.equal(many.value, Math.max(0, 100 - 30 * 3 - 15));
  assert.equal(many.grade, 'F');
});

test('baseline diff detects swaps, new and removed scripts', () => {
  const obs = (url: string, sha: string, third = true): ScriptObservation => ({ url, origin: new URL(url).origin, thirdParty: third, inDom: true, integrity: null, crossOrigin: null, nonce: false, status: 200, bytes: 100, sha256: sha, sha384: 'sha384-x', category: null, categoryRisk: null });
  const base = buildBaseline('https://app.example.com/', [obs('https://cdn.example.com/a.js', 'aaa', false), obs('https://vendor.net/b.js', 'bbb')]);
  const diff = diffBaseline(base, [obs('https://cdn.example.com/a.js', 'aaa', false), obs('https://vendor.net/b.js', 'CHANGED'), obs('https://new.net/c.js', 'ccc')]);
  assert.equal(diff.changed.length, 1);
  assert.equal(diff.changed[0].thirdParty, true);
  assert.equal(diff.added.length, 1);
  assert.equal(diff.removed.length, 0);
  assert.equal(diff.unchanged, 1);
});

test('knowledge base integrity: every rule maps to real incidents and kill-chain stages', () => {
  const incidentIds = new Set(INCIDENT_LIST.map((i) => i.id));
  const stageRuleIds = new Set(KILL_CHAINS.flatMap((k) => k.stages.flatMap((s) => s.rules)));
  for (const r of RULE_LIST) {
    for (const id of r.incidentIds) assert.ok(incidentIds.has(id), `rule ${r.id} references unknown incident ${id}`);
    assert.ok(r.fix.steps.length > 0, `rule ${r.id} has no fix steps`);
    assert.ok(r.why.length > 40, `rule ${r.id} has a thin why`);
  }
  // every non-policy rule id should appear in some kill-chain stage
  for (const r of RULE_LIST) {
    assert.ok(stageRuleIds.has(r.id), `rule ${r.id} is not in any kill-chain stage`);
  }
});

test('SARIF and Markdown export', () => {
  const findings = [makeFinding('R5', { key: 'R5:x', summary: 'secret', severity: 'critical', evidence: [{ location: 'src/.env', detail: 'token', line: 3 }] })];
  const mod: ModuleResult = { module: 'repo', target: '/repo', startedAt: '', finishedAt: '', findings, score: scoreFindings(findings), meta: { root: '/repo' }, errors: [] };
  const report = { id: 'x', tool: { name: 'Safetyfirst', version: '0.1.0' }, createdAt: '', targets: {}, modules: [mod], overall: scoreFindings(findings), killChains: summarizeKillChains([mod]) };
  const sarif = toSarif(report, '/repo') as { runs: { results: unknown[]; tool: { driver: { rules: unknown[] } } }[] };
  assert.equal(sarif.runs[0].results.length, 1);
  assert.ok(sarif.runs[0].tool.driver.rules.length >= RULE_LIST.length);
  const md = toMarkdown(report);
  assert.ok(md.includes('Safetyfirst report'));
  assert.ok(md.includes('R5'));
});
