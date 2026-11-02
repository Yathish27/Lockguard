import type { RuleDef } from '../types.js';

const CSP_EXPRESS = `import crypto from 'node:crypto';

app.use((req, res, next) => {
  const nonce = crypto.randomBytes(16).toString('base64');
  res.locals.cspNonce = nonce;
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    \`script-src 'nonce-\${nonce}' 'strict-dynamic'\`, // nonce'd scripts may load their own deps; nothing else runs
    "object-src 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "connect-src 'self' https://api.yourdomain.example", // where fetch/XHR/WebSocket may go (blocks exfil)
    "form-action 'self'",
    "require-trusted-types-for 'script'",
    "report-to csp-endpoint"
  ].join('; '));
  res.setHeader('Reporting-Endpoints', 'csp-endpoint="https://yourdomain.example/csp-report"');
  next();
});

// In templates: <script nonce="<%= cspNonce %>" src="/app.js"></script>`;

const CSP_NEXT = `// middleware.ts (Next.js)
import { NextResponse } from 'next/server';
export function middleware(req: Request) {
  const nonce = Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64');
  const csp = \`default-src 'self'; script-src 'nonce-\${nonce}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; connect-src 'self'; form-action 'self'; require-trusted-types-for 'script'; report-to csp-endpoint\`;
  const headers = new Headers(req.headers);
  headers.set('x-nonce', nonce);
  const res = NextResponse.next({ request: { headers } });
  res.headers.set('Content-Security-Policy', csp);
  res.headers.set('Reporting-Endpoints', 'csp-endpoint="/api/csp-report"');
  return res;
}`;

export const RULES: Record<string, RuleDef> = {
  // ------------------------------------------------------------------ WEB
  W1: {
    id: 'W1',
    module: 'web',
    title: 'Third-party JavaScript executes on your page',
    severity: 'medium',
    killChain: 'vendor-script',
    stage: 'vendor-compromised',
    incidentIds: ['polymarket-2026-10', 'polyfill-io-2024-06'],
    why:
      'Every script you load from someone else\'s origin runs with the same authority as your own code: it can read storage and cookies that JavaScript can see, call your APIs as the user, and rewrite the DOM. ' +
      'Polymarket lost ≈ $2.7M on 29 Oct 2026 when a page-speed monitoring script from a vendor was swapped for code that read trading API keys out of logged-in sessions. ' +
      'Tag managers and session-replay tools are the riskiest kind: their behaviour is remote-configured, so there is nothing to pin.',
    fix: {
      summary: 'Keep third-party JavaScript off pages that sign, trade or withdraw; pin and self-host what remains; review every vendor on a schedule.',
      effort: 'hours',
      impact: 'high',
      steps: [
        'Write down every third-party origin below as a vendor with an owner and a last-review date. Anything over 90 days unreviewed is a finding.',
        'Remove all third-party scripts from wallet, signing, trading and withdrawal pages. Analytics can run on the marketing site.',
        'For scripts you keep: load a pinned version, add Subresource Integrity (W2), and prefer self-hosting the file from your own origin.',
        'Move non-essential widgets (chat, surveys) into a sandboxed iframe on a separate origin so they cannot touch your DOM or storage.',
        'Replace remote-configured loaders (tag managers, session replay) on sensitive pages. They cannot be integrity-checked by design.',
        'Treat vendor script changes like code changes: they go through change review, and Safetyfirst\'s baseline (W6) flags drift.'
      ],
      snippets: [
        {
          title: 'Sandboxed iframe for a non-essential widget',
          lang: 'html',
          code: '<iframe src="https://widgets.yourdomain.example/chat" sandbox="allow-scripts allow-forms" referrerpolicy="no-referrer" title="Support chat"></iframe>'
        },
        {
          title: 'vendors.yml — a reviewable inventory',
          lang: 'yaml',
          code: `# Every third party that can execute code in production\n- origin: https://cdn.vendor.example\n  purpose: performance monitoring\n  owner: web-platform\n  pages: [marketing]           # never: [trade, withdraw, sign]\n  pinned_version: 4.2.1\n  sri: true\n  last_reviewed: 2026-11-01`
        }
      ]
    },
    references: [
      { title: 'OWASP Third Party JavaScript Management Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html' }
    ]
  },
  W2: {
    id: 'W2',
    module: 'web',
    title: 'External script loaded without Subresource Integrity',
    severity: 'high',
    killChain: 'vendor-script',
    stage: 'script-executes',
    incidentIds: ['polymarket-2026-10', 'bybit-2025-02', 'ledger-connect-kit-2023-12'],
    why:
      'Subresource Integrity (SRI) makes the browser refuse to run a script whose bytes do not match the hash you shipped. ' +
      'It is the one control that would have turned the Polymarket and Ledger Connect Kit incidents into a broken widget instead of a theft: the vendor\'s file changed, the hash did not, the browser said no. ' +
      'Scripts injected at runtime (by a tag manager, for example) cannot carry SRI, which is itself a reason to remove the loader from sensitive pages.',
    fix: {
      summary: 'Add integrity and crossorigin attributes to every external script, pin the version, and fail CI when the hash changes unexpectedly.',
      effort: 'minutes',
      impact: 'high',
      steps: [
        'Pin the script to an immutable URL (a versioned path, not "latest").',
        'Compute the hash of the file as served (Safetyfirst\'s Harden tab does this) and add integrity="sha384-…" crossorigin="anonymous".',
        'The vendor must serve the file with CORS (Access-Control-Allow-Origin); if it cannot, self-host the file.',
        'If the script is inserted by another script (tag manager, loader) there is no tag to annotate: replace the loader on sensitive pages.',
        'Verify in CI: fetch each pinned URL and compare the hash. A mismatch means the vendor changed the file, which is a change-review event, not a silent update.'
      ],
      snippets: [
        {
          title: 'Script tag with SRI',
          lang: 'html',
          code: '<script src="https://cdn.vendor.example/widget/4.2.1/widget.min.js"\n        integrity="sha384-REPLACE_WITH_HASH_FROM_HARDEN_TAB"\n        crossorigin="anonymous"></script>'
        },
        {
          title: 'Compute the hash yourself',
          lang: 'bash',
          code: 'curl -sL https://cdn.vendor.example/widget/4.2.1/widget.min.js | openssl dgst -sha384 -binary | openssl base64 -A'
        }
      ]
    },
    references: [{ title: 'MDN: Subresource Integrity', url: 'https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity' }]
  },
  W3: {
    id: 'W3',
    module: 'web',
    title: 'Content Security Policy missing or weak',
    severity: 'high',
    killChain: 'vendor-script',
    stage: 'script-executes',
    incidentIds: ['polymarket-2026-10', 'bybit-2025-02'],
    why:
      'A strict, nonce-based CSP decides which scripts may run and where the page may send data. With connect-src locked to your own API, the Polymarket script could not have shipped the stolen keys anywhere; ' +
      'with strict-dynamic and nonces, an injected or swapped script does not run at all. A CSP with \'unsafe-inline\', wildcards or https: in script-src is decoration. ' +
      'Polymarket\'s own post-incident plan was exactly this: a stronger CSP, pinned versions and sandboxing.',
    fix: {
      summary: 'Ship a nonce-based CSP with strict-dynamic, lock connect-src and form-action, and collect violation reports.',
      effort: 'hours',
      impact: 'high',
      steps: [
        'Start in report-only mode with Content-Security-Policy-Report-Only and a reporting endpoint; fix what it reports for a week.',
        'Generate a fresh nonce per response and put it on every script tag you render. Use \'strict-dynamic\' so bundler-loaded chunks work without listing hosts.',
        'Remove \'unsafe-inline\' and \'unsafe-eval\' from script-src. Move inline handlers to addEventListener.',
        'Set object-src \'none\', base-uri \'none\', frame-ancestors \'none\' (or your allowed parents), form-action \'self\'.',
        'Lock connect-src to the hosts your front-end actually talks to. This is the exfiltration control.',
        'Switch to enforcing mode. Alert on a spike of violation reports in production: that is the detection signal for a swapped script.'
      ],
      snippets: [
        { title: 'Express middleware', lang: 'ts', code: CSP_EXPRESS },
        { title: 'Next.js middleware', lang: 'ts', code: CSP_NEXT },
        {
          title: 'nginx (static nonce not possible; use a hash-based policy for static sites)',
          lang: 'nginx',
          code: `add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'sha384-HASH_OF_INLINE_BOOTSTRAP'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; connect-src 'self'; form-action 'self'; report-to csp-endpoint" always;\nadd_header Reporting-Endpoints 'csp-endpoint="https://yourdomain.example/csp-report"' always;`
        }
      ]
    },
    references: [
      { title: 'web.dev: Mitigate XSS with a strict CSP', url: 'https://web.dev/articles/strict-csp' },
      { title: 'Google CSP Evaluator', url: 'https://csp-evaluator.withgoogle.com/' }
    ]
  },
  W4: {
    id: 'W4',
    module: 'web',
    title: 'Session secrets readable by JavaScript',
    severity: 'critical',
    killChain: 'vendor-script',
    stage: 'secrets-read',
    incidentIds: ['polymarket-2026-10'],
    why:
      'The Polymarket script did not need an exploit. It read what the page had already put within reach of any JavaScript: account material and trading API keys in the browser. ' +
      'A token in localStorage, a session cookie without HttpOnly, or a private key in storage is readable by every script on the page, including the vendor\'s, including the attacker\'s.',
    fix: {
      summary: 'Keep sessions in HttpOnly, Secure, SameSite cookies; never persist API keys or key material where JavaScript can read them; require step-up auth for money movement.',
      effort: 'hours',
      impact: 'high',
      steps: [
        'Move session tokens out of localStorage/sessionStorage into cookies set with HttpOnly; Secure; SameSite=Lax (or Strict for the trading origin).',
        'Shorten token lifetime and bind sessions to the device (DBSC / token binding where available). Rotate on privilege change.',
        'API keys with trading or withdrawal rights must never live in the browser. Issue short-lived, scoped tokens from the server per action instead.',
        'Require step-up authentication (passkey / hardware key) for withdrawals, API-key creation and address-book changes. A stolen session should not be enough.',
        'Wallet key material (private keys, mnemonics) in web storage is an emergency: rotate the wallet now.'
      ],
      snippets: [
        {
          title: 'Express: session cookie that JavaScript cannot read',
          lang: 'ts',
          code: `res.cookie('session', token, {\n  httpOnly: true,   // document.cookie cannot see it\n  secure: true,     // HTTPS only\n  sameSite: 'lax',  // not sent on cross-site POSTs\n  path: '/',\n  maxAge: 15 * 60 * 1000 // short-lived; refresh server-side\n});`
        },
        {
          title: 'Raw header',
          lang: 'http',
          code: 'Set-Cookie: session=…; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=900'
        }
      ]
    },
    references: [
      { title: 'OWASP Session Management Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html' },
      { title: 'OWASP HTML5 Security: local storage', url: 'https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage' }
    ]
  },
  W5: {
    id: 'W5',
    module: 'web',
    title: 'Trusted Types not enforced',
    severity: 'medium',
    killChain: 'vendor-script',
    stage: 'script-executes',
    incidentIds: ['bybit-2025-02'],
    why:
      'Trusted Types make DOM-XSS sinks (innerHTML, script.src, eval) refuse plain strings unless they pass through a policy you wrote. ' +
      'It closes the class of bugs a tampered or compromised script would otherwise chain into, and it makes the Bybit-style "rewrite what the signer sees" much harder to do quietly.',
    fix: {
      summary: 'Add require-trusted-types-for \'script\' to your CSP and define a default policy (DOMPurify works) for the few sinks you need.',
      effort: 'hours',
      impact: 'medium',
      steps: [
        'Add require-trusted-types-for \'script\'; trusted-types default dompurify to the CSP in report-only first.',
        'Fix reported sinks: use textContent, or wrap HTML through a policy backed by DOMPurify.',
        'Enforce. React, Angular and most modern frameworks work with Trusted Types out of the box.'
      ],
      snippets: [
        {
          title: 'Default policy with DOMPurify',
          lang: 'ts',
          code: `import DOMPurify from 'dompurify';\nif (window.trustedTypes?.createPolicy) {\n  window.trustedTypes.createPolicy('default', {\n    createHTML: (s) => DOMPurify.sanitize(s, { RETURN_TRUSTED_TYPE: false }),\n    createScriptURL: (s) => { if (new URL(s, location.href).origin === location.origin) return s; throw new TypeError('blocked script URL ' + s); },\n    createScript: () => { throw new TypeError('eval is not allowed'); }\n  });\n}`
        }
      ]
    },
    references: [{ title: 'web.dev: Prevent DOM-based XSS with Trusted Types', url: 'https://web.dev/articles/trusted-types' }]
  },
  W6: {
    id: 'W6',
    module: 'web',
    title: 'Script changed since the approved baseline',
    severity: 'critical',
    killChain: 'vendor-script',
    stage: 'vendor-compromised',
    incidentIds: ['polymarket-2026-10', 'bybit-2025-02', 'polyfill-io-2024-06'],
    why:
      'Hash drift on a production page is the earliest signal you can get of a vendor or CDN compromise. Polymarket\'s malicious script was live for hours before researchers downloaded it; a daily (or hourly) crawl comparing script hashes to an approved baseline turns that into minutes. ' +
      'Bybit\'s injected code sat in Safe\'s bucket for two days before it fired.',
    fix: {
      summary: 'Approve the baseline deliberately, re-crawl on a schedule, and treat any drift as a change-review event until proven benign.',
      effort: 'minutes',
      impact: 'high',
      steps: [
        'Confirm each changed or new script is a deploy you expected. If not, kill-switch the vendor tag now and roll the CDN back to the last known-good build.',
        'Once reviewed, save a new baseline from the Safetyfirst UI (or commit .safetyfirst/baselines/<host>.json).',
        'Run the web scan on a schedule (GitHub Action below) with --baseline so drift fails the job and pages someone.',
        'Pin versions and add SRI (W2) so drift cannot execute even if it is not noticed.'
      ],
      snippets: [
        {
          title: 'Scheduled drift check (GitHub Actions)',
          lang: 'yaml',
          code: `name: safetyfirst-drift\non:\n  schedule: [{ cron: '*/30 * * * *' }]\n  workflow_dispatch:\njobs:\n  web:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@<pinned-sha>\n      - uses: actions/setup-node@<pinned-sha>\n        with: { node-version: 22 }\n      - run: npx playwright install --with-deps chromium\n      - run: npx safetyfirst scan --web https://app.yourdomain.example/trade --baseline --fail-on high --sarif safetyfirst.sarif\n      - uses: github/codeql-action/upload-sarif@<pinned-sha>\n        if: always()\n        with: { sarif_file: safetyfirst.sarif }`
        }
      ]
    },
    references: []
  },
  W7: {
    id: 'W7',
    module: 'web',
    title: 'Hardening headers missing',
    severity: 'low',
    killChain: 'vendor-script',
    stage: 'secrets-read',
    incidentIds: [],
    why:
      'Strict-Transport-Security, frame-ancestors / X-Frame-Options, Referrer-Policy, Permissions-Policy and X-Content-Type-Options each close one well-known way to downgrade, frame, leak or sniff your pages. They are cheap and they compound with CSP.',
    fix: {
      summary: 'Add the standard hardening headers at the edge.',
      effort: 'minutes',
      impact: 'medium',
      steps: ['Add the headers below at your CDN or reverse proxy.', 'Submit the domain to the HSTS preload list once max-age ≥ 1 year with includeSubDomains.'],
      snippets: [
        {
          title: 'Headers',
          lang: 'http',
          code: 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\nX-Content-Type-Options: nosniff\nReferrer-Policy: strict-origin-when-cross-origin\nPermissions-Policy: camera=(), microphone=(), geolocation=(), payment=()\nCross-Origin-Opener-Policy: same-origin\nX-Frame-Options: DENY'
        }
      ]
    },
    references: [{ title: 'OWASP Secure Headers Project', url: 'https://owasp.org/www-project-secure-headers/' }]
  },
  W8: {
    id: 'W8',
    module: 'web',
    title: 'Page or script delivered over plain HTTP',
    severity: 'high',
    killChain: 'vendor-script',
    stage: 'script-executes',
    incidentIds: [],
    why: 'Anything on the network path can rewrite an HTTP response. SRI and CSP cannot help a page whose own HTML arrived unauthenticated.',
    fix: {
      summary: 'Serve everything over HTTPS and enable HSTS.',
      effort: 'hours',
      impact: 'high',
      steps: ['Redirect HTTP to HTTPS at the edge.', 'Set Strict-Transport-Security with a long max-age.', 'Fix any http:// script URLs (the browser blocks mixed scripts on HTTPS pages, but an HTTP page has no protection).'],
      snippets: []
    },
    references: []
  },

  // ------------------------------------------------------------------ REPO
  R1: {
    id: 'R1',
    module: 'repo',
    title: 'Dependencies run install scripts (and nothing blocks them)',
    severity: 'high',
    killChain: 'supply-chain',
    stage: 'lure',
    incidentIds: ['tradertraitor', 'npm-worms-2025'],
    why:
      'npm install executes preinstall/install/postinstall scripts from every dependency as your user. That is the TraderTraitor entry point: a recruiter\'s "coding test" repo or a poisoned package runs code on an engineer\'s laptop the moment it is installed, and takes SSH keys, cloud credentials, browser sessions and signing material with it. ' +
      'The 2025 npm worms (Shai-Hulud, chalk/debug) used the same hook to steal tokens from thousands of machines and CI runners.',
    fix: {
      summary: 'Turn install scripts off by default on developer machines and CI, and allowlist the few packages that genuinely need a build step.',
      effort: 'minutes',
      impact: 'high',
      steps: [
        'Add ignore-scripts=true to the repo .npmrc and to ~/.npmrc on every developer machine and CI image.',
        'For packages that genuinely need a native build (esbuild, sharp, etc.), allowlist them: pnpm onlyBuiltDependencies, Bun trustedDependencies, or an explicit `npm rebuild <pkg>` step.',
        'Never run install on a repo you received from a stranger (job tests, "please review") outside a disposable VM or codespace with no credentials.',
        'Put engineers with production, cloud or signing access on privileged access workstations where package installs cannot reach credentials.',
        'Monitor on endpoints: node or python spawning a shell, curl or wget, or touching ~/.aws, ~/.ssh, keychains and browser profile directories is the detection signal.'
      ],
      snippets: [
        { title: '.npmrc (repo and ~/.npmrc)', lang: 'ini', code: 'ignore-scripts=true\nsave-exact=true\naudit=true\nfund=false' },
        { title: '.yarnrc.yml', lang: 'yaml', code: 'enableScripts: false' },
        { title: 'pnpm-workspace.yaml: allowlist builds, and wait before adopting fresh versions', lang: 'yaml', code: 'onlyBuiltDependencies:\n  - esbuild\n  - sharp\nminimumReleaseAge: 4320   # minutes (3 days): skip versions published in the last 3 days' },
        { title: 'package.json (Bun)', lang: 'json', code: '{\n  "trustedDependencies": ["esbuild", "sharp"]\n}' },
        { title: 'CI step', lang: 'yaml', code: '- run: npm ci --ignore-scripts\n- run: npm rebuild esbuild sharp   # only what you allowlisted' }
      ]
    },
    references: [
      { title: 'npm config: ignore-scripts', url: 'https://docs.npmjs.com/cli/v10/using-npm/config#ignore-scripts' },
      { title: 'pnpm: minimumReleaseAge', url: 'https://pnpm.io/settings#minimumreleaseage' },
      { title: 'FBI PSA on North Korean social engineering of crypto engineers', url: 'https://www.ic3.gov/PSA/2024/PSA240903' }
    ]
  },
  R2: {
    id: 'R2',
    module: 'repo',
    title: 'Lockfile missing, bypassed, or loose dependency ranges',
    severity: 'medium',
    killChain: 'supply-chain',
    stage: 'malicious-dependency',
    incidentIds: ['ledger-connect-kit-2023-12', 'npm-worms-2025'],
    why:
      'Without a committed lockfile and a frozen install, every build resolves ranges fresh and picks up whatever was published last night, which in the 2025 npm compromises was a credential stealer. ' +
      'A lockfile pins the exact tree you reviewed; `npm ci` / `--frozen-lockfile` make CI refuse anything else.',
    fix: {
      summary: 'Commit the lockfile, install with it frozen in CI, and avoid ranges that mean "anything".',
      effort: 'minutes',
      impact: 'medium',
      steps: [
        'Commit package-lock.json (or pnpm-lock.yaml / yarn.lock) and never add it to .gitignore.',
        'In CI use npm ci, pnpm install --frozen-lockfile or yarn install --immutable, not npm install.',
        'Replace "*", "latest", ">=" and git/http dependencies with exact versions.',
        'Set save-exact=true so new dependencies are pinned by default; let Dependabot or Renovate propose updates as reviewable PRs.'
      ],
      snippets: [
        { title: 'CI install', lang: 'yaml', code: '- run: npm ci --ignore-scripts        # npm\n- run: pnpm install --frozen-lockfile  # pnpm\n- run: yarn install --immutable        # yarn berry' }
      ]
    },
    references: [{ title: 'npm ci', url: 'https://docs.npmjs.com/cli/v10/commands/npm-ci' }]
  },
  R3: {
    id: 'R3',
    module: 'repo',
    title: 'CI authenticates to the cloud with static keys',
    severity: 'high',
    killChain: 'supply-chain',
    stage: 'credentials-stolen',
    incidentIds: ['tradertraitor', 'npm-worms-2025', 'bybit-2025-02'],
    why:
      'A long-lived AWS/GCP/Azure key in CI secrets is exactly what install-script malware and compromised actions harvest, and it keeps working from anywhere until someone rotates it. ' +
      'OIDC federation gives each job a token that lives minutes, is bound to this repo and branch, and cannot be replayed from a laptop in another country. ' +
      'Bybit\'s root cause was a single developer environment with credentials that could change what production served.',
    fix: {
      summary: 'Replace static cloud keys with OIDC workload identity and scope the role to the repository and branch.',
      effort: 'hours',
      impact: 'high',
      steps: [
        'Create a cloud role/service account trusted by GitHub\'s OIDC provider, with a subject condition like repo:org/repo:ref:refs/heads/main.',
        'Add permissions: id-token: write to the job and use the provider\'s auth action with role-to-assume / workload_identity_provider.',
        'Delete the static key from repository secrets and from the cloud account. Check CloudTrail / audit logs for its last use first.',
        'Repeat for npm publish (trusted publishing), PyPI and container registries.'
      ],
      snippets: [
        {
          title: 'AWS via OIDC',
          lang: 'yaml',
          code: `permissions:\n  id-token: write\n  contents: read\nsteps:\n  - uses: aws-actions/configure-aws-credentials@<pinned-sha> # v4\n    with:\n      role-to-assume: arn:aws:iam::123456789012:role/github-deploy\n      aws-region: us-east-1`
        },
        {
          title: 'GCP via Workload Identity Federation',
          lang: 'yaml',
          code: `permissions:\n  id-token: write\nsteps:\n  - uses: google-github-actions/auth@<pinned-sha> # v2\n    with:\n      workload_identity_provider: projects/123/locations/global/workloadIdentityPools/github/providers/github\n      service_account: deploy@project.iam.gserviceaccount.com`
        },
        {
          title: 'Azure via federated credentials',
          lang: 'yaml',
          code: `permissions:\n  id-token: write\nsteps:\n  - uses: azure/login@<pinned-sha> # v2\n    with:\n      client-id: \${{ vars.AZURE_CLIENT_ID }}\n      tenant-id: \${{ vars.AZURE_TENANT_ID }}\n      subscription-id: \${{ vars.AZURE_SUBSCRIPTION_ID }}`
        }
      ]
    },
    references: [
      { title: 'GitHub: About security hardening with OpenID Connect', url: 'https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect' }
    ]
  },
  R4: {
    id: 'R4',
    module: 'repo',
    title: 'GitHub Actions pinned by mutable tag instead of commit SHA',
    severity: 'medium',
    killChain: 'supply-chain',
    stage: 'malicious-dependency',
    incidentIds: ['npm-worms-2025'],
    why:
      'A tag like @v4 is a pointer the action\'s maintainer (or whoever steals their token) can move. In March 2025 the tj-actions/changed-files tags were repointed to a commit that dumped CI secrets into build logs across thousands of repositories. ' +
      'A 40-character commit SHA cannot be moved.',
    fix: {
      summary: 'Pin every third-party action to a full commit SHA with the version as a comment, and let Dependabot propose updates.',
      effort: 'minutes',
      impact: 'medium',
      steps: [
        'Replace each uses: owner/repo@tag with uses: owner/repo@<40-char sha> # tag. Safetyfirst\'s Harden tab rewrites a workflow for you.',
        'Enable Dependabot for github-actions so pins get reviewable update PRs.',
        'In organisation settings, restrict actions to verified creators or an allowlist.'
      ],
      snippets: [
        { title: 'Pinned action', lang: 'yaml', code: '- uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0' },
        { title: '.github/dependabot.yml', lang: 'yaml', code: 'version: 2\nupdates:\n  - package-ecosystem: github-actions\n    directory: /\n    schedule: { interval: weekly }' }
      ]
    },
    references: [
      { title: 'GitHub: Security hardening for GitHub Actions', url: 'https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions' }
    ]
  },
  R5: {
    id: 'R5',
    module: 'repo',
    title: 'Tokens or keys committed to the repository',
    severity: 'critical',
    killChain: 'supply-chain',
    stage: 'credentials-stolen',
    incidentIds: ['tradertraitor', 'npm-worms-2025'],
    why:
      'A token in .npmrc, a key in .env or a private key in the tree is stolen by the first malicious install script, the first compromised action, or the first clone of the repo. ' +
      'An npm publish token is how the 2025 worms spread; a deployer private key is a wallet drain with no further steps required.',
    fix: {
      summary: 'Rotate now, purge from history, and block the next one with pre-commit scanning and push protection.',
      effort: 'hours',
      impact: 'high',
      steps: [
        'Rotate every credential listed below immediately. Assume it is already copied.',
        'For wallet private keys or mnemonics: move funds to a fresh wallet; do not reuse the key after rotation.',
        'Remove the secret from the working tree and rewrite history (git filter-repo), then force-push and ask collaborators to re-clone.',
        'Add .env and local config to .gitignore; load secrets from a manager or CI OIDC, never from files in the repo.',
        'Install gitleaks as a pre-commit hook and enable GitHub secret scanning with push protection.'
      ],
      snippets: [
        { title: 'Pre-commit scanning', lang: 'yaml', code: '# .pre-commit-config.yaml\nrepos:\n  - repo: https://github.com/gitleaks/gitleaks\n    rev: v8.21.2\n    hooks:\n      - id: gitleaks' },
        { title: 'Purge from history', lang: 'bash', code: 'pip install git-filter-repo\ngit filter-repo --invert-paths --path .env --path .npmrc\ngit push --force --all' }
      ]
    },
    references: [{ title: 'gitleaks', url: 'https://github.com/gitleaks/gitleaks' }]
  },
  R6: {
    id: 'R6',
    module: 'repo',
    title: 'Privileged workflow runs untrusted code or input',
    severity: 'high',
    killChain: 'supply-chain',
    stage: 'malicious-dependency',
    incidentIds: ['npm-worms-2025'],
    why:
      'pull_request_target runs with your secrets; checking out the pull request\'s head in it hands those secrets to anyone who opens a PR. Interpolating issue or PR text into run: lets a stranger execute shell in your CI. ' +
      'Both are standard first steps for stealing the deploy credentials that later change what production serves.',
    fix: {
      summary: 'Never check out or execute untrusted content in a workflow that has secrets; pass event data through env, not string interpolation.',
      effort: 'hours',
      impact: 'high',
      steps: [
        'Use pull_request (no secrets) for anything that builds or tests contributor code.',
        'If you must use pull_request_target, do not check out the PR head, and do not run npm install, scripts or tests from it.',
        'Pass github.event.* values through env: and reference them as shell variables, never inline in run:.',
        'Split privileged steps (labelling, commenting, deploy) into a separate workflow triggered by workflow_run that reads artifacts, not code.'
      ],
      snippets: [
        { title: 'Safe interpolation', lang: 'yaml', code: '- env:\n    TITLE: ${{ github.event.pull_request.title }}\n  run: echo "PR title is $TITLE"' }
      ]
    },
    references: [
      { title: 'GitHub Security Lab: Preventing pwn requests', url: 'https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/' }
    ]
  },
  R7: {
    id: 'R7',
    module: 'repo',
    title: 'No registry proxy and no minimum release age',
    severity: 'medium',
    killChain: 'supply-chain',
    stage: 'lure',
    incidentIds: ['npm-worms-2025', 'tradertraitor'],
    why:
      'Most poisoned package versions are detected and pulled within a day or two. Installing straight from the public registry at the moment of publication is how you become part of the detection. ' +
      'An internal proxy (with quarantine) plus a minimum release age means a malicious version has to survive public scrutiny before it can reach your machines.',
    fix: {
      summary: 'Route installs through an internal registry proxy and refuse versions younger than a few days.',
      effort: 'hours',
      impact: 'medium',
      steps: [
        'Point .npmrc at an internal proxy (Artifactory, Nexus, Verdaccio, GitHub Packages, Cloudsmith) that caches and can quarantine new versions.',
        'Set a minimum release age (pnpm minimumReleaseAge, or the proxy\'s quarantine window) of 3–7 days.',
        'Block direct access to registry.npmjs.org from CI and privileged workstations so the proxy cannot be bypassed.'
      ],
      snippets: [
        { title: '.npmrc', lang: 'ini', code: 'registry=https://npm.internal.example/repository/npm-proxy/\nignore-scripts=true' },
        { title: 'pnpm-workspace.yaml', lang: 'yaml', code: 'minimumReleaseAge: 7200   # 5 days, in minutes\nminimumReleaseAgeExclude:\n  - "@yourorg/*"' }
      ]
    },
    references: [{ title: 'pnpm: minimumReleaseAge', url: 'https://pnpm.io/settings#minimumreleaseage' }]
  },
  R8: {
    id: 'R8',
    module: 'repo',
    title: 'Workflow token permissions too broad',
    severity: 'low',
    killChain: 'supply-chain',
    stage: 'credentials-stolen',
    incidentIds: ['npm-worms-2025'],
    why: 'A GITHUB_TOKEN with write-all lets any compromised step push code, tags, releases or packages. Least privilege keeps a bad action from becoming a bad commit.',
    fix: {
      summary: 'Set permissions: contents: read at the workflow level and elevate per job only where needed.',
      effort: 'minutes',
      impact: 'medium',
      steps: ['Add a top-level permissions block with contents: read.', 'Grant extra scopes per job.', 'In repo settings, set the default workflow token to read-only.'],
      snippets: [{ title: 'Least privilege', lang: 'yaml', code: 'permissions:\n  contents: read\njobs:\n  release:\n    permissions:\n      contents: write\n      id-token: write' }]
    },
    references: []
  },

  // ------------------------------------------------------------------ CHAIN
  C1: {
    id: 'C1',
    module: 'chain',
    title: 'Address is delegated to contract code (EIP-7702)',
    severity: 'critical',
    killChain: 'signer-abuse',
    stage: 'delegation-live',
    incidentIds: ['binance-2026-10'],
    why:
      'An EIP-7702 delegation turns an externally owned account into a proxy for whatever contract it points at. On 29 Oct 2026 one transaction carrying 50 signed authorizations handed Binance\'s hot wallet "Binance 14" to a sweeper contract, and the wallet was emptied. ' +
      'If this address is a custody, treasury or deployer wallet and you did not deliberately install this delegation, treat it as an active compromise: the delegate can move everything the address holds, including future deposits.',
    fix: {
      summary: 'Verify the delegate; if unexpected, move funds and clear the delegation with a type-4 transaction to the zero address, then block tx type 4 at the signer.',
      effort: 'minutes',
      impact: 'high',
      steps: [
        'Check the delegate address on a block explorer. If you did not deliberately install it (for example a wallet feature you enabled), assume compromise.',
        'Stop deposits to this address and move remaining funds from a clean device (the delegate code may front-run; prioritise what matters).',
        'Clear the delegation: sign an EIP-7702 authorization for address 0x0000000000000000000000000000000000000000 and include it in a type-4 transaction. Note: whoever obtained the original signature can re-delegate, so the key is burned.',
        'At the signing service, deny transaction type 4 (and any authorizationList) for custody addresses outright. Delegations should be impossible for these keys, not merely reviewed.',
        'Alert when eth_getCode for any custody address changes from 0x. Safetyfirst\'s scheduled chain scan does this; a Sentinel rule is in the docs.'
      ],
      snippets: [
        {
          title: 'Clear a delegation with viem (run from a clean machine)',
          lang: 'ts',
          code: `import { createWalletClient, http, zeroAddress } from 'viem';\nimport { privateKeyToAccount } from 'viem/accounts';\nimport { mainnet } from 'viem/chains';\n\nconst account = privateKeyToAccount(process.env.PK as \`0x\${string}\`);\nconst client = createWalletClient({ account, chain: mainnet, transport: http() });\n\nconst authorization = await client.signAuthorization({ contractAddress: zeroAddress, executor: 'self' });\nconst hash = await client.sendTransaction({ to: account.address, authorizationList: [authorization], value: 0n });\nconsole.log('delegation cleared in', hash);`
        },
        {
          title: 'Cron check (any custody address with code is an alarm)',
          lang: 'bash',
          code: 'cast code 0xYourCustodyAddress --rpc-url $RPC   # expect 0x; 0xef0100… means delegated'
        }
      ]
    },
    references: [
      { title: 'EIP-7702: Set EOA account code', url: 'https://eips.ethereum.org/EIPS/eip-7702' },
      { title: 'Fireblocks: Deconstructing the Binance exploit', url: 'https://www.fireblocks.com/blog/binance-hack-eip-7702' }
    ]
  },
  C2: {
    id: 'C2',
    module: 'chain',
    title: 'Unlimited token approvals outstanding',
    severity: 'high',
    killChain: 'signer-abuse',
    stage: 'delegation-live',
    incidentIds: ['binance-2026-10', 'ledger-connect-kit-2023-12'],
    why:
      'An unlimited ERC-20 approval or setApprovalForAll lets the spender move every token you hold now or receive later, with no further signature from you. Drainers served through compromised front-ends (Ledger Connect Kit) ask for exactly this; a compromised router or spender contract turns an old approval into a loss years later. ' +
      'An approval to an externally owned account rather than a contract is almost always a drainer.',
    fix: {
      summary: 'Revoke approvals you do not actively need, approve exact amounts, and use Permit2 or expiring permits for the rest.',
      effort: 'minutes',
      impact: 'high',
      steps: [
        'For each spender below, decide whether you still use it. Revoke the rest with approve(spender, 0) / setApprovalForAll(operator, false). The calldata is in the evidence.',
        'Approve exact amounts going forward; most interfaces offer this.',
        'For custody addresses: forbid approve/setApprovalForAll in the signer\'s method allowlist unless the spender is on an allowlist and the amount is bounded.',
        'Schedule this scan; a new unlimited approval on a treasury address is an incident.'
      ],
      snippets: [
        { title: 'Revoke with cast', lang: 'bash', code: 'cast send $TOKEN "approve(address,uint256)" $SPENDER 0 --rpc-url $RPC --ledger\ncast send $NFT "setApprovalForAll(address,bool)" $OPERATOR false --rpc-url $RPC --ledger' }
      ]
    },
    references: [
      { title: 'revoke.cash (independent revocation UI)', url: 'https://revoke.cash' },
      { title: 'Uniswap Permit2', url: 'https://github.com/Uniswap/permit2' }
    ]
  },
  C3: {
    id: 'C3',
    module: 'chain',
    title: 'Signer policy gap',
    severity: 'high',
    killChain: 'signer-abuse',
    stage: 'policy-gap',
    incidentIds: ['binance-2026-10', 'bybit-2025-02'],
    why:
      'Binance\'s co-CEO said the delegation "did not pass through our normal approval controls". That is the whole lesson: the controls were somewhere the attacker could step around. A signing policy that lives next to the key (HSM/MPC policy engine) and refuses by default is the control that makes a compromised laptop a bounded problem. ' +
      'Each gap below is a transaction the signer would sign that it should refuse.',
    fix: {
      summary: 'Close each gap in the policy document and make the signing service enforce it; two people approve every policy change.',
      effort: 'days',
      impact: 'high',
      steps: [
        'Allowlist transaction types (legacy and EIP-1559 only; never type 4 for custody keys).',
        'Allowlist destinations and contract methods per signer; new destinations wait 24 hours.',
        'Set per-transaction, hourly and daily velocity caps with a circuit breaker that pauses the signer and pages on-call.',
        'Require two approvals above a threshold and two approvals for any policy change; hash the policy and alert on changes.',
        'Replay this policy against the three real kill chains in staging each quarter and measure time to detect and time to pause.'
      ],
      snippets: []
    },
    references: [{ title: 'Safetyfirst signer policy schema and template', url: 'https://github.com/Yathish27/Lockguard/blob/main/docs/signer-policy.md' }]
  },
  C4: {
    id: 'C4',
    module: 'chain',
    title: 'Address is a smart contract',
    severity: 'info',
    killChain: 'signer-abuse',
    stage: 'delegation-live',
    incidentIds: ['bybit-2025-02'],
    why: 'This address holds contract code (not an EIP-7702 delegation). For multisigs and proxies the signing risk moves to the owners and the implementation: Bybit\'s Safe was drained by swapping its implementation through a delegatecall the signers did not realise they were approving.',
    fix: {
      summary: 'Verify owners, threshold and implementation; monitor for implementation and owner changes.',
      effort: 'hours',
      impact: 'medium',
      steps: ['Confirm the implementation address and owners on-chain match what you expect.', 'Alert on any change to the implementation slot, owners or threshold.', 'Make signers verify the full payload on hardware devices; disable delegatecall where possible.'],
      snippets: []
    },
    references: []
  }
};

export const RULE_LIST = Object.values(RULES);
