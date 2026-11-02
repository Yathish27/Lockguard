import type { KillChain } from '../types.js';

/**
 * Each attack written as steps. For every step: the guardrail that should stop it, the signal that proves it was tried,
 * and the Safetyfirst rules that check whether the guardrail is actually in place.
 */
export const KILL_CHAINS: KillChain[] = [
  {
    id: 'vendor-script',
    name: 'Vendor script injection',
    tagline: 'Polymarket (2026) and Bybit (2025): a third-party or tampered script runs inside your page with your users\' authority.',
    incidentIds: ['polymarket-2026-10', 'bybit-2025-02', 'ledger-connect-kit-2023-12', 'polyfill-io-2024-06'],
    stages: [
      {
        id: 'vendor-compromised',
        step: 'A vendor, CDN or DNS record you depend on is compromised',
        guardrail: 'Inventory of every third party that can execute code on your pages; pinned versions; self-hosting; review every vendor on a ≤90-day cadence',
        signal: 'Unapproved script hash on production pages (drift against baseline)',
        rules: ['W1', 'W6']
      },
      {
        id: 'script-executes',
        step: 'The swapped script executes on your page',
        guardrail: 'Nonce-based CSP with strict-dynamic; Subresource Integrity on every external script; Trusted Types; no HTTP',
        signal: 'CSP violation spike; SRI failures reported from the browser',
        rules: ['W2', 'W3', 'W5', 'W8']
      },
      {
        id: 'secrets-read',
        step: 'The script reads session tokens or API keys, or rewrites what the user sees before they sign',
        guardrail: 'HttpOnly, Secure, SameSite cookies; no secrets in localStorage; no third-party JS on signing, trading or withdrawal pages',
        signal: 'Same session ID seen from a new ASN or device; API calls from unexpected origins',
        rules: ['W4', 'W1', 'W7']
      },
      {
        id: 'funds-move',
        step: 'Positions are sold and funds leave with the user\'s authority',
        guardrail: 'Step-up authentication for withdrawals; address allowlists with a delay for new addresses; velocity caps and a circuit breaker',
        signal: 'Outflow above X% in Y minutes; new destinations per user spike',
        rules: ['C3']
      }
    ]
  },
  {
    id: 'supply-chain',
    name: 'Developer and CI compromise (TraderTraitor)',
    tagline: 'How Bybit and (per Binance) the Binance attack began: an engineer\'s machine, a package install, stolen credentials.',
    incidentIds: ['tradertraitor', 'bybit-2025-02', 'binance-2026-10', 'npm-worms-2025'],
    stages: [
      {
        id: 'lure',
        step: 'An engineer is lured with a fake job, coding test or "please review my repo"',
        guardrail: 'Privileged access workstations; ignore-scripts on dev machines and CI; internal registry proxy; minimum release age',
        signal: 'EDR: node or python spawning shells or touching credential files',
        rules: ['R1', 'R7']
      },
      {
        id: 'malicious-dependency',
        step: 'A malicious or tampered dependency reaches a build',
        guardrail: 'Committed lockfile and frozen installs; GitHub Actions pinned by commit SHA; no untrusted code in privileged workflows',
        signal: 'Lockfile changes outside dependency PRs; new install-script packages',
        rules: ['R2', 'R4', 'R6']
      },
      {
        id: 'credentials-stolen',
        step: 'Cloud keys, npm tokens and session tokens are stolen from disk, env or CI',
        guardrail: 'No long-lived keys: OIDC in CI, short-TTL device-bound tokens, FIDO2 only; nothing committed; least-privilege workflow tokens',
        signal: 'Same token used from a new ASN; secret-scanning alerts; unusual npm publish',
        rules: ['R3', 'R5', 'R8']
      },
      {
        id: 'pivot',
        step: 'Access pivots to production and the signing path',
        guardrail: 'Separation of duties; signing policy enforced next to the key, not in a laptop UI',
        signal: 'Signer requests outside baseline',
        rules: ['C3']
      }
    ]
  },
  {
    id: 'signer-abuse',
    name: 'Signing infrastructure abuse',
    tagline: 'Binance (2026) and Bybit (2025): the key never leaked, the signer signed what it should never have been allowed to sign.',
    incidentIds: ['binance-2026-10', 'bybit-2025-02'],
    stages: [
      {
        id: 'reach-signer',
        step: 'An attacker reaches a path that can request signatures',
        guardrail: 'Privileged access workstations; hardware-backed auth; no static credentials near the signer',
        signal: 'New device or ASN on signer-adjacent accounts',
        rules: ['R3', 'R5']
      },
      {
        id: 'policy-gap',
        step: 'The signing policy allows an unusual transaction (type 4 delegation, implementation swap, unknown destination)',
        guardrail: 'Policy engine in the HSM/MPC: transaction-type allowlist (no EIP-7702 for custody), method and destination allowlists, two-person change control',
        signal: 'Delegation authorizations signed by custody keys; signer requests outside baseline',
        rules: ['C3', 'C1']
      },
      {
        id: 'delegation-live',
        step: 'A delegation or unlimited approval takes effect on a funded address',
        guardrail: 'No EIP-7702 delegation on custody addresses; no unlimited approvals; continuous eth_getCode monitoring',
        signal: 'eth_getCode changes from 0x to 0xef0100…; Approval events with max uint',
        rules: ['C1', 'C2', 'C4']
      },
      {
        id: 'sweep',
        step: 'A sweeper contract empties the wallet in minutes',
        guardrail: 'Velocity caps; withdrawal circuit breaker; pre-arranged issuer freeze contacts',
        signal: 'Hot wallet outflow above X% in Y minutes',
        rules: ['C3']
      }
    ]
  }
];

export const KILL_CHAIN_BY_ID = Object.fromEntries(KILL_CHAINS.map((k) => [k.id, k])) as Record<string, KillChain>;
