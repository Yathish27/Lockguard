import type { Incident } from '../types.js';

/**
 * Real incidents the findings map to. Figures are from public reporting at the time of writing;
 * where sources disagree we say so. Keep this file factual and cite sources.
 */
export const INCIDENTS: Record<string, Incident> = {
  'polymarket-2026-10': {
    id: 'polymarket-2026-10',
    name: 'Polymarket vendor-script compromise',
    date: '2026-10-29',
    loss: '≈ $2.7M stolen from ≈ 710–726 wallets; $3.9M refunded by Polymarket',
    oneLiner: 'A page-speed monitoring script from a vendor (DebugBear) was replaced with code that read trading API keys out of logged-in browsers.',
    summary:
      'On 29 October 2026 the script Polymarket loaded from a third-party performance vendor began serving malicious code (DebugBear attributed it to a DNS hijack of the host it was served from). ' +
      'Running with full authority inside polymarket.com, the script targeted logged-in sessions, read account material the site kept in the browser, including trading API keys, ' +
      'and used it to sell positions and move assets. Polymarket pulled the script within the hour, purged caches, reset every session and paused trading. ' +
      'It was the second third-party script compromise on the platform in 2026. No smart contract was broken.',
    lessons: [
      'A third-party script is first-party code: it can read anything your own JavaScript can read.',
      'Secrets that JavaScript can read (localStorage tokens, non-HttpOnly cookies, API keys in memory you expose) are the payload.',
      'SRI + a nonce-based CSP would have refused the swapped file; script-hash drift monitoring would have paged someone within minutes.',
      'Keep third-party JavaScript off pages that sign, trade or withdraw.'
    ],
    links: [
      { title: 'The Hacker News: Hackers steal about $2.7 million from Polymarket traders via hijacked DebugBear script', url: 'https://thehackernews.com/2026/11/hackers-steal-about-27-million-from.html' },
      { title: 'SecurityWeek: Polymarket returns $3.9 million to traders as DebugBear cites DNS hijack', url: 'https://www.securityweek.com/polymarket-returns-3-9-million-to-traders-as-debugbear-cites-dns-hijack/' },
      { title: 'Hackread: Polymarket users lose $2.7 million in third-party script hack', url: 'https://hackread.com/polymarket-users-lose-2-7m-third-party-script-hack/' }
    ]
  },
  'binance-2026-10': {
    id: 'binance-2026-10',
    name: 'Binance hot-wallet drain via EIP-7702 delegation',
    date: '2026-10-29',
    loss: '≈ $6.3B by Binance\'s own estimate (figures vary by source; the Ethereum leg alone was put at ≈ $3.8B). Issuers froze ≈ $2.4–3B.',
    oneLiner: 'A single transaction carrying 50 signed EIP-7702 authorizations handed the hot wallet "Binance 14" to an attacker-controlled sweeper contract.',
    summary:
      'Also on 29 October 2026, the Ethereum hot wallet labelled "Binance 14" was placed under an EIP-7702 delegation to unverified code and emptied by a sweeper contract. ' +
      'The delegation required authentic signatures from the wallet\'s own key: a transaction carrying 50 signed authorizations over consecutive nonces went on-chain. ' +
      'Binance said no private key appears to have leaked and pointed to a potentially compromised employee (DevOps) laptop and a service container; its co-CEO said ' +
      '"the delegation did not pass through our normal approval controls". Withdrawals were paused across several networks while Tether and Circle froze funds. ' +
      'Analysts attribute the operation to North Korea\'s TraderTraitor / Lazarus, the same crew as Bybit. The EIP-7702 standard was not the flaw; the signing path was.',
    lessons: [
      'A signing service that will sign a type-4 (EIP-7702) authorization for a custody address is a single point of total loss.',
      'Transaction-type, method and destination allowlists must live in the policy engine next to the key (HSM/MPC), not in a UI.',
      'Monitor custody addresses for code: eth_getCode changing from 0x to 0xef0100… is the alarm.',
      'Velocity caps and a withdrawal circuit breaker turn a total drain into a bounded loss.'
    ],
    links: [
      { title: 'Hacken: Binance $6.3B hack analysis', url: 'https://hacken.io/insights/binance-hack/' },
      { title: 'Fireblocks: Deconstructing the Binance exploit', url: 'https://www.fireblocks.com/blog/binance-hack-eip-7702' },
      { title: 'Hypernative: Inside the $6.3B Binance hot-wallet drain', url: 'https://www.hypernative.io/insights/blog/inside-the-largest-crypto-theft-of-all-time-the-6-3b-binance-hot-wallet-drain' },
      { title: 'Cointelegraph: How Binance\'s record $6.3B hack unfolded', url: 'https://cointelegraph.com/news/recap-binances-record-63b-hack-unfolded' },
      { title: 'EIP-7702 specification', url: 'https://eips.ethereum.org/EIPS/eip-7702' }
    ]
  },
  'bybit-2025-02': {
    id: 'bybit-2025-02',
    name: 'Bybit: Safe{Wallet} front-end tampering',
    date: '2025-02-21',
    loss: '≈ $1.5B (401,347 ETH)',
    oneLiner: 'A Safe{Wallet} developer machine was compromised; JavaScript planted in Safe\'s hosting rewrote what Bybit\'s signers saw, and they signed a contract swap.',
    summary:
      'Attackers compromised a Safe{Wallet} developer\'s machine and, on 19 February 2025, placed malicious JavaScript in the bucket serving app.safe.global. ' +
      'It activated only for Bybit\'s cold-wallet signers: the UI showed a routine transfer while the payload signed was a delegatecall that swapped the Safe\'s implementation, ' +
      'after which the attackers drained the wallet on 21 February and removed the code. The FBI attributed the theft to TraderTraitor on 26 February 2025.',
    lessons: [
      'What the screen shows and what the key signs are two different things unless the signing device verifies the payload.',
      'One developer workstation with deploy credentials was the whole blast radius.',
      'Script integrity on the signing page would have refused the modified bundle.'
    ],
    links: [
      { title: 'SlowMist: Bybit\'s $1.5 billion theft unveiled: Safe{Wallet} front-end code tampered', url: 'https://slowmist.medium.com/bybits-1-5-billion-theft-unveiled-safe-wallet-front-end-code-tampered-84b78f0fa9c2' },
      { title: 'The Hacker News: Bybit hack traced to Safe{Wallet} supply chain attack', url: 'https://thehackernews.com/2025/02/bybit-hack-traced-to-safewallet-supply.html' },
      { title: 'SecurityWeek: FBI says North Korea hacked Bybit', url: 'https://www.securityweek.com/fbi-says-north-korea-hacked-bybit-as-details-of-1-5b-heist-emerge/' }
    ]
  },
  'tradertraitor': {
    id: 'tradertraitor',
    name: 'TraderTraitor developer lures',
    date: '2022–present',
    loss: 'Billions across Bybit, Binance (attributed), Radiant and others',
    oneLiner: 'Fake recruiters, "coding tests" and investment tools deliver trojanized npm packages and repos that steal credentials from engineers at exchanges and custodians.',
    summary:
      'TraderTraitor is the FBI\'s name for a North Korean campaign that targets engineers in the crypto industry through long-running social engineering: ' +
      'fake job offers, take-home coding tests, "fix my repo" requests and trading tools. The lure is a repository or npm package whose install or run step ' +
      'steals SSH keys, cloud credentials, browser sessions and signing material, then pivots into CI, cloud and signing infrastructure. ' +
      'The Bybit root cause (a Safe{Wallet} developer machine) and Binance\'s "compromised DevOps laptop" are what this looks like from the victim\'s side.',
    lessons: [
      'Never run npm install on a stranger\'s repository outside a disposable VM. Install scripts are code execution.',
      'Privileged access workstations, ignore-scripts, a registry proxy and a minimum release age cut off the common entry.',
      'Credentials that live on laptops (long-lived cloud keys, npm tokens, .env files) are what gets stolen. Replace them with short-lived, device-bound tokens and OIDC.'
    ],
    links: [
      { title: 'FBI PSA: North Korea aggressively targeting cryptocurrency industry with well-disguised social engineering', url: 'https://www.ic3.gov/PSA/2024/PSA240903' },
      { title: 'CISA AA22-108A: TraderTraitor', url: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-108a' }
    ]
  },
  'ledger-connect-kit-2023-12': {
    id: 'ledger-connect-kit-2023-12',
    name: 'Ledger Connect Kit npm compromise',
    date: '2023-12-14',
    loss: '≈ $600K across many dApps',
    oneLiner: 'A phished npm account published malicious versions of a wallet-connect library that hundreds of dApp front-ends loaded live from a CDN.',
    summary:
      'A former Ledger employee was phished, the attacker published malicious @ledgerhq/connect-kit versions, and dApps that loaded the library without a pinned version or integrity ' +
      'hash served a wallet drainer to their users for about five hours.',
    lessons: ['Load pinned versions with SRI, or self-host. "latest" from a CDN is somebody else\'s deploy pipeline.'],
    links: [{ title: 'Ledger security incident report', url: 'https://www.ledger.com/blog/security-incident-report' }]
  },
  'polyfill-io-2024-06': {
    id: 'polyfill-io-2024-06',
    name: 'polyfill.io domain takeover',
    date: '2024-06',
    loss: '100,000+ sites served malicious code',
    oneLiner: 'The polyfill.io domain and GitHub account were sold; the new owner served malicious JavaScript to every site still embedding it.',
    summary: 'A long-trusted script host changed hands and became hostile. Sites that embedded it without SRI could not tell.',
    lessons: ['Vendor trust is not permanent. Inventory third-party origins and re-review them on a schedule.'],
    links: [{ title: 'Sansec: Polyfill supply chain attack hits 100K+ sites', url: 'https://sansec.io/research/polyfill-supply-chain-attack' }]
  },
  'npm-worms-2025': {
    id: 'npm-worms-2025',
    name: 'npm install-script worms (Shai-Hulud, chalk/debug, nx)',
    date: '2025-08 → 2025-09',
    loss: 'Thousands of stolen npm, GitHub and cloud tokens; crypto-clipper shipped to billions of weekly downloads',
    oneLiner: 'Phished maintainers and postinstall hooks turned popular packages into credential stealers that re-published themselves.',
    summary:
      'In August and September 2025 a run of npm compromises (nx "s1ngularity", the chalk/debug maintainer phish, then the self-replicating Shai-Hulud worm) used install-time scripts to harvest ' +
      'npm tokens, GitHub tokens and cloud credentials from developer machines and CI, then used those tokens to infect more packages.',
    lessons: ['ignore-scripts and a minimum release age would have blocked the install-time stage for most victims.', 'Tokens on disk and in CI env are the prize.'],
    links: [
      { title: 'Unit 42: npm supply chain attack (Shai-Hulud)', url: 'https://unit42.paloaltonetworks.com/npm-supply-chain-attack/' },
      { title: 'GitHub: Our plan for a more secure npm supply chain', url: 'https://github.blog/security/supply-chain-security/our-plan-for-a-more-secure-npm-supply-chain/' }
    ]
  }
};

export const INCIDENT_LIST = Object.values(INCIDENTS);
