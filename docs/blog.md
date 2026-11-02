# Two hacks in one day, $6.3B and $2.7M, and not one broken contract

On 29 October 2026 the crypto industry had its worst single day on record, and the postmortems all pointed somewhere surprising. Nobody found a reentrancy bug. Nobody found an integer overflow. The smart contracts did exactly what they were written to do.

Binance lost billions from a hot wallet. Polymarket lost about $2.7 million from hundreds of traders. The two incidents look unrelated until you line them up against a third, from eight months earlier, and notice they are the same story told three ways. All three came in through things a developer sets up on an ordinary Tuesday: a third-party script, a signing pipeline, a laptop with credentials on it.

This post walks through what actually happened, the three risks you create without noticing, and a tool you can run against your own stack in five minutes.

## What actually happened

**Polymarket (29 Oct 2026, ≈ $2.7M).** Polymarket's site loaded a page-speed monitoring script from a third-party vendor. That script was swapped for a malicious version (the vendor, DebugBear, attributed it to a DNS hijack of the host it was served from). Running inside polymarket.com with the full authority of first-party code, the script read the account material the site kept in the browser — including a set of trading API keys — and used it to sell positions and move assets. Polymarket pulled the script within the hour, reset every session, paused trading, and refunded $3.9M. It was the platform's *second* third-party script compromise of the year.

**Bybit (21 Feb 2025, ≈ $1.5B).** Attackers compromised a Safe{Wallet} developer's machine and planted JavaScript in the infrastructure that served Safe's app. It activated only for Bybit's signers: the screen showed a routine transfer while the transaction actually being signed swapped the wallet's implementation. The signers approved what they saw; what they signed was something else. The FBI attributed it to North Korea's TraderTraitor.

**Binance (29 Oct 2026, ≈ $6.3B by Binance's estimate).** The hot wallet "Binance 14" was placed under an **EIP-7702 delegation** to an attacker-controlled "sweeper" contract and emptied. EIP-7702, shipped with Ethereum's Pectra upgrade, lets an account delegate to contract code, and the delegation requires a genuine signature from the account's own key. One transaction carried fifty signed authorizations. Binance said no private key leaked and pointed to a compromised DevOps laptop; its co-CEO said the delegation "did not pass through our normal approval controls." Analysts attribute it to the same crew as Bybit. The EIP itself was not the flaw. The signing path was.

Three incidents, one shape: **the system did what it was told, by someone who should never have been able to tell it.**

## The three risks developers create without noticing

### 1. A third-party script is first-party code

When you add `<script src="https://vendor.example/widget.js">` to a page, that code runs with the same authority as your own. It can read anything your JavaScript can read: `localStorage`, non-`HttpOnly` cookies, anything in the DOM, your API responses. Analytics, session replay, tag managers, chat widgets, performance monitors — each one is a company whose next deploy, or whose next breach, runs in your users' browsers.

Polymarket is what this looks like when it goes wrong. The fix is not "trust better vendors." It is to assume any third-party script can turn hostile and to make that survivable:

- **Subresource Integrity** so the browser refuses a script whose bytes changed.
- A **strict, nonce-based Content Security Policy** so an injected or swapped script does not run, and `connect-src` so it cannot phone stolen data home.
- **No third-party JavaScript at all** on pages that sign, trade or withdraw.
- **Script-hash monitoring** so a swap pages someone in minutes, not hours.
- **Secrets out of JavaScript's reach:** sessions in `HttpOnly` cookies, never API keys or key material in the browser.

### 2. Your supply chain starts on a laptop

TraderTraitor — the FBI's name for the campaign behind Bybit and, per Binance, the October attack — does not start with a zero-day. It starts with a fake recruiter, a take-home coding test, a "please review my repo." The lure is a repository or npm package whose install step runs code on an engineer's machine and steals SSH keys, cloud credentials and session tokens. From there it pivots into CI, cloud and the signing path.

`npm install` executes `postinstall` scripts from every dependency as you. That is the entry point. The 2025 npm worms (Shai-Hulud, the chalk/debug phish) used the same hook to steal tokens from thousands of machines. The fixes are unglamorous and effective:

- `ignore-scripts` on developer machines and CI; allowlist the few packages that truly need a build step.
- A committed lockfile and frozen installs.
- GitHub Actions pinned to **commit SHAs**, not tags a maintainer can move.
- **OIDC** in CI instead of long-lived cloud keys.
- Nothing sensitive committed; secret scanning with push protection.
- A registry proxy and a minimum release age, so a poisoned version has to survive public scrutiny before it reaches you.

### 3. A signer that signs anything is a single point of total loss

The Binance key never leaked. The signing *service* produced a valid signature for a transaction it should have refused. That is the whole lesson. A key is only as safe as the policy sitting in front of it, and that policy has to live next to the key — in the HSM or MPC policy engine — not in a UI a compromised laptop can step around.

A signer for a custody wallet should refuse, by default:

- transaction **type 4** (EIP-7702 delegation) — the exact thing that emptied Binance 14;
- destinations not on an allowlist, with a delay before a new one is usable;
- amounts over a cap, with per-transaction, hourly and daily velocity limits and a circuit breaker;
- `approve` / `setApprovalForAll` / implementation swaps, unless a separate break-glass process is invoked;
- any change to the policy itself without two approvers.

On-chain, the same posture shows up as two checks you can run today: is any address you control **delegated** to code you did not install, and do you have **unlimited approvals** outstanding to spenders you no longer use?

## Watch it happen: the lab

Reading about a DOM-storage token is abstract. Watching one get stolen is not. Lockguard ships a tiny exchange that runs entirely on your machine, in two builds.

Open the **vulnerable** build, log in, and it stashes a session token and a trading API key in `localStorage` — the way Polymarket's front-end kept trading keys in the browser. Now flip the pretend vendor CDN to "compromised" and reload. A cross-origin script reads the token, calls the exchange's own withdraw API as you, and rewrites the screen. The balance is gone.

Open the **hardened** build and do the same thing. The session is an `HttpOnly` cookie the script cannot read. The browser refuses the swapped script because its hash no longer matches the pinned SRI value. Withdrawals need a step-up token the script cannot mint. The attack fails three times over. Same app, two postures, and you can see exactly which line of defense caught it.

There is no real exploit code in the lab. It only ever attacks its own in-memory balance.

## Check yourself: the scanner

Lockguard's UI has three scanners. Point the **web** module at a site you own and it inventories every third-party origin, flags scripts without SRI, grades your CSP, and finds session tokens or API keys sitting in `localStorage`. Point the **repo** module at a checkout and it finds install scripts, committed secrets, unpinned actions and static cloud keys. Point the **chain** module at your addresses and it checks for EIP-7702 delegations and unlimited approvals, and lints your signer policy.

Every finding comes with the real incident it maps to, why it matters, and a fix you can copy. The results group into the three kill chains above, so you see "this is the step where Polymarket happened to you," not a flat list.

## Fix list, by effort vs impact

If you do nothing else:

1. **Move session tokens into `HttpOnly` cookies and get API keys out of the browser.** Minutes. Stops the Polymarket payload cold.
2. **Add SRI to every external script and pin versions.** Minutes. Turns a vendor compromise into a broken widget.
3. **`ignore-scripts` on dev and CI; commit your lockfile.** Minutes. Closes the TraderTraitor install-time entry.
4. **Ship a strict nonce-based CSP in report-only, then enforce.** Hours. Stops injected scripts running and data leaving.
5. **Pin GitHub Actions to SHAs and move CI to OIDC.** Hours. Removes the movable tag and the long-lived key.
6. **Forbid tx type 4 and unknown destinations at the signer; add velocity caps and a circuit breaker.** Days. Makes a compromised laptop a bounded loss instead of a total one.

Run it against your own stack: `npm install && npm start`. Everything stays on your machine.

*Incident figures are from public reporting at the time of writing; where sources disagree, Lockguard's knowledge base says so. Sources are listed in [`docs/incidents.md`](incidents.md).*
