# Signer policy (Safetyfirst v1)

A signer policy describes, in one reviewable file, what each signing key is allowed to sign. Safetyfirst lints it for the gaps the Binance (Oct 2026) and Bybit (Feb 2025) attacks walked through. The file is the source of truth; the **signing service (HSM / MPC policy engine) must enforce it next to the key**, because a policy that lives in a UI is one a compromised laptop can step around — which is exactly what Binance's co-CEO described when he said the delegation "did not pass through our normal approval controls."

Load the template from the Harden tab, or `GET /api/policy/template`.

## Schema

```yaml
version: 1
org: <string>
signers:
  - id: <string>                 # a name you recognise
    address: "0x…"               # 20-byte address; lets Safetyfirst cross-check on-chain
    role: hot | warm | cold | deployer
    chainIds: [1, 8453, …]       # chains this key is used on
    allowedTxTypes: [0, 2]       # legacy + EIP-1559. NEVER 4 (EIP-7702) for custody keys.
    allowedMethods: [transfer, withdraw, …]
    maxPerTxUsd: <number>
    maxPerHourUsd: <number>
    maxPerDayUsd: <number>
    destinationAllowlist:
      mode: strict | monitor     # strict = refuse anything not listed
      addresses: ["0x…"]
      newAddressDelayHours: 24    # delay before a newly added destination is usable
    approvals:
      requiredApprovers: 2
      aboveUsd: 100000            # amount above which a second approver is required
    delegation:
      allowEip7702: false         # must be false for custody keys
      allowDelegatecall: false    # how Bybit's Safe implementation was swapped
    tokenApprovals:
      allowed: false              # ERC-20 approve / setApprovalForAll from this key
circuitBreaker:
  enabled: true
  maxOutflowPctPer15m: 10         # pause signing if outflow exceeds this in 15 minutes
  maxNewDestinationsPerHour: 5
  pauseApi: https://…/pause       # the monitor calls this to pause withdrawals
  pager: pagerduty:custody-oncall
changeControl:
  requiredApprovers: 2            # two humans approve any change to this file / the engine
  policyHashAlert: true           # alert when the deployed policy hash differs from approved
contacts:
  issuers:
    - { name: Tether, channel: "pre-arranged freeze contact" }
    - { name: Circle, channel: "pre-arranged freeze contact" }
  analytics:
    - { name: Chainalysis / TRM, channel: "incident desk" }
```

## What the linter checks

| Code | Gap | Why |
|---|---|---|
| P01 | `allowedTxTypes` missing or includes `4` | Type 4 (EIP-7702) is what emptied Binance 14 |
| P02 | `delegation.allowEip7702` not `false` | Delegation must be impossible for custody keys, not merely reviewed |
| P03 | No strict destination allowlist | A sweeper contract is never on the list |
| P04 | No delay for new destinations | Buys time to notice an attacker-added address |
| P05 | Missing velocity caps | One signature should not be able to move everything |
| P06 | No method allowlist, or dangerous methods allowed | `approve`, `upgradeTo`, `setImplementation`, `enableModule`… are the drain primitives |
| P07 | Token approvals not denied for custody keys | Unlimited approvals are a delayed drain |
| P08 | No multi-approval for cold keys / no step-up threshold | Separation of duties |
| P09 | `delegatecall` allowed | The Bybit implementation-swap primitive |
| P10 | No chain allowlist | Replay / wrong-chain risk |
| P12 | No circuit breaker | Detection has to become a pause; minutes matter |
| P13 | Single-person policy changes | The attacker's first move is to loosen the policy |
| P14 | No policy-drift alert | You must know when the deployed policy differs from the approved one |
| P15 | No issuer freeze contacts | Pre-arrange and rehearse stablecoin freezes |

The template passes all of these. Start from it, adjust the numbers to your treasury, and keep the file under the same two-person review as code.
