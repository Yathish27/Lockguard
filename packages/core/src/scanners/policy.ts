import { parse as parseYaml } from 'yaml';
import type { Evidence, Finding, Severity } from '../types.js';
import { makeFinding } from '../knowledge/index.js';

/** Safetyfirst signer policy, version 1. See docs/signer-policy.md. */
export const SIGNER_POLICY_TEMPLATE = `# Safetyfirst signer policy v1
# Describe what each signing key is allowed to sign. The signing service (HSM / MPC policy engine) enforces it;
# this file is the reviewable source of truth and is what Safetyfirst lints.
version: 1
org: Example Exchange
signers:
  - id: hot-eth-1
    address: "0x0000000000000000000000000000000000000001"
    role: hot                     # hot | warm | cold | deployer
    chainIds: [1, 8453, 42161]
    allowedTxTypes: [0, 2]        # legacy + EIP-1559. Never 4 (EIP-7702) for custody keys.
    allowedMethods: [transfer, transferFrom, withdraw]
    maxPerTxUsd: 250000
    maxPerHourUsd: 1000000
    maxPerDayUsd: 5000000
    destinationAllowlist:
      mode: strict                # strict: refuse anything not listed. monitor: allow but alert.
      addresses: ["0x0000000000000000000000000000000000000002"]
      newAddressDelayHours: 24
    approvals:
      requiredApprovers: 2
      aboveUsd: 100000
    delegation:
      allowEip7702: false
      allowDelegatecall: false
    tokenApprovals:
      allowed: false              # ERC-20 approve / setApprovalForAll from this key
  - id: cold-treasury
    address: "0x0000000000000000000000000000000000000003"
    role: cold
    chainIds: [1]
    allowedTxTypes: [2]
    allowedMethods: [transfer, execTransaction]
    maxPerTxUsd: 20000000
    maxPerDayUsd: 50000000
    destinationAllowlist: { mode: strict, addresses: ["0x0000000000000000000000000000000000000001"], newAddressDelayHours: 48 }
    approvals: { requiredApprovers: 3, aboveUsd: 0 }
    delegation: { allowEip7702: false, allowDelegatecall: false }
    tokenApprovals: { allowed: false }
circuitBreaker:
  enabled: true
  maxOutflowPctPer15m: 10         # pause all signers if outflow > 10% of hot balance in 15 minutes
  maxNewDestinationsPerHour: 5
  pauseApi: https://internal.example/withdrawals/pause
  pager: pagerduty:custody-oncall
changeControl:
  requiredApprovers: 2            # two humans approve any change to this file / the engine config
  policyHashAlert: true           # alert when the deployed policy hash differs from the approved one
contacts:
  issuers:
    - { name: Tether, channel: "compliance@tether.to (pre-arranged freeze contact)" }
    - { name: Circle, channel: "pre-arranged freeze contact" }
  analytics:
    - { name: Chainalysis / TRM, channel: "incident desk" }
`;

export function parsePolicy(input: string | Record<string, unknown>): Record<string, any> {
  if (typeof input !== 'string') return input as Record<string, any>;
  const t = input.trim();
  if (!t) throw new Error('Empty policy');
  try { return JSON.parse(t); } catch { /* fall through */ }
  const y = parseYaml(t);
  if (!y || typeof y !== 'object') throw new Error('Policy must be a JSON or YAML object');
  return y as Record<string, any>;
}

const CUSTODY = new Set(['hot', 'warm', 'cold']);

export function lintSignerPolicy(input: string | Record<string, unknown>): Finding[] {
  const p = parsePolicy(input);
  const out: Finding[] = [];
  const add = (code: string, where: string, title: string, severity: Severity, summary: string, detail: string, steps: string[] = []) =>
    out.push(makeFinding('C3', { key: `C3:${code}:${where}`, title: `Signer policy gap: ${title}`, severity, summary, evidence: [{ location: where, detail }], tags: [code], extraSteps: steps }));

  const signers: any[] = Array.isArray(p.signers) ? p.signers : [];
  if (!signers.length) add('P00', 'signers', 'no signers declared', 'info', 'The policy declares no signers, so nothing is constrained.', 'signers: [] or missing');

  signers.forEach((s, i) => {
    const where = `signers[${i}] (${s.id ?? s.address ?? 'unnamed'})`;
    const role = String(s.role ?? 'hot');
    const custody = CUSTODY.has(role);
    const hot = role === 'hot' || role === 'warm';
    const types: number[] | null = Array.isArray(s.allowedTxTypes) ? s.allowedTxTypes.map(Number) : null;
    if (!types) add('P01', where, 'transaction types unrestricted', custody ? 'critical' : 'high', `${s.id ?? where} may sign any transaction type, including type 4 (EIP-7702 delegation).`, 'allowedTxTypes missing', ['Set allowedTxTypes: [0, 2] (or [2]). Type 4 is what emptied Binance 14.']);
    else if (types.includes(4)) add('P01', where, 'EIP-7702 delegation allowed', custody ? 'critical' : 'high', `${s.id ?? where} is allowed to sign type-4 (EIP-7702) transactions.`, `allowedTxTypes: [${types.join(', ')}]`, ['Remove 4 from allowedTxTypes for every custody signer.']);
    const del = s.delegation ?? {};
    if (del.allowEip7702 !== false) add('P02', where, 'delegation not explicitly denied', custody ? 'critical' : 'high', `${s.id ?? where} does not explicitly deny EIP-7702 delegation (delegation.allowEip7702).`, `delegation.allowEip7702 = ${JSON.stringify(del.allowEip7702)}`, ['Set delegation.allowEip7702: false and make the engine reject any authorizationList.']);
    if (custody && del.allowDelegatecall !== false) add('P09', where, 'delegatecall allowed', role === 'cold' ? 'high' : 'medium', `${s.id ?? where} can approve delegatecall operations (how Bybit's Safe implementation was swapped).`, `delegation.allowDelegatecall = ${JSON.stringify(del.allowDelegatecall)}`, ['Set delegation.allowDelegatecall: false; for Safe, refuse operation=1 unless a separate break-glass process is invoked.']);
    const da = s.destinationAllowlist;
    if (!da) add('P03', where, 'no destination allowlist', hot ? 'high' : 'medium', `${s.id ?? where} can send to any address.`, 'destinationAllowlist missing', ['Add destinationAllowlist with mode: strict. Sweeper contracts are never on the list.']);
    else {
      if (da.mode !== 'strict') add('P03', where, 'destination allowlist not enforced', hot ? 'high' : 'medium', `${s.id ?? where} destination allowlist is "${da.mode ?? 'unset'}" (not strict).`, `destinationAllowlist.mode = ${JSON.stringify(da.mode)}`, ['Set mode: strict.']);
      if (!(Number(da.newAddressDelayHours) >= 1)) add('P04', where, 'no delay for new destinations', 'medium', `${s.id ?? where} can use a newly added destination immediately.`, `destinationAllowlist.newAddressDelayHours = ${JSON.stringify(da.newAddressDelayHours)}`, ['Require 24h (hot) / 48h (cold) between adding a destination and sending to it.']);
    }
    const caps = ['maxPerTxUsd', 'maxPerHourUsd', 'maxPerDayUsd'].filter((k) => !(Number(s[k]) > 0));
    if (caps.length === 3) add('P05', where, 'no velocity caps', hot ? 'high' : 'medium', `${s.id ?? where} has no per-transaction, hourly or daily caps: one signature can move everything.`, 'maxPerTxUsd / maxPerHourUsd / maxPerDayUsd missing', ['Set all three caps. For hot wallets, the daily cap bounds the worst day.']);
    else if (caps.length) add('P05', where, 'incomplete velocity caps', 'medium', `${s.id ?? where} is missing ${caps.join(', ')}.`, `missing: ${caps.join(', ')}`);
    const methods: string[] | null = Array.isArray(s.allowedMethods) ? s.allowedMethods.map(String) : null;
    if (!methods) add('P06', where, 'no method allowlist', 'medium', `${s.id ?? where} may call any contract method.`, 'allowedMethods missing', ['Allowlist the methods this key legitimately calls (transfer, transferFrom, withdraw…).']);
    else {
      const risky = methods.filter((m) => /^(approve|setApprovalForAll|increaseAllowance|permit|upgradeTo|upgradeToAndCall|changeMasterCopy|setImplementation|enableModule|addOwner|changeThreshold|setFallbackHandler)$/i.test(m));
      if (risky.length) add('P06', where, 'dangerous methods allowed', hot ? 'high' : 'medium', `${s.id ?? where} may call ${risky.join(', ')}.`, `allowedMethods includes ${risky.join(', ')}`, ['Move these behind a separate break-glass signer with multi-approval; approvals should be exact-amount and to allowlisted spenders only.']);
    }
    const ta = s.tokenApprovals;
    if (custody && ta?.allowed !== false) add('P07', where, 'token approvals not denied', 'medium', `${s.id ?? where} does not explicitly deny ERC-20 approve / setApprovalForAll.`, `tokenApprovals.allowed = ${JSON.stringify(ta?.allowed)}`, ['Set tokenApprovals.allowed: false for custody keys.']);
    const ap = s.approvals ?? {};
    const req = Number(ap.requiredApprovers ?? 0);
    if (role === 'cold' && req < 2) add('P08', where, 'cold signer without multi-approval', 'high', `${s.id ?? where} (cold) requires ${req || 'no'} approver(s).`, `approvals.requiredApprovers = ${JSON.stringify(ap.requiredApprovers)}`, ['Cold / treasury movements need ≥ 2 (ideally 3) independent approvers on separate devices.']);
    else if (hot && (req < 2 || !(Number(ap.aboveUsd) >= 0))) add('P08', where, 'no step-up approval threshold', 'medium', `${s.id ?? where} has no amount above which a second approver is required.`, `approvals = ${JSON.stringify(ap)}`, ['Add approvals: { requiredApprovers: 2, aboveUsd: <threshold> }.']);
    if (!Array.isArray(s.chainIds) || !s.chainIds.length) add('P10', where, 'no chain allowlist', 'medium', `${s.id ?? where} may sign for any chain id (replay / wrong-chain risk).`, 'chainIds missing', ['List the chain ids this key is used on.']);
    if (!s.address || !/^0x[0-9a-fA-F]{40}$/.test(String(s.address))) add('P11', where, 'signer address missing', 'low', `${s.id ?? where} has no valid address, so Safetyfirst cannot cross-check it on-chain.`, `address = ${JSON.stringify(s.address)}`);
  });

  const cb = p.circuitBreaker;
  if (!cb || cb.enabled === false) add('P12', 'circuitBreaker', 'no circuit breaker', 'high', 'Nothing pauses signing automatically when outflow spikes.', `circuitBreaker = ${JSON.stringify(cb)}`, ['Add circuitBreaker with maxOutflowPctPer15m, a pauseApi the monitor can call, and a pager target. Minutes matter.']);
  else {
    if (!(Number(cb.maxOutflowPctPer15m) > 0)) add('P12', 'circuitBreaker', 'circuit breaker without outflow threshold', 'medium', 'The circuit breaker has no outflow threshold.', 'circuitBreaker.maxOutflowPctPer15m missing');
    if (!cb.pauseApi) add('P12', 'circuitBreaker', 'circuit breaker cannot pause anything', 'medium', 'No pauseApi: detection cannot become a pause.', 'circuitBreaker.pauseApi missing');
  }
  const cc = p.changeControl ?? {};
  if (!(Number(cc.requiredApprovers) >= 2)) add('P13', 'changeControl', 'single-person policy changes', 'high', 'One person can change the signing policy.', `changeControl.requiredApprovers = ${JSON.stringify(cc.requiredApprovers)}`, ['Require two approvers for any change to this file or the engine config; the attacker\'s first move is to loosen the policy.']);
  if (cc.policyHashAlert !== true) add('P14', 'changeControl', 'no policy-drift alert', 'medium', 'Nobody is alerted when the deployed policy differs from the approved one.', `changeControl.policyHashAlert = ${JSON.stringify(cc.policyHashAlert)}`, ['Hash the deployed policy on a schedule and alert on any change lacking two approvals.']);
  if (!p.contacts?.issuers?.length) add('P15', 'contacts', 'no issuer freeze contacts', 'low', 'No pre-arranged stablecoin issuer contacts for emergency freezes.', 'contacts.issuers missing', ['Pre-arrange Tether / Circle freeze contacts and rehearse the request twice a year.']);
  return out;
}
