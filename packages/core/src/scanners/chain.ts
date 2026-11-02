import { createPublicClient, http, getAddress, isAddress, pad, type Address, type Hex, type Chain, hexToBigInt, hexToBool } from 'viem';
import { mainnet, base, arbitrum, optimism, polygon, bsc, sepolia } from 'viem/chains';
import type { ChainTarget, Evidence, Finding, ModuleResult, NetworkId, Progress, Severity } from '../types.js';
import { makeFinding } from '../knowledge/index.js';
import { scoreFindings } from '../report/score.js';
import { sortFindings } from './web.js';
import { lintSignerPolicy } from './policy.js';

export const NETWORKS: Record<NetworkId, Chain> = { mainnet, base, arbitrum, optimism, polygon, bsc, sepolia };
export const EXPLORERS: Record<NetworkId, string> = {
  mainnet: 'https://etherscan.io', base: 'https://basescan.org', arbitrum: 'https://arbiscan.io', optimism: 'https://optimistic.etherscan.io', polygon: 'https://polygonscan.com', bsc: 'https://bscscan.com', sepolia: 'https://sepolia.etherscan.io'
};

const APPROVAL_TOPIC = '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925' as Hex; // Approval(address,address,uint256)
const APPROVAL_FOR_ALL_TOPIC = '0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31' as Hex; // ApprovalForAll(address,address,bool)
const UNLIMITED = 1n << 255n;
const HUGE = 10n ** 27n;

export const KNOWN_SPENDERS: Record<string, string> = {
  '0x000000000022d473030f116ddee9f6b43ac78ba3': 'Uniswap Permit2',
  '0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad': 'Uniswap Universal Router',
  '0x66a9893cc07d91d95644aedd05d03f95e1dba8af': 'Uniswap Universal Router v2',
  '0x7a250d5630b4cf539739df2c5dacb4c659f2488d': 'Uniswap V2 Router',
  '0xe592427a0aece92de3edee1f18e0157c05861564': 'Uniswap V3 SwapRouter',
  '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45': 'Uniswap SwapRouter02',
  '0x0000000000000068f116a894984e2db1123eb395': 'OpenSea Seaport 1.6',
  '0x00000000000000adc04c56bf30ac9d3c0aaf14dc': 'OpenSea Seaport 1.5',
  '0x1e0049783f008a0085193e00003d00cd54003c71': 'OpenSea Conduit',
  '0x111111125421ca6dc452d289314280a0f8842a65': '1inch Aggregation Router v6',
  '0x1111111254eeb25477b68fb85ed929f73a960582': '1inch Aggregation Router v5',
  '0xdef1c0ded9bec7f1a1670819833240f027b25eff': '0x Exchange Proxy',
  '0x6131b5fae19ea4f9d964eac0408e4408b66337b5': 'KyberSwap Router',
  '0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae': 'LI.FI Diamond',
  '0x6a000f20005980200259b80c5102003040001068': 'ParaSwap Augustus v6',
  '0xa0c68c638235ee32657e8f720a23cec1bfc77c77': 'Polygon PoS Bridge (RootChainManager)',
  '0x4200000000000000000000000000000000000010': 'OP Stack L2 Standard Bridge',
  '0xc1e7e1a9e9a7a0cf3a9c2d9d8c6a1b1a3d4e5f60': 'example'
};

export function approveZeroCalldata(spender: Address): Hex {
  return (`0x095ea7b3${pad(spender).slice(2)}${'0'.repeat(64)}`) as Hex;
}
export function setApprovalForAllFalseCalldata(operator: Address): Hex {
  return (`0xa22cb465${pad(operator).slice(2)}${'0'.repeat(64)}`) as Hex;
}

interface RawLog { address: Address; topics: Hex[]; data: Hex; blockNumber: Hex; transactionHash: Hex; logIndex: Hex }

export async function scanChain(target: ChainTarget, onProgress: Progress = () => {}): Promise<ModuleResult> {
  const startedAt = new Date().toISOString();
  const findings: Finding[] = [];
  const errors: string[] = [];
  const meta: Record<string, unknown> = {};
  const chain = NETWORKS[target.network];
  const rpcUrl = target.rpcUrl || chain.rpcUrls.default.http[0];
  meta.network = target.network; meta.rpcUrl = rpcUrl; meta.explorer = EXPLORERS[target.network];
  const client = createPublicClient({ chain, transport: http(rpcUrl, { timeout: 25_000, retryCount: 2 }) });
  const knownDelegates = new Set((target.knownDelegates ?? []).map((a) => a.toLowerCase()));
  const knownSpenders = new Set((target.knownSpenders ?? []).map((a) => a.toLowerCase()));
  const addresses = (target.addresses ?? []).map((a) => a.trim()).filter(Boolean);
  const bad = addresses.filter((a) => !isAddress(a));
  if (bad.length) errors.push(`chain: invalid address(es): ${bad.join(', ')}`);
  const valid = addresses.filter((a) => isAddress(a)).map((a) => getAddress(a));
  const perAddress: Record<string, unknown> = {};

  try {
    if (target.policy) {
      onProgress('Linting signer policy', 3);
      try {
        const pf = lintSignerPolicy(target.policy as any);
        findings.push(...pf);
        meta.policyFindings = pf.length;
      } catch (e: any) { errors.push(`policy: ${e?.message ?? e}`); }
    }
    if (!valid.length) {
      meta.addresses = [];
    } else {
      let latest: bigint;
      try { latest = await client.getBlockNumber(); } catch (e: any) { throw new Error(`RPC ${rpcUrl} unreachable: ${e?.shortMessage ?? e?.message ?? e}`); }
      meta.latestBlock = latest.toString();
      const lookback = BigInt(Math.max(1000, target.lookbackBlocks ?? 250_000));
      const fromBlock = latest > lookback ? latest - lookback : 0n;
      meta.lookback = { fromBlock: fromBlock.toString(), toBlock: latest.toString(), blocks: (latest - fromBlock).toString() };

      for (const [ai, addr] of valid.entries()) {
        const basePct = 5 + Math.floor((ai / valid.length) * 90);
        onProgress(`${addr}: checking account code (EIP-7702)`, basePct);
        const info: Record<string, unknown> = {};
        perAddress[addr] = info;
        const code = (await client.getCode({ address: addr })) ?? '0x';
        info.code = code.length > 80 ? code.slice(0, 80) + '…' : code;
        if (code.toLowerCase().startsWith('0xef0100') && code.length === 48) {
          const delegate = getAddress(('0x' + code.slice(8)) as Hex);
          info.delegate = delegate;
          const known = knownDelegates.has(delegate.toLowerCase());
          let delegateCode = '0x';
          try { delegateCode = (await client.getCode({ address: delegate })) ?? '0x'; } catch { /* ignore */ }
          findings.push(makeFinding('C1', {
            key: `C1:${target.network}:${addr}`,
            summary: known ? `${addr} is delegated to an approved contract (${delegate}).` : `${addr} is delegated to ${delegate}. If you did not install this, treat it as an active compromise.`,
            severity: known ? 'info' : 'critical',
            evidence: [
              { location: addr, detail: `eth_getCode = ${code} (EIP-7702 designator)` },
              { location: delegate, detail: `delegate contract ${delegateCode === '0x' ? 'has NO code (points at an EOA or self-destructed contract)' : `has ${(delegateCode.length - 2) / 2} bytes of code`} · ${EXPLORERS[target.network]}/address/${delegate}#code` }
            ],
            tags: known ? ['approved-delegate'] : ['eip-7702']
          }));
        } else if (code !== '0x') {
          findings.push(makeFinding('C4', {
            key: `C4:${target.network}:${addr}`,
            summary: `${addr} is a smart contract (${(code.length - 2) / 2} bytes).`,
            evidence: [{ location: addr, detail: `Contract account · ${EXPLORERS[target.network]}/address/${addr}#code` }]
          }));
        }

        // ---------------- approvals
        onProgress(`${addr}: scanning Approval events (${(latest - fromBlock).toString()} blocks)`, basePct + 3);
        const ownerTopic = pad(addr) as Hex;
        const { logs: erc20Logs, partial: p1, requests: r1 } = await getLogsChunked(client, [APPROVAL_TOPIC, ownerTopic], fromBlock, latest);
        const { logs: allLogs, partial: p2, requests: r2 } = await getLogsChunked(client, [APPROVAL_FOR_ALL_TOPIC, ownerTopic], fromBlock, latest);
        info.approvalLogs = erc20Logs.length; info.approvalForAllLogs = allLogs.length; info.partialCoverage = p1 || p2; info.rpcRequests = r1 + r2;

        const latestAllowance = new Map<string, { token: Address; spender: Address; value: bigint; tx: Hex }>();
        for (const l of erc20Logs) {
          if (l.topics.length !== 3 || !l.data || l.data === '0x' || l.data.length !== 66) continue; // ERC-721 Approval has 4 topics
          const spender = getAddress(('0x' + l.topics[2].slice(26)) as Hex);
          latestAllowance.set(`${l.address.toLowerCase()}:${spender.toLowerCase()}`, { token: getAddress(l.address), spender, value: hexToBigInt(l.data), tx: l.transactionHash });
        }
        const latestOperator = new Map<string, { collection: Address; operator: Address; approved: boolean; tx: Hex }>();
        for (const l of allLogs) {
          if (l.topics.length !== 3 || l.data.length !== 66) continue;
          const operator = getAddress(('0x' + l.topics[2].slice(26)) as Hex);
          latestOperator.set(`${l.address.toLowerCase()}:${operator.toLowerCase()}`, { collection: getAddress(l.address), operator, approved: hexToBool(l.data), tx: l.transactionHash });
        }
        const candidates = [...latestAllowance.values()].filter((a) => a.value >= HUGE).slice(0, 120);
        const operators = [...latestOperator.values()].filter((a) => a.approved).slice(0, 120);
        onProgress(`${addr}: verifying ${candidates.length + operators.length} candidate approval(s) on-chain`, basePct + 8);
        const unlimited: Array<{ token: Address; symbol: string; spender: Address; label: string | null; spenderIsEoa: boolean; allowance: bigint; tx: Hex }> = [];
        for (const c of candidates) {
          let current: bigint;
          try {
            current = await client.readContract({ address: c.token, abi: ERC20, functionName: 'allowance', args: [addr, c.spender] });
          } catch { continue; }
          if (current < HUGE) continue;
          const symbol = await client.readContract({ address: c.token, abi: ERC20, functionName: 'symbol' }).catch(() => c.token.slice(0, 10));
          const spenderCode = await client.getCode({ address: c.spender }).catch(() => '0x' as Hex);
          unlimited.push({ token: c.token, symbol: String(symbol), spender: c.spender, label: KNOWN_SPENDERS[c.spender.toLowerCase()] ?? null, spenderIsEoa: !spenderCode || spenderCode === '0x', allowance: current, tx: c.tx });
        }
        const operatorsLive: Array<{ collection: Address; operator: Address; label: string | null; operatorIsEoa: boolean; tx: Hex }> = [];
        for (const o of operators) {
          let live = false;
          try { live = await client.readContract({ address: o.collection, abi: ERC721, functionName: 'isApprovedForAll', args: [addr, o.operator] }); } catch { continue; }
          if (!live) continue;
          const opCode = await client.getCode({ address: o.operator }).catch(() => '0x' as Hex);
          operatorsLive.push({ collection: o.collection, operator: o.operator, label: KNOWN_SPENDERS[o.operator.toLowerCase()] ?? null, operatorIsEoa: !opCode || opCode === '0x', tx: o.tx });
        }
        info.unlimitedApprovals = unlimited.map((u) => ({ ...u, allowance: u.allowance.toString() }));
        info.operatorApprovals = operatorsLive;

        for (const u of unlimited) {
          const intentional = knownSpenders.has(u.spender.toLowerCase());
          const sev: Severity = u.spenderIsEoa ? 'critical' : intentional ? 'low' : u.label ? 'medium' : 'high';
          findings.push(makeFinding('C2', {
            key: `C2:${target.network}:${addr}:${u.token}:${u.spender}`,
            summary: `${addr.slice(0, 8)}… has an unlimited ${u.symbol} approval to ${u.label ?? u.spender}${u.spenderIsEoa ? ' — the spender is an EOA, not a contract (drainer pattern)' : ''}.`,
            severity: sev,
            evidence: [
              { location: `${u.symbol} ${u.token}`, detail: `allowance(${addr.slice(0, 8)}…, ${u.spender.slice(0, 10)}…) = ${u.allowance >= UNLIMITED ? 'unlimited (≥ 2^255)' : u.allowance.toString()} · set in tx ${u.tx}` },
              { location: u.spender, detail: `${u.label ? `known: ${u.label}` : 'unknown spender'} · ${u.spenderIsEoa ? 'NO contract code' : 'contract'} · ${EXPLORERS[target.network]}/address/${u.spender}` },
              { location: 'revoke calldata', detail: `to: ${u.token} · data: ${approveZeroCalldata(u.spender)}` }
            ],
            extraSnippets: [{ title: `Revoke ${u.symbol} → ${u.label ?? u.spender.slice(0, 10) + '…'}`, lang: 'bash', code: `cast send ${u.token} "approve(address,uint256)" ${u.spender} 0 --rpc-url $RPC --ledger` }],
            tags: [u.spenderIsEoa ? 'eoa-spender' : u.label ? 'known-spender' : 'unknown-spender']
          }));
        }
        for (const o of operatorsLive) {
          const intentional = knownSpenders.has(o.operator.toLowerCase());
          findings.push(makeFinding('C2', {
            key: `C2:${target.network}:${addr}:${o.collection}:${o.operator}:all`,
            summary: `${addr.slice(0, 8)}… granted setApprovalForAll on ${o.collection.slice(0, 10)}… to ${o.label ?? o.operator}${o.operatorIsEoa ? ' — operator is an EOA (drainer pattern)' : ''}.`,
            severity: o.operatorIsEoa ? 'critical' : intentional ? 'low' : o.label ? 'medium' : 'high',
            evidence: [
              { location: o.collection, detail: `isApprovedForAll(${addr.slice(0, 8)}…, ${o.operator.slice(0, 10)}…) = true · set in tx ${o.tx}` },
              { location: o.operator, detail: `${o.label ? `known: ${o.label}` : 'unknown operator'} · ${o.operatorIsEoa ? 'NO contract code' : 'contract'}` },
              { location: 'revoke calldata', detail: `to: ${o.collection} · data: ${setApprovalForAllFalseCalldata(o.operator)}` }
            ],
            tags: ['nft-operator']
          }));
        }
      }
      meta.addresses = perAddress;
    }
    onProgress('Chain scan complete', 100);
  } catch (e: any) {
    errors.push(`chain: ${e?.shortMessage ?? e?.message ?? String(e)}`);
  }
  return { module: 'chain', target: `${target.network}: ${valid.join(', ') || (target.policy ? 'signer policy' : 'no addresses')}`, startedAt, finishedAt: new Date().toISOString(), findings: sortFindings(findings), score: scoreFindings(findings), meta, errors };
}

async function getLogsChunked(client: ReturnType<typeof createPublicClient>, topics: Hex[], from: bigint, to: bigint): Promise<{ logs: RawLog[]; partial: boolean; requests: number }> {
  const logs: RawLog[] = [];
  let step = 20_000n;
  let cursor = from;
  let requests = 0;
  const MAX_REQUESTS = 90;
  while (cursor <= to) {
    if (requests >= MAX_REQUESTS) return { logs, partial: true, requests };
    const end = cursor + step - 1n > to ? to : cursor + step - 1n;
    try {
      requests++;
      const res = (await client.request({ method: 'eth_getLogs', params: [{ fromBlock: `0x${cursor.toString(16)}`, toBlock: `0x${end.toString(16)}`, topics }] } as any)) as RawLog[];
      logs.push(...res);
      cursor = end + 1n;
      if (res.length < 500 && step < 100_000n) step *= 2n;
    } catch (e: any) {
      const msg = String(e?.details ?? e?.shortMessage ?? e?.message ?? e).toLowerCase();
      if (/range|limit|too many|exceed|10000|response size|timeout|larger than|block range|query returned|max/i.test(msg) && step > 1_000n) { step /= 2n; continue; }
      if (step > 1_000n) { step /= 2n; continue; }
      throw new Error(`eth_getLogs failed: ${e?.shortMessage ?? e?.message ?? e}`);
    }
  }
  return { logs, partial: false, requests };
}

const ERC20 = [
  { type: 'function', name: 'allowance', stateMutability: 'view', inputs: [{ name: 'owner', type: 'address' }, { name: 'spender', type: 'address' }], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'symbol', stateMutability: 'view', inputs: [], outputs: [{ type: 'string' }] }
] as const;
const ERC721 = [
  { type: 'function', name: 'isApprovedForAll', stateMutability: 'view', inputs: [{ name: 'owner', type: 'address' }, { name: 'operator', type: 'address' }], outputs: [{ type: 'bool' }] }
] as const;
