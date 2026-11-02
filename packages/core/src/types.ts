export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Module = 'web' | 'repo' | 'chain';
export type KillChainId = 'vendor-script' | 'supply-chain' | 'signer-abuse';
export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export interface Evidence {
  /** Where it was seen: a URL, a file path, an address... */
  location: string;
  detail: string;
  line?: number;
  snippet?: string;
}

export interface Snippet {
  title: string;
  lang: string;
  code: string;
}

export interface Fix {
  summary: string;
  steps: string[];
  snippets?: Snippet[];
  effort: 'minutes' | 'hours' | 'days';
  impact: 'high' | 'medium' | 'low';
}

export interface Incident {
  id: string;
  name: string;
  date: string;
  loss: string;
  oneLiner: string;
  summary: string;
  lessons: string[];
  links: Array<{ title: string; url: string }>;
}

export interface KillChainStage {
  id: string;
  step: string;
  guardrail: string;
  signal: string;
  rules: string[];
}

export interface KillChain {
  id: KillChainId;
  name: string;
  tagline: string;
  incidentIds: string[];
  stages: KillChainStage[];
}

export interface RuleDef {
  id: string;
  module: Module;
  title: string;
  severity: Severity;
  killChain: KillChainId;
  stage: string;
  incidentIds: string[];
  why: string;
  fix: Fix;
  references: Array<{ title: string; url: string }>;
}

export interface Finding {
  /** Rule id, e.g. "W2" */
  id: string;
  /** Unique per instance, e.g. "W2:https://cdn.example/x.js" */
  key: string;
  module: Module;
  title: string;
  severity: Severity;
  killChain: KillChainId;
  stage: string;
  incidentIds: string[];
  /** One line, instance-specific */
  summary: string;
  why: string;
  evidence: Evidence[];
  fix: Fix;
  references: Array<{ title: string; url: string }>;
  tags: string[];
}

export interface Score {
  value: number;
  grade: Grade;
  counts: Record<Severity, number>;
}

export interface ModuleResult {
  module: Module;
  target: string;
  startedAt: string;
  finishedAt: string;
  findings: Finding[];
  score: Score;
  meta: Record<string, unknown>;
  errors: string[];
}

export interface KillChainStageStatus {
  id: string;
  step: string;
  guardrail: string;
  signal: string;
  status: 'open' | 'covered' | 'unknown';
  findingKeys: string[];
  worst: Severity | null;
}

export interface KillChainSummary {
  id: KillChainId;
  name: string;
  tagline: string;
  incidentIds: string[];
  stages: KillChainStageStatus[];
}

export interface Report {
  id: string;
  tool: { name: string; version: string };
  createdAt: string;
  targets: ScanTargets;
  modules: ModuleResult[];
  overall: Score;
  killChains: KillChainSummary[];
}

export type Progress = (message: string, pct?: number) => void;

export interface WebTarget {
  url: string;
  /** Playwright storageState JSON (cookies + localStorage) exported from your own logged-in browser. */
  storageState?: unknown;
  /** Force "signing page" severity escalation. 'auto' uses heuristics. */
  signingPage?: boolean | 'auto';
  /** Extra registrable domains you own (treated as first-party). */
  firstPartyDomains?: string[];
  /** Compare script hashes against a saved baseline. */
  baseline?: Baseline | null;
  timeoutMs?: number;
  settleMs?: number;
  ignoreHTTPSErrors?: boolean;
}

export interface RepoTarget {
  path: string;
}

export type NetworkId = 'mainnet' | 'base' | 'arbitrum' | 'optimism' | 'polygon' | 'bsc' | 'sepolia';

export interface ChainTarget {
  addresses: string[];
  network: NetworkId;
  rpcUrl?: string;
  /** How many blocks back to look for Approval events (default 250000). */
  lookbackBlocks?: number;
  /** Delegate contract addresses you approved (EIP-7702). */
  knownDelegates?: string[];
  /** Spenders you approved intentionally. */
  knownSpenders?: string[];
  /** Signer policy document (JSON or YAML string, or object) for the linter. */
  policy?: string | Record<string, unknown> | null;
}

export interface ScanTargets {
  web?: WebTarget;
  repo?: RepoTarget;
  chain?: ChainTarget;
}

export interface BaselineScript {
  url: string;
  origin: string;
  sha256: string;
  sha384: string;
  bytes: number;
}

export interface Baseline {
  version: 1;
  url: string;
  host: string;
  createdAt: string;
  scripts: BaselineScript[];
}

export interface ScriptObservation {
  url: string;
  origin: string;
  thirdParty: boolean;
  inDom: boolean;
  integrity: string | null;
  crossOrigin: string | null;
  nonce: boolean;
  status: number | null;
  bytes: number;
  sha256: string | null;
  sha384: string | null;
  category: string | null;
  categoryRisk: 'critical' | 'high' | 'medium' | 'low' | null;
}
