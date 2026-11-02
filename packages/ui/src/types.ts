export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Module = 'web' | 'repo' | 'chain';
export interface Evidence { location: string; detail: string; line?: number; snippet?: string }
export interface Snippet { title: string; lang: string; code: string }
export interface Fix { summary: string; steps: string[]; snippets?: Snippet[]; effort: string; impact: string }
export interface Finding { id: string; key: string; module: Module; title: string; severity: Severity; killChain: string; stage: string; incidentIds: string[]; summary: string; why: string; evidence: Evidence[]; fix: Fix; references: { title: string; url: string }[]; tags: string[] }
export interface Score { value: number; grade: string; counts: Record<Severity, number> }
export interface ModuleResult { module: Module; target: string; findings: Finding[]; score: Score; meta: Record<string, unknown>; errors: string[] }
export interface KillChainStageStatus { id: string; step: string; guardrail: string; signal: string; status: 'open' | 'covered' | 'unknown'; findingKeys: string[]; worst: Severity | null }
export interface KillChainSummary { id: string; name: string; tagline: string; incidentIds: string[]; stages: KillChainStageStatus[] }
export interface Report { id: string; tool: { name: string; version: string }; createdAt: string; modules: ModuleResult[]; overall: Score; killChains: KillChainSummary[] }
export interface Incident { id: string; name: string; date: string; loss: string; oneLiner: string; summary: string; lessons: string[]; links: { title: string; url: string }[] }
export interface KillChainStage { id: string; step: string; guardrail: string; signal: string; rules: string[] }
export interface KillChain { id: string; name: string; tagline: string; incidentIds: string[]; stages: KillChainStage[] }
export interface Rule { id: string; module: Module; title: string; severity: Severity; killChain: string; stage: string; incidentIds: string[]; why: string; fix: Fix; references: { title: string; url: string }[] }
export interface Knowledge { incidents: Incident[]; killChains: KillChain[]; rules: Rule[]; version: string }
export interface Job { id: string; status: 'running' | 'done' | 'error'; pct: number; message: string; targetSummary: string; report?: Report; error?: string }
