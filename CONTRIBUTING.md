# Contributing to Safetyfirst

Safetyfirst grows by adding checks that map to real incidents. The bar for a new check: it must correspond to a weakness that was actually exploited (or is a direct, documented precondition), and it must come with a hands-on fix.

## Layout

- `packages/core/src/knowledge/` — the knowledge base:
  - `incidents.ts` — real incidents, with cited sources.
  - `killchains.ts` — each attack as stages, each stage naming its guardrail, detection signal, and the rule ids that check it.
  - `rules.ts` — the rule catalog: severity, the incident(s) it maps to, *why it matters*, and the *fix* (steps + copy-paste snippets).
- `packages/core/src/scanners/` — `web.ts`, `repo.ts`, `chain.ts`, `policy.ts`. Each returns `Finding[]` built with `makeFinding(ruleId, …)`.
- `packages/core/src/report/` — scoring, SARIF, Markdown.
- `packages/server` — API + CLI. `packages/ui` — React app. `packages/lab` — the demo exchange.

## Adding a check

1. Add the incident to `incidents.ts` if it is not already there, with a real source link.
2. Add a rule to `rules.ts`: `id`, `module`, `severity`, `killChain`, `stage`, `incidentIds`, `why`, and a `fix` with concrete steps and at least one snippet.
3. Reference the rule id from the matching stage in `killchains.ts` so it shows up on the kill-chain map.
4. Emit it from the scanner with `makeFinding(id, { key, summary, evidence, … })`. Keep `key` unique per instance.
5. Add a unit test in `packages/core/test/unit.test.ts`.

```bash
npm run dev     # UI at :5173, API at :4477
npm test
npm run build
```

## Principles

- **Only passive checks.** No exploitation. The lab attacks only itself.
- **Nothing leaves the machine** unless the user asked for it (the URL, the RPC, GitHub's API for pinning).
- **Every finding teaches.** Say which real incident it maps to, why it matters, and exactly how to fix it.
- **No false confidence.** Prefer `info` with a clear note over a finding you cannot substantiate. On-chain checks verify state live (e.g. re-read allowances) rather than trusting historical logs alone.
