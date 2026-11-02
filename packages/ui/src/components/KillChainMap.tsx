import type { KillChainSummary } from '../types';

export function KillChainMap({ chains }: { chains: KillChainSummary[] }) {
  return (
    <div className="kcmap">
      {chains.map((kc) => {
        const open = kc.stages.filter((s) => s.status === 'open').length;
        return (
          <div className="kc" key={kc.id}>
            <div className="kchead">
              <h3>{kc.name} <span className="modcount">{open > 0 ? `${open} stage${open > 1 ? 's' : ''} open` : 'no open stages'}</span></h3>
              <p>{kc.tagline}</p>
            </div>
            {kc.stages.map((s) => (
              <div className="stage" key={s.id}>
                <div style={{ paddingTop: 5 }}><span className={`dot ${s.status}`} title={s.status} /></div>
                <div>
                  <div className="stepname">{s.step}</div>
                  <div className="meta"><b>Guardrail:</b> {s.guardrail}</div>
                  <div className="meta"><b>Detection signal:</b> {s.signal}</div>
                  <div className="meta">
                    {s.status === 'open' && <span style={{ color: 'var(--crit)' }}>⚠ open — {s.findingKeys.length} finding(s){s.worst ? `, worst ${s.worst}` : ''}</span>}
                    {s.status === 'covered' && <span style={{ color: 'var(--accent)' }}>✓ no findings in what was scanned</span>}
                    {s.status === 'unknown' && <span style={{ color: 'var(--muted2)' }}>not scanned (run the matching module)</span>}
                  </div>
                </div>
              </div>
            ))}
          </div>
        );
      })}
    </div>
  );
}
