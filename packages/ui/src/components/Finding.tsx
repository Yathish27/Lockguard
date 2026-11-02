import type { Finding, Incident } from '../types';
import { SevPill, Code } from './common';

export function FindingCard({ f, incidents }: { f: Finding; incidents: Record<string, Incident> }) {
  return (
    <details className="finding">
      <summary>
        <SevPill s={f.severity} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="ftitle">{f.id} · {f.title}</div>
          <div className="fsum">{f.summary}</div>
        </div>
        <span className="chev">›</span>
      </summary>
      <div className="fbody">
        {f.incidentIds.length > 0 && (
          <>
            <h4>This is how it happened for real</h4>
            {f.incidentIds.map((id) => {
              const inc = incidents[id];
              if (!inc) return <span key={id} className="incidentchip">{id}</span>;
              return <span key={id} className="incidentchip" title={inc.oneLiner}>{inc.name} · {inc.date} · {inc.loss}</span>;
            })}
          </>
        )}
        <h4>Evidence</h4>
        {f.evidence.map((e, i) => (
          <div className="evid" key={i}>
            <div className="loc">{e.location}{e.line ? `:${e.line}` : ''}</div>
            <div style={{ color: 'var(--muted)', marginTop: 3 }}>{e.detail}</div>
          </div>
        ))}
        <h4>Why it matters</h4>
        <p style={{ margin: 0, color: 'var(--text)', whiteSpace: 'pre-wrap' }}>{f.why}</p>
        <h4>How to fix it <span style={{ textTransform: 'none', color: 'var(--muted)', fontWeight: 400 }}>· {f.fix.effort} · {f.fix.impact} impact</span></h4>
        <p style={{ margin: '0 0 8px', color: 'var(--text)' }}>{f.fix.summary}</p>
        <ol className="steps">{f.fix.steps.map((s, i) => <li key={i}>{s}</li>)}</ol>
        {(f.fix.snippets || []).map((sn, i) => <Code key={i} code={sn.code} lang={sn.lang} title={sn.title} />)}
        {f.references.length > 0 && (
          <>
            <h4>References</h4>
            <ul className="steps">{f.references.map((r, i) => <li key={i}><a href={r.url} target="_blank" rel="noreferrer noopener">{r.title}</a></li>)}</ul>
          </>
        )}
      </div>
    </details>
  );
}
