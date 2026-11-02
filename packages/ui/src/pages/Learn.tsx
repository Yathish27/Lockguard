import { useState } from 'react';
import type { Knowledge } from '../types';
import { Code, SevPill } from '../components/common';

export function Learn({ knowledge }: { knowledge: Knowledge }) {
  const [tab, setTab] = useState<'incidents' | 'chains' | 'rules'>('incidents');
  return (
    <div>
      <div className="pagehead">
        <h1>Learn</h1>
        <p>The incidents behind every check, the kill chains they form, and the full rule catalog with fixes.</p>
      </div>
      <div className="tabs">
        <button className={tab === 'incidents' ? 'active' : ''} onClick={() => setTab('incidents')}>Incidents</button>
        <button className={tab === 'chains' ? 'active' : ''} onClick={() => setTab('chains')}>Kill chains</button>
        <button className={tab === 'rules' ? 'active' : ''} onClick={() => setTab('rules')}>All checks</button>
      </div>
      {tab === 'incidents' && knowledge.incidents.map((inc) => (
        <div className="card" key={inc.id}>
          <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' }}>
            <h3>{inc.name}</h3>
            <span className="hint" style={{ margin: 0 }}>{inc.date} · {inc.loss}</span>
          </div>
          <p style={{ color: 'var(--text)', fontWeight: 500, margin: '2px 0 8px' }}>{inc.oneLiner}</p>
          <p style={{ color: 'var(--muted)', margin: '0 0 10px' }}>{inc.summary}</p>
          <h4 style={{ color: 'var(--muted2)', fontSize: 12, textTransform: 'uppercase' }}>What it teaches</h4>
          <ul className="steps">{inc.lessons.map((l, i) => <li key={i}>{l}</li>)}</ul>
          <div style={{ marginTop: 8 }}>{inc.links.map((l, i) => <div key={i}><a href={l.url} target="_blank" rel="noreferrer noopener">{l.title}</a></div>)}</div>
        </div>
      ))}
      {tab === 'chains' && knowledge.killChains.map((kc) => (
        <div className="card" key={kc.id}>
          <h3>{kc.name}</h3>
          <p className="sub">{kc.tagline}</p>
          <div className="kv" style={{ gridTemplateColumns: '1fr', gap: 10 }}>
            {kc.stages.map((s) => (
              <div key={s.id} className="evid">
                <div style={{ fontWeight: 600 }}>{s.step}</div>
                <div style={{ fontSize: 13, color: 'var(--muted)', marginTop: 4 }}><b style={{ color: 'var(--muted2)' }}>Guardrail:</b> {s.guardrail}</div>
                <div style={{ fontSize: 13, color: 'var(--muted)' }}><b style={{ color: 'var(--muted2)' }}>Signal:</b> {s.signal}</div>
                <div style={{ marginTop: 5 }}>{s.rules.map((r) => <span key={r} className="tag">{r}</span>)}</div>
              </div>
            ))}
          </div>
        </div>
      ))}
      {tab === 'rules' && (
        <div>
          {(['web', 'repo', 'chain'] as const).map((mod) => (
            <div key={mod}>
              <h3 style={{ margin: '18px 0 8px', textTransform: 'capitalize' }}>{mod} checks</h3>
              {knowledge.rules.filter((r) => r.module === mod).map((r) => (
                <details className="finding" key={r.id}>
                  <summary>
                    <SevPill s={r.severity} />
                    <div style={{ flex: 1 }}><div className="ftitle">{r.id} · {r.title}</div></div>
                    <span className="chev">›</span>
                  </summary>
                  <div className="fbody">
                    <p style={{ whiteSpace: 'pre-wrap', color: 'var(--text)' }}>{r.why}</p>
                    <h4>Fix · {r.fix.effort} · {r.fix.impact} impact</h4>
                    <p style={{ margin: '0 0 8px' }}>{r.fix.summary}</p>
                    <ol className="steps">{r.fix.steps.map((s, i) => <li key={i}>{s}</li>)}</ol>
                    {(r.fix.snippets || []).map((sn, i) => <Code key={i} code={sn.code} lang={sn.lang} title={sn.title} />)}
                  </div>
                </details>
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
