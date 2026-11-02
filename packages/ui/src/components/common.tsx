import { useState } from 'react';
import type { Severity } from '../types';

export function SevPill({ s }: { s: Severity }) {
  return <span className={`pill sev-${s}`}>{s}</span>;
}

export function CopyBtn({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button className="copybtn" onClick={async () => {
      try { await navigator.clipboard.writeText(text); } catch { /* ignore */ }
      setDone(true); setTimeout(() => setDone(false), 1200);
    }}>{done ? 'copied' : 'copy'}</button>
  );
}

export function Code({ code, lang, title }: { code: string; lang?: string; title?: string }) {
  return (
    <div className="codeblock">
      <div className="cbhead"><span>{title || lang || 'code'}</span><CopyBtn text={code} /></div>
      <pre><code>{code}</code></pre>
    </div>
  );
}

export function Grade({ grade, value }: { grade: string; value: number }) {
  return (
    <div className="scorebig">
      <div className={`gradecircle g-${grade}`}>{grade}</div>
      <div>
        <div style={{ fontSize: 28, fontWeight: 800 }}>{value}<span style={{ color: 'var(--muted2)', fontSize: 16, fontWeight: 500 }}>/100</span></div>
        <div style={{ color: 'var(--muted)', fontSize: 13 }}>higher is safer</div>
      </div>
    </div>
  );
}

export function SevCounts({ counts }: { counts: Record<Severity, number> }) {
  const order: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  return (
    <div className="sevcounts">
      {order.filter((s) => counts[s] > 0).map((s) => (
        <span key={s} className={`pill sev-${s}`}>{counts[s]} {s}</span>
      ))}
      {order.every((s) => counts[s] === 0) && <span className="pill sev-info">no findings</span>}
    </div>
  );
}
