import { useEffect, useState } from 'react';
import { api } from './api';
import type { Knowledge } from './types';
import { Overview } from './pages/Overview';
import { Scan } from './pages/Scan';
import { Tools } from './pages/Tools';
import { Lab } from './pages/Lab';
import { Learn } from './pages/Learn';

const NAV = [
  { id: 'overview', label: 'Overview', ic: '◆' },
  { id: 'scan', label: 'Scan', ic: '⌕' },
  { id: 'tools', label: 'Harden', ic: '🛠' },
  { id: 'lab', label: 'Lab', ic: '⚑' },
  { id: 'learn', label: 'Learn', ic: '≡' }
];

export default function App() {
  const [tab, setTab] = useState('overview');
  const [knowledge, setKnowledge] = useState<Knowledge | null>(null);
  const [err, setErr] = useState('');
  const [open, setOpen] = useState(false);
  const [labUrls, setLabUrls] = useState<{ vulnerable: string | null }>({ vulnerable: null });
  const [mode, setMode] = useState<'local' | 'hosted' | 'static'>('local');

  useEffect(() => {
    api.knowledge().then(setKnowledge).catch((e) => setErr(e instanceof Error ? e.message : String(e)));
    api.mode().then(setMode).catch(() => setMode('static'));
    api.labStatus().then((s) => { if (s.vulnerable) setLabUrls({ vulnerable: s.vulnerable }); }).catch(() => {});
    const h = () => { const t = location.hash.slice(1); if (t && NAV.some((n) => n.id === t)) setTab(t); };
    h(); window.addEventListener('hashchange', h);
    return () => window.removeEventListener('hashchange', h);
  }, []);

  function go(t: string) { setTab(t); location.hash = t; setOpen(false); window.scrollTo(0, 0); }

  return (
    <div className="app">
      <button className="menubtn" onClick={() => setOpen((o) => !o)}>☰</button>
      <aside className={`sidebar ${open ? 'open' : ''}`}>
        <div className="brand">
          <svg viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#101a24" /><path d="M32 8l20 7v15c0 12-8.5 22-20 26C20.5 52 12 42 12 30V15l20-7z" fill="none" stroke="#3ddc97" strokeWidth="4" strokeLinejoin="round" /><path d="M22 32l7 7 13-14" fill="none" stroke="#3ddc97" strokeWidth="4.5" strokeLinecap="round" strokeLinejoin="round" /></svg>
          <b>Lock<span>guard</span></b>
        </div>
        {NAV.map((n) => <button key={n.id} className={`navbtn ${tab === n.id ? 'active' : ''}`} onClick={() => go(n.id)}><span className="ic">{n.ic}</span>{n.label}</button>)}
        <div className="foot">Runs locally.<br />No telemetry.<br />Scan only what you own.</div>
      </aside>
      <main className="main">
        <div className="wrap">
          {err && <div className="banner err">Could not reach the Lockguard API: {err}</div>}
          {!knowledge && !err && <div className="empty"><span className="spinner" /> loading…</div>}
          {knowledge && (
            <>
              {tab === 'overview' && <Overview knowledge={knowledge} go={go} mode={mode} />}
              {tab === 'scan' && <Scan knowledge={knowledge} labUrls={labUrls} mode={mode} />}
              {tab === 'tools' && <Tools knowledge={knowledge} mode={mode} />}
              {tab === 'lab' && <Lab onLabReady={(u) => setLabUrls({ vulnerable: u.vulnerable })} mode={mode} />}
              {tab === 'learn' && <Learn knowledge={knowledge} />}
            </>
          )}
        </div>
      </main>
    </div>
  );
}
