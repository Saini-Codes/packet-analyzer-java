import React, { useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Activity, AlertTriangle, CheckCircle2, CircleDot, FileUp, Gauge, Globe2, Layers3, Network, Play, RefreshCw, Shield, ShieldAlert, SlidersHorizontal, Terminal, Upload, Wifi } from 'lucide-react';
import './styles.css';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8080';
const EMPTY = { summary: { packets: 0, bytes: 0, forwarded: 0, dropped: 0, flows: 0 }, applications: {}, packets: [], flows: [] };

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}
function percent(a, b) { return b ? Math.round((a / b) * 100) : 0; }
function Badge({ children, danger = false }) { return <span className={danger ? 'badge danger' : 'badge'}>{children}</span>; }
function Stat({ icon: Icon, label, value, hint }) {
  return <div className="stat"><div className="statIcon"><Icon size={18} /></div><div><div className="muted">{label}</div><strong>{value}</strong><span>{hint}</span></div></div>;
}
function Empty({ text, sub }) {
  return <tr><td colSpan="8"><div className="empty"><AlertTriangle size={18} /><b>{text}</b><span>{sub}</span></div></td></tr>;
}
function Rule({ title, placeholder, value, setValue, add, values, remove }) {
  return <div className="rule"><label>{title}</label><div className="ruleInput"><input value={value} onChange={e => setValue(e.target.value)} placeholder={placeholder} onKeyDown={e => e.key === 'Enter' && add()} /><button onClick={add}>Add</button></div><div className="chips">{values.map(v => <button key={v} onClick={() => remove(v)}>{v} x</button>)}</div></div>;
}

function App() {
  const [data, setData] = useState(EMPTY);
  const [file, setFile] = useState(null);
  const [busy, setBusy] = useState(false);
  const [online, setOnline] = useState(null);
  const [tab, setTab] = useState('packets');
  const [query, setQuery] = useState('');
  const [blockIp, setBlockIp] = useState('');
  const [blockPort, setBlockPort] = useState('');
  const [blockDomain, setBlockDomain] = useState('');
  const [rules, setRules] = useState({ blockIps: [], blockPorts: [], blockDomains: [] });

  const filtered = useMemo(() => data.packets.filter(p => JSON.stringify(p).toLowerCase().includes(query.toLowerCase())), [data.packets, query]);
  const topApps = useMemo(() => Object.entries(data.applications).sort((a, b) => b[1] - a[1]).slice(0, 6), [data.applications]);

  async function health() {
    try { const r = await fetch(`${API}/api/health`); setOnline(r.ok); } catch { setOnline(false); }
  }
  async function loadSample() {
    setBusy(true);
    try {
      const r = await fetch(`${API}/api/sample`);
      if (!r.ok) throw new Error(await r.text());
      setData(await r.json()); setFile({ name: 'test.pcap', size: 0 }); setOnline(true);
    } catch { alert('Cannot reach the Java API. Start: java -jar target/packet-analyzer-1.0.0.jar server'); }
    finally { setBusy(false); }
  }
  async function analyze() {
    if (!file) return;
    setBusy(true);
    try {
      const bytes = await file.arrayBuffer();
      let binary = '';
      const u8 = new Uint8Array(bytes);
      const chunk = 0x8000;
      for (let i = 0; i < u8.length; i += chunk) binary += String.fromCharCode(...u8.subarray(i, Math.min(i + chunk, u8.length)));
      const body = { data: btoa(binary), blockIps: rules.blockIps, blockPorts: rules.blockPorts, blockDomains: rules.blockDomains };
      const r = await fetch(`${API}/api/analyze`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      if (!r.ok) throw new Error(await r.text());
      setData(await r.json()); setOnline(true);
    } catch (e) { alert(`Analysis failed: ${e.message}`); }
    finally { setBusy(false); }
  }
  function addRule(kind, value, clear) {
    const v = value.trim();
    if (!v || rules[kind].includes(v)) return;
    setRules(old => ({ ...old, [kind]: [...old[kind], v] })); clear('');
  }
  function removeRule(kind, value) { setRules(old => ({ ...old, [kind]: old[kind].filter(x => x !== value) })); }

  return <div className="app">
    <aside className="sidebar">
      <div className="brand"><div className="logo"><Shield size={21} /></div><div><b>Packet Analyzer</b><small>JAVA SECURITY CONSOLE</small></div></div>
      <nav>
        <button className="active"><Gauge size={18} />Overview</button>
        <button onClick={() => setTab('packets')}><Layers3 size={18} />Packets</button>
        <button onClick={() => setTab('flows')}><Network size={18} />Flows</button>
        <button><ShieldAlert size={18} />Firewall Rules</button>
      </nav>
      <div className="sideBottom"><div className="apiStatus"><span className={online ? 'dot online' : 'dot'}></span><span>{online === null ? 'API not checked' : online ? 'Java API online' : 'API offline'}</span></div><button className="ghost" onClick={health}><RefreshCw size={15} />Check API</button></div>
    </aside>
    <main>
      <header><div><div className="eyebrow"><CircleDot size={12} /> NETWORK ANALYSIS</div><h1>Packet intelligence, at a glance.</h1><p>Inspect PCAP traffic, identify applications, trace flows and enforce rules.</p></div><div className="headerActions"><button className="secondary" onClick={loadSample} disabled={busy}><Play size={16} />Analyze sample</button><button className="primary" onClick={() => document.getElementById('pcap').click()}><Upload size={16} />Upload PCAP</button><input id="pcap" hidden type="file" accept=".pcap,.cap" onChange={e => setFile(e.target.files?.[0] || null)} /></div></header>
      <section className="drop"><div className="dropIcon"><FileUp /></div><div><b>{file ? file.name : 'Drop a PCAP file here'}</b><p>{file ? `${formatBytes(file.size)} ready for analysis` : 'Ethernet PCAP - .pcap / .cap'}</p></div>{file && <button className="primary" onClick={analyze} disabled={busy}>{busy ? <RefreshCw className="spin" size={16} /> : <Activity size={16} />}{busy ? ' Analyzing...' : ' Run analysis'}</button>}</section>
      <section className="stats"><Stat icon={Layers3} label="Packets" value={data.summary.packets.toLocaleString()} hint={`${data.summary.forwarded.toLocaleString()} forwarded`} /><Stat icon={Wifi} label="Traffic" value={formatBytes(data.summary.bytes)} hint="Captured traffic" /><Stat icon={Network} label="Active flows" value={data.summary.flows} hint="Unique connections" /><Stat icon={ShieldAlert} label="Dropped" value={data.summary.dropped} hint={`${percent(data.summary.dropped, data.summary.packets)}% blocked`} /></section>
      <div className="grid">
        <section className="panel wide"><div className="panelHead"><div><h2>Traffic inspection</h2><p>Decoded packets returned by the Java analyzer.</p></div><div className="tabs"><button className={tab === 'packets' ? 'sel' : ''} onClick={() => setTab('packets')}>Packets</button><button className={tab === 'flows' ? 'sel' : ''} onClick={() => setTab('flows')}>Flows</button></div></div><div className="toolbar"><div className="search"><Terminal size={15} /><input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search IP, domain, protocol..." /></div><Badge>{tab === 'packets' ? filtered.length : data.flows.length} rows</Badge></div>
          {tab === 'packets' ? <div className="tableWrap"><table><thead><tr><th>#</th><th>Protocol</th><th>Source</th><th>Destination</th><th>Application</th><th>Domain</th><th>Bytes</th><th>Status</th></tr></thead><tbody>{filtered.length ? filtered.map(p => <tr key={p.id}><td className="muted">{p.id}</td><td><Badge>{p.protocol}</Badge></td><td className="mono">{p.source || '-'}</td><td className="mono">{p.destination || '-'}</td><td>{p.application || '-'}</td><td>{p.domain || '-'}</td><td>{formatBytes(p.bytes)}</td><td>{p.blocked ? <Badge danger>BLOCKED</Badge> : <span className="ok"><CheckCircle2 size={14} />ALLOWED</span>}</td></tr>) : <Empty text="No packets yet" sub="Upload a PCAP or analyze the included sample." />}</tbody></table></div>
          : <div className="tableWrap"><table><thead><tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Application</th><th>Domain</th><th>Packets</th><th>Bytes</th><th>Status</th></tr></thead><tbody>{data.flows.length ? data.flows.map((f, i) => <tr key={i}><td className="mono">{f.source}</td><td className="mono">{f.destination}</td><td><Badge>{f.protocol}</Badge></td><td>{f.application || '-'}</td><td>{f.domain || '-'}</td><td>{f.packets}</td><td>{formatBytes(f.bytes)}</td><td>{f.blocked ? <Badge danger>BLOCKED</Badge> : <span className="ok">ACTIVE</span>}</td></tr>) : <Empty text="No flows yet" sub="Run an analysis to populate connection tracking." />}</tbody></table></div>}
        </section>
        <section className="panel"><div className="panelHead"><div><h2>Applications</h2><p>DPI classification</p></div><Globe2 size={18} /></div><div className="apps">{topApps.length ? topApps.map(([name, count]) => <div className="appRow" key={name}><span>{name}</span><div className="bar"><i style={{ width: `${percent(count, topApps[0][1])}%` }} /></div><b>{count}</b></div>) : <div className="empty"><AlertTriangle size={18} /><b>No application data</b><span>DPI results appear after analysis.</span></div>}</div></section>
      </div>
      <section className="panel rules"><div className="panelHead"><div><h2>Firewall rules</h2><p>Rules are applied by the Java API during analysis.</p></div><SlidersHorizontal size={18} /></div><div className="ruleGrid"><Rule title="Block IP" placeholder="192.168.1.10" value={blockIp} setValue={setBlockIp} add={() => addRule('blockIps', blockIp, setBlockIp)} values={rules.blockIps} remove={v => removeRule('blockIps', v)} /><Rule title="Block port" placeholder="443" value={blockPort} setValue={setBlockPort} add={() => addRule('blockPorts', blockPort, setBlockPort)} values={rules.blockPorts} remove={v => removeRule('blockPorts', v)} /><Rule title="Block domain" placeholder="example.com" value={blockDomain} setValue={setBlockDomain} add={() => addRule('blockDomains', blockDomain, setBlockDomain)} values={rules.blockDomains} remove={v => removeRule('blockDomains', v)} /></div></section>
      <footer><span><Shield size={14} />Packet Analyzer Java</span><span>PCAP - DPI - Flow tracking - Firewall</span></footer>
    </main>
  </div>;
}

createRoot(document.getElementById('root')).render(<App />);
