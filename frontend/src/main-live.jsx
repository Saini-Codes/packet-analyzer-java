import React, { useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Activity, AlertTriangle, CircleDot, Network, Play, Shield, Square, Wifi } from 'lucide-react';
import './styles.css';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8080';
const initial = { packets: [], bytes: 0, blocked: 0, protocols: {} };

function bytes(n) { if (n < 1024) return `${n} B`; if (n < 1048576) return `${(n/1024).toFixed(1)} KB`; return `${(n/1048576).toFixed(2)} MB`; }
function App() {
  const [interfaces, setInterfaces] = useState([]); const [iface, setIface] = useState('');
  const [running, setRunning] = useState(false); const [online, setOnline] = useState(false);
  const [state, setState] = useState(initial); const [error, setError] = useState('');
  const eventSource = useRef(null);

  async function loadInterfaces() { try { const r = await fetch(`${API}/api/interfaces`); if (!r.ok) throw new Error(await r.text()); const x = await r.json(); setInterfaces(x); if (!iface && x[0]) setIface(x[0].name); setOnline(true); setError(''); } catch (e) { setOnline(false); setError(e.message); } }
  useEffect(() => { loadInterfaces(); return () => eventSource.current?.close(); }, []);

  function connectStream() {
    eventSource.current?.close();
    const es = new EventSource(`${API}/api/stream`); eventSource.current = es;
    es.onmessage = e => { try { const p = JSON.parse(e.data); if (p.type === 'packet') setState(s => { const packets = [p, ...s.packets].slice(0, 250); return { ...s, packets, bytes: s.bytes + (p.bytes || 0), blocked: s.blocked + (p.blocked ? 1 : 0), protocols: { ...s.protocols, [p.protocol]: (s.protocols[p.protocol] || 0) + 1 } }; }); if (p.type === 'status') setRunning(p.status === 'CAPTURING'); if (p.type === 'error') setError(p.message); } catch {} };
    es.onerror = () => setOnline(false);
  }
  async function start() { setError(''); try { const r = await fetch(`${API}/api/capture/start`, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({interface:iface}) }); const x=await r.json(); if (!r.ok) throw new Error(x.error || 'Unable to start capture'); setRunning(true); setOnline(true); connectStream(); } catch(e) { setError(e.message); } }
  async function stop() { try { await fetch(`${API}/api/capture/stop`, {method:'POST'}); } finally { setRunning(false); eventSource.current?.close(); } }
  const top = useMemo(() => Object.entries(state.protocols).sort((a,b)=>b[1]-a[1]), [state.protocols]);

  return <div className="app"><main style={{maxWidth:1500,margin:'0 auto',width:'100%'}}>
    <header><div><div className="eyebrow"><CircleDot size={12}/> REAL-TIME NETWORK ANALYSIS</div><h1>Live Packet Analyzer</h1><p>Capture traffic directly from your network interface and stream every decoded packet into the dashboard.</p></div><div className="headerActions"><span className="badge"><span className={online?'dot online':'dot'}></span>{online?'API ONLINE':'API OFFLINE'}</span></div></header>
    <section className="drop" style={{display:'flex',gap:14,alignItems:'center',flexWrap:'wrap'}}><div className="dropIcon"><Wifi/></div><div style={{flex:1,minWidth:260}}><b>Capture interface</b><p>Select Wi-Fi, Ethernet or another Npcap interface.</p></div><select value={iface} onChange={e=>setIface(e.target.value)} style={{padding:'12px 14px',borderRadius:10,minWidth:280}}><option value="">Select interface</option>{interfaces.map(i=><option key={i.name} value={i.name}>{i.description ? `${i.description} (${i.name})` : i.name}</option>)}</select>{!running?<button className="primary" onClick={start} disabled={!iface}><Play size={16}/> Start capture</button>:<button className="secondary" onClick={stop}><Square size={16}/> Stop capture</button>}</section>
    {error && <section className="panel" style={{marginTop:16}}><div className="empty"><AlertTriangle size={18}/><b>Capture error</b><span>{error}</span></div></section>}
    <section className="stats"><div className="stat"><div className="statIcon"><Activity size={18}/></div><div><div className="muted">Packets received</div><strong>{state.packets.length.toLocaleString()}</strong><span>{running?'Streaming now':'Waiting for capture'}</span></div></div><div className="stat"><div className="statIcon"><Network size={18}/></div><div><div className="muted">Traffic received</div><strong>{bytes(state.bytes)}</strong><span>Since this session</span></div></div><div className="stat"><div className="statIcon"><Shield size={18}/></div><div><div className="muted">Blocked</div><strong>{state.blocked}</strong><span>Firewall decisions</span></div></div><div className="stat"><div className="statIcon"><Wifi size={18}/></div><div><div className="muted">Protocols</div><strong>{Object.keys(state.protocols).length}</strong><span>{top.map(x=>`${x[0]} ${x[1]}`).join(' · ') || 'No traffic yet'}</span></div></div></section>
    <section className="panel wide"><div className="panelHead"><div><h2>Live packets</h2><p>Newest packets appear at the top. The browser receives them through Server-Sent Events.</p></div><span className={running?'badge':'badge danger'}>{running?'● LIVE':'● STOPPED'}</span></div><div className="tableWrap"><table><thead><tr><th>#</th><th>Protocol</th><th>Source</th><th>Destination</th><th>Application</th><th>Domain</th><th>Bytes</th><th>Status</th></tr></thead><tbody>{state.packets.length?state.packets.map(p=><tr key={p.id}><td className="muted">{p.id}</td><td><span className="badge">{p.protocol}</span></td><td className="mono">{p.source||'-'}</td><td className="mono">{p.destination||'-'}</td><td>{p.application||'-'}</td><td>{p.domain||'-'}</td><td>{bytes(p.bytes)}</td><td>{p.blocked?<span className="badge danger">BLOCKED</span>:<span className="ok">ALLOWED</span>}</td></tr>):<tr><td colSpan="8"><div className="empty"><Network size={18}/><b>No live packets</b><span>Choose an interface and press Start capture.</span></div></td></tr>}</tbody></table></div></section>
    <footer><span><Shield size={14}/> Packet Analyzer Java</span><span>Live capture · Pcap4J · DPI · Flow tracking · SSE</span></footer>
  </main></div>;
}
createRoot(document.getElementById('root')).render(<App/>);
