import { useEffect, useState } from 'react';
import {
  ShieldCheck, LockKeyhole, Activity, Boxes, Fingerprint, Settings2,
  ArrowRightLeft, ArrowUpRight, Copy, Check, RotateCcw, Play, LoaderCircle,
  Eye, EyeOff, ChevronDown, TerminalSquare, CircleHelp, FileJson2,
  AlertCircle, CheckCircle2, Server, Workflow, Sparkles, Database, KeyRound,
  ExternalLink, Braces, Radio, Info, Code2, CheckCheck
} from 'lucide-react';

const sample = JSON.stringify({
  "src_ip": "10.20.3.7",
  "device": { "name": "dc01.corp.example", "ip": "10.20.3.21" },
  "user": "EXAMPLE\\analyst",
  "description": "EXAMPLE\\analyst authenticated to dc01.corp.example from 10.20.3.7",
  "mitre_techniques": ["T1078"],
  "risk_score": 72,
  "password": "SyntheticSecretForDemo"
}, null, 2);

const profiles = [
  {value:'generic-v1',label:'Generic Privacy'},
  {value:'agentic-soc-v1',label:'Agentic SOC'},
  {value:'soorin-copilot-v1',label:'Soorin Copilot'}
];

function jsonPretty(value, type) {
  return type === 'text' ? String(value ?? '') : JSON.stringify(value, null, 2);
}
function parsing(value, type) {
  if (type === 'text') return value;
  if (!value.trim()) throw new Error('Enter a JSON payload before running.');
  try { return JSON.parse(value); }
  catch { throw new Error('Invalid JSON. Correct the syntax or switch to Plain text.'); }
}
async function callApi(path, apiKey, payload) {
  if (!apiKey) throw new Error('Enter a local development API key to continue.');
  const res = await fetch(path, {
    method: 'POST',
    headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type':'application/json' },
    body: JSON.stringify(payload),
    cache: 'no-store'
  });
  const value = await res.json().catch(()=>({detail:'Unable to read API response.'}));
  if (!res.ok) throw new Error(value.detail || `Gateway returned HTTP ${res.status}`);
  return value;
}

function Logo(){
  return (
    <div className="logo-mark" aria-hidden="true">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
        <path d="M4 7c5-5 11-5 16 0" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round"/>
        <path d="M6 12c3.5-3.5 8.5-3.5 12 0" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round"/>
        <path d="M9 17c2-2 4-2 6 0" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round"/>
      </svg>
    </div>
  );
}
function Tag({children,tone='muted'}){return <span className={'tag '+tone}>{children}</span>}

function App() {
  const [operation,setOperation] = useState('encode');
  const [format,setFormat] = useState('json');
  const [profile,setProfile] = useState('agentic-soc-v1');
  const [tenant,setTenant] = useState('');
  const [context,setContext] = useState('');
  const [apiKey,setApiKey] = useState('');
  const [keyBound,setKeyBound] = useState(false);
  const [visibleKey,setVisibleKey] = useState(false);
  const [input,setInput] = useState(sample);
  const [output,setOutput] = useState('');
  const [stats,setStats] = useState(null);
  const [busy,setBusy] = useState(false);
  const [error,setError] = useState('');
  const [copied,setCopied] = useState(false);
  const [health,setHealth] = useState('checking');
  const [tab,setTab] = useState('workspace');
  const [lastRun,setLastRun] = useState(null);

  useEffect(()=>{
    let active = true;
    fetch('/ready',{cache:'no-store'}).then(r => { if (active) setHealth(r.ok?'online':'offline'); })
      .catch(()=>{ if (active) setHealth('offline'); });
    fetch('/v1/dev/console',{cache:'no-store'})
      .then(async r => {
        if (!active || !r.ok) return;
        const data = await r.json().catch(()=>null);
        if (data?.api_key) {
          setApiKey(data.api_key);
          setKeyBound(true);
        }
      })
      .catch(()=>{ /* bootstrap is optional outside Docker/dev UI */ });
    return ()=>{ active=false; };
  },[]);

  const execute = async () => {
    setBusy(true);setError('');setStats(null);setCopied(false);
    try {
      const payload=parsing(input,format);
      let result;
      if(operation==='encode') {
        result=await callApi('/v1/encode',apiKey,{
          context_id:context || null,profile,tenant_id:tenant.trim()||null,
          purpose:'llm-egress',format,payload
        });
        setContext(result.context_id);
      } else {
        if(!context.trim())throw new Error('Enter the Context ID from a previous encoding operation.');
        result=await callApi('/v1/decode',apiKey,{
          context_id:context,format,payload,purpose:'llm-response',reveal_credentials:false
        });
      }
      setOutput(jsonPretty(result.payload,format));setStats(result.stats);
      setLastRun(new Date().toLocaleTimeString());
    } catch(err){setError(err.message||'Unexpected request failure.');setOutput('');}
    finally{setBusy(false);}
  };

  const reset=()=>{setInput(format==='text'?'':sample);setOutput('');setError('');setStats(null);setContext('');};
  const copy = async ()=>{if(!output)return;try{await navigator.clipboard.writeText(output);setCopied(true);setTimeout(()=>setCopied(false),1800);}catch{setError('Clipboard access was blocked by the browser.');}};
  const switchDirection=()=>{
    setOperation(x=>x==='encode'?'decode':'encode');
    if(output){setInput(output);setOutput('');}
    setStats(null);setError('');
  };
  const switchFormat=(next)=>{setFormat(next);setOutput('');setStats(null);setError('');if(next==='text')setInput('EXAMPLE\\analyst authenticated to dc01.corp.example from 10.20.3.7');else if(next==='messages')setInput(JSON.stringify([{role:'user',content:'Analyze the activity of 10.20.3.7 and dc01.corp.example.'}],null,2));else setInput(sample);};

  return <div className="app">
    <aside className="sidebar">
      <div className="brand"><Logo/><div><b>soorin<span className="brand-dot">sec</span></b><small>DATA PRIVACY GATEWAY</small></div></div>
      <div className="side-section-label">WORKSPACE</div>
      <button className={'nav-item '+(tab==='workspace'?'active':'')} onClick={()=>setTab('workspace')}><Boxes size={18}/> Privacy Workspace <span className="nav-arrow">›</span></button>
      <button className={'nav-item '+(tab==='guide'?'active':'')} onClick={()=>setTab('guide')}><Code2 size={18}/> Integration Guide</button>
      <div className="side-section-label side-secondary">SECURITY ENGINE</div>
      <div className="nav-item disabled"><Fingerprint size={18}/> Identity protection <Tag>ON</Tag></div>
      <div className="nav-item disabled"><Database size={18}/> Encrypted mapping <Tag>AEAD</Tag></div>
      <div className="nav-item disabled"><Workflow size={18}/> Scoped contexts <Tag>TTL</Tag></div>
      <div className="side-bottom">
        <div className="bordered-note"><div className="note-icon"><LockKeyhole size={17}/></div><strong>Private by design</strong><p>Identifiers never need to leave your boundary in their original form.</p></div>
        <div className="side-user"><div className="avatar">DP</div><div><b>Privacy Gateway</b><small>Development Console</small></div><Settings2 size={17}/></div>
      </div>
    </aside>

    <main className="main">
      <header className="topbar"><div className="breadcrumbs">Workspace <span>/</span> <b>{tab==='workspace'?'Privacy Engine':'Integration Guide'}</b></div><div className="top-right"><span className={'connection '+(health==='online'?'up':'down')}><i/>{health==='online'?'Gateway Online':health==='checking'?'Checking Gateway':'Gateway Offline'}</span><span className="vertical-rule"/><span className="version">v0.1.0</span></div></header>
      {tab==='workspace'?<div className="page">
        <div className="eyebrow"><span className="tiny-cube">◆</span> SOORIN SECURITY · SECURE EGRESS</div>
        <div className="title-row"><div><h1>Data Privacy <span>Gateway</span></h1><p className="subtitle">Classify, tokenize and restore sensitive identities with Soorin&apos;s secure, context-aware privacy boundary.</p></div><div className="title-lock"><ShieldCheck size={30}/><span>SOORIN<br/><strong>BOUNDARY</strong></span></div></div>
        <div className="stats-strip"><div><Fingerprint size={16}/><span>Semantic identity detection</span></div><i/><div><KeyRound size={16}/><span>HMAC tokenization</span></div><i/><div><LockKeyhole size={16}/><span>AES-GCM mapping vault</span></div><i/><div><Activity size={16}/><span>Auditable API</span></div></div>
        <section className="control-card">
          <div className="control-title"><div><Settings2 size={17}/> <b>Configuration</b></div><span>Development environment</span></div>
          <div className="control-grid">
            <label className="field"><span>Privacy profile</span><div className="select-wrap"><select value={profile} onChange={e=>setProfile(e.target.value)}>{profiles.map(p=><option key={p.value} value={p.value}>{p.label}</option>)}</select><ChevronDown size={16}/></div></label>
            <label className="field"><span>Input format</span><div className="select-wrap"><select value={format} onChange={e=>switchFormat(e.target.value)}><option value="json">Structured JSON</option><option value="text">Plain text</option><option value="messages">LLM messages</option></select><ChevronDown size={16}/></div></label>
            <label className="field"><span>Tenant ID <em>(optional)</em></span><input spellCheck="false" value={tenant} onChange={e=>setTenant(e.target.value)} placeholder="Tenantless context"/></label>
            <label className="field"><span>Development API key {keyBound?<em>(auto-connected)</em>:null}</span><div className="password-wrap"><input type={visibleKey?'text':'password'} autoComplete="off" spellCheck="false" value={apiKey} readOnly={keyBound} onChange={e=>{setApiKey(e.target.value);setKeyBound(false);}} placeholder={keyBound?'Connected from gateway .env':'Paste your local API key'}/><button title="Show/hide local key" onClick={()=>setVisibleKey(v=>!v)} type="button">{visibleKey?<EyeOff size={16}/>:<Eye size={16}/>}</button></div></label>
          </div>
          <div className="context-row"><div><Radio size={15}/><b>Active privacy context</b><span>Context-scoped, time-limited mappings</span></div><input aria-label="Privacy context ID" value={context} onChange={e=>setContext(e.target.value)} placeholder="Created automatically on first encode" spellCheck="false"/></div>
        </section>
        <div className="editor-heading"><div><h2>Transformation studio</h2><p>Inspect the exact protected representation before it reaches an external model.</p></div><div className="mode-switch"><button className={operation==='encode'?'selected':''} onClick={()=>{setOperation('encode');setStats(null);setError('');}}><LockKeyhole size={15}/> Encode</button><button className={operation==='decode'?'selected':''} onClick={()=>{setOperation('decode');setStats(null);setError('');}}><ArrowRightLeft size={15}/> Decode</button></div></div>
        <section className="editor-grid">
          <div className="editor-card"><div className="editor-header"><div className="editor-label"><span className="editor-icon blue"><FileJson2 size={17}/></span><div><strong>Input payload</strong><small>Original or encoded data</small></div></div><span className="editor-number">01 / INPUT</span></div><textarea value={input} onChange={e=>setInput(e.target.value)} spellCheck="false" aria-label="Input payload" placeholder="Paste JSON, LLM messages or plaintext here"/><div className="editor-footer"><div><span className="dot-blue"/> Input stays inside your private gateway</div><button onClick={reset}><RotateCcw size={14}/> Reset</button></div></div>
          <div className="direction-float"><button title="Swap direction and use output as input" onClick={switchDirection}><ArrowRightLeft size={18}/></button></div>
          <div className="editor-card"><div className="editor-header"><div className="editor-label"><span className="editor-icon violet"><ShieldCheck size={17}/></span><div><strong>{operation==='encode'?'Protected output':'Rehydrated output'}</strong><small>{operation==='encode'?'Provider-safe aliases':'Locally restored identity values'}</small></div></div><span className="editor-number">02 / OUTPUT</span></div><textarea readOnly value={output} spellCheck="false" aria-label="Protected output" placeholder={operation==='encode'?'Your tokenized payload will appear here…':'Your decoded response will appear here…'}/><div className="editor-footer"><div><span className="dot-green"/>{output?'Transformation completed':'Awaiting transformation'}</div><button onClick={copy}>{copied?<Check size={14}/>:<Copy size={14}/>} {copied?'Copied':'Copy output'}</button></div></div>
        </section>
        <div className="action-row"><div className="tip"><Info size={16}/><span>Credential aliases are not revealed by standard decode.</span></div><button className="execute" onClick={execute} disabled={busy}>{busy?<LoaderCircle size={18} className="spin"/>:<Play size={18} fill="currentColor"/>}{busy?'Processing…':operation==='encode'?'Protect payload':'Rehydrate payload'} <ArrowUpRight size={17}/></button></div>
        {error&&<div role="alert" className="alert error"><AlertCircle size={18}/><div><strong>Request unsuccessful</strong><span>{error}</span></div><button onClick={()=>setError('')}>×</button></div>}
        {stats&&<div className="result-bar"><div className="result-title"><CheckCircle2 size={19}/><div><strong>Transformation successful</strong><span>Last processed {lastRun} · Context <code>{context.slice(0,19)}…</code></span></div></div><div className="result-metrics">{Object.entries(stats).map(([k,v])=><div key={k}><strong>{v}</strong><span>{k.replaceAll('_',' ')}</span></div>)}</div></div>}
        <footer className="footer"><span><ShieldCheck size={15}/> soorinsec.ir · Secure AI Infrastructure</span><span>Never expose production credentials in the browser console.</span></footer>
      </div>:<div className="page guide-page"><div className="eyebrow">DEVELOPER RESOURCES</div><h1>Integration <span>Guide</span></h1><p className="subtitle">Connect any AI product through an authenticated privacy context and an explicit encode/decode boundary.</p><div className="guide-cards"><div><span className="guide-icon"><Code2/></span><h3>1. Create a context</h3><p>POST /v1/contexts</p><code>{'{"profile":"agentic-soc-v1","tenant_id":null}'}</code></div><div><span className="guide-icon"><LockKeyhole/></span><h3>2. Encode before egress</h3><p>POST /v1/encode</p><code>{'{"context_id":"ctx_...","format":"messages","payload":[...]}'}</code></div><div><span className="guide-icon"><ArrowRightLeft/></span><h3>3. Restore locally</h3><p>POST /v1/decode</p><code>{'{"context_id":"ctx_...","format":"text","payload":"..."}'}</code></div></div><div className="guide-tip"><Info size={19}/><div><b>Production integration</b><p>The browser key-input console is for local development only. Use the Python SDK with server-side credentials, TLS, trusted tenant identity and an outbound network egress guard in production.</p></div></div><button className="back-workspace" onClick={()=>setTab('workspace')}>Back to workspace <ArrowUpRight size={17}/></button></div>}
    </main>
  </div>;
}

export default App;
