import { useEffect, useRef, useState, startTransition } from 'react';
import {
  ShieldCheck, LockKeyhole, Activity, Boxes, Fingerprint, Settings2,
  ArrowRightLeft, ArrowUpRight, Copy, Check, RotateCcw, Play, LoaderCircle,
  Eye, EyeOff, ChevronDown, FileJson2, Upload, Download,
  AlertCircle, CheckCircle2, Database, KeyRound,
  Radio, Info, Code2, Workflow
} from 'lucide-react';
import {
  iterateFileLineChunks,
  splitTextIntoLineChunks,
  transformTextChunked,
  MAX_SINGLE_SHOT_BYTES,
} from './chunked.js';

const PREVIEW_CHARS = 6000;
const MAX_INLINE_CHARS = 512 * 1024;
/** Cap live textarea growth so streaming 1 GiB does not freeze the tab. */
const STREAM_DISPLAY_CHARS = 256 * 1024;
/** Browser console accepts up to 1 GiB via streamed chunked encode (not one shot). */
const MAX_FILE_BYTES = 1024 * 1024 * 1024;

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
function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / 1048576).toFixed(2)} MiB`;
}
function previewText(text) {
  if (text.length <= PREVIEW_CHARS) return text;
  return `${text.slice(0, PREVIEW_CHARS)}\n\n… [${(text.length - PREVIEW_CHARS).toLocaleString()} more characters held in memory for encode/decode — not fully rendered]`;
}
function parsing(value, type) {
  if (type === 'text') return value;
  if (!value.trim()) throw new Error('Enter a JSON payload before running.');
  try { return JSON.parse(value); }
  catch { throw new Error('Invalid JSON. Correct the syntax or switch to Plain text.'); }
}
async function callApi(path, apiKey, payload) {
  if (!apiKey) throw new Error('Enter a local development API key to continue.');
  let res;
  try {
    res = await fetch(path, {
      method: 'POST',
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      cache: 'no-store'
    });
  } catch {
    throw new Error('Network failure talking to the privacy gateway.');
  }
  const value = await res.json().catch(() => ({ detail: 'Unable to read API response.' }));
  if (!res.ok) {
    if (res.status === 413) {
      throw new Error(value.detail || 'Payload exceeds gateway limit (configure DLP_MAX_PAYLOAD_BYTES).');
    }
    throw new Error(value.detail || `Gateway returned HTTP ${res.status}`);
  }
  return value;
}
function downloadBlob(filename, data) {
  const blob = data instanceof Blob ? data : new Blob([data], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function Logo(){
  return (
    <img
      className="brand-logo"
      src="/logosoorin.svg"
      alt="Soorin"
      width={148}
      height={48}
    />
  );
}
function Tag({children,tone='muted'}){return <span className={'tag '+tone}>{children}</span>}

function App() {
  const [operation,setOperation] = useState('encode');
  const [format,setFormat] = useState('json');
  const [profile,setProfile] = useState('agentic-soc-v1');
  const [tenant,setTenant] = useState('demo');
  const [context,setContext] = useState('');
  const [apiKey,setApiKey] = useState('');
  const [keyBound,setKeyBound] = useState(false);
  const [visibleKey,setVisibleKey] = useState(false);
  const [input,setInput] = useState(sample);
  const [output,setOutput] = useState('');
  const [inputLabel,setInputLabel] = useState('');
  const [outputLabel,setOutputLabel] = useState('');
  const [stats,setStats] = useState(null);
  const [busy,setBusy] = useState(false);
  const [error,setError] = useState('');
  const [copied,setCopied] = useState(false);
  const [health,setHealth] = useState('checking');
  const [tab,setTab] = useState('workspace');
  const [lastRun,setLastRun] = useState(null);
  const [progress,setProgress] = useState(null);
  const runGeneration = useRef(0);
  const inputFull = useRef(sample);
  const outputFull = useRef('');
  const outputBlob = useRef(null);
  const outputParts = useRef([]);
  const outputAreaRef = useRef(null);
  const inputFile = useRef(null);
  const fileInputRef = useRef(null);

  const adoptInput = (text, label = '') => {
    inputFile.current = null;
    inputFull.current = text;
    setInputLabel(label);
    setInput(text.length > MAX_INLINE_CHARS ? previewText(text) : text);
  };
  const adoptOutput = (text, blob = null) => {
    outputFull.current = text || '';
    outputBlob.current = blob;
    outputParts.current = blob ? [] : (text ? [text] : []);
    const bytes = blob ? blob.size : new Blob([text || '']).size;
    setOutputLabel(bytes > MAX_INLINE_CHARS ? `${formatBytes(bytes)} — preview only · use Download` : '');
    setOutput(text && text.length > MAX_INLINE_CHARS ? previewText(text) : (text || ''));
  };

  const beginStreamOutput = () => {
    outputParts.current = [];
    outputFull.current = '';
    outputBlob.current = null;
    setOutput('');
    setOutputLabel('Streaming…');
    setStats(null);
  };

  const appendStreamChunk = ({ piece, index, total, context_id, bytesOut }) => {
    outputParts.current.push(piece);
    if (context_id) setContext(context_id);
    setOutput((prev) => {
      const next = prev + piece;
      if (next.length <= STREAM_DISPLAY_CHARS) return next;
      // Keep a live tail so the panel still updates while the full Blob grows.
      const tail = next.slice(-STREAM_DISPLAY_CHARS);
      return `… [live stream — showing last ${formatBytes(STREAM_DISPLAY_CHARS)} of ${formatBytes(bytesOut)}]\n` + tail;
    });
    setOutputLabel(`Streaming chunk ${index}/${total} · ${formatBytes(bytesOut)}`);
    outputFull.current = (outputFull.current + piece).slice(0, STREAM_DISPLAY_CHARS * 2);
    requestAnimationFrame(() => {
      const el = outputAreaRef.current;
      if (el) el.scrollTop = el.scrollHeight;
    });
  };

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
    const generation = ++runGeneration.current;
    setBusy(true);
    setError('');
    setCopied(false);
    setProgress(null);
    try {
      const file = inputFile.current;
      const raw = inputFull.current || input;
      const useChunkedText = format === 'text' && (
        !!file
        || new Blob([raw]).size > MAX_SINGLE_SHOT_BYTES
      );
      let result;
      if (useChunkedText) {
        beginStreamOutput();
        const chunks = file
          ? iterateFileLineChunks(file)
          : splitTextIntoLineChunks(raw);
        result = await transformTextChunked({
          chunks,
          operation,
          callApi,
          apiKey,
          profile,
          tenant: tenant.trim() || null,
          contextId: context || null,
          knownTotal: file ? Math.max(1, Math.ceil(file.size / (4 * 1024 * 1024))) : null,
          onProgress: (p) => {
            if (generation === runGeneration.current) setProgress(p);
          },
          onChunk: async (chunkInfo) => {
            if (generation !== runGeneration.current) return;
            appendStreamChunk(chunkInfo);
          },
        });
      } else {
        const payload = parsing(raw, format);
        if (operation === 'encode') {
          result = await callApi('/v1/encode', apiKey, {
            context_id: context || null,
            profile,
            tenant_id: tenant.trim() || null,
            purpose: 'llm-egress',
            format,
            payload
          });
        } else {
          if (!context.trim()) throw new Error('Enter the Context ID from a previous encoding operation.');
          result = await callApi('/v1/decode', apiKey, {
            context_id: context,
            format,
            payload,
            purpose: 'llm-response',
            reveal_credentials: false
          });
        }
        const pretty = jsonPretty(result.payload, format);
        beginStreamOutput();
        appendStreamChunk({
          piece: pretty,
          index: 1,
          total: 1,
          context_id: result.context_id,
          bytesOut: new Blob([pretty]).size,
        });
        result = {
          context_id: result.context_id,
          payloadPreview: pretty,
          payloadBlob: new Blob([pretty], { type: 'text/plain;charset=utf-8' }),
          stats: result.stats,
          chunks: 1,
        };
      }
      if (generation !== runGeneration.current) return;
      const finalBlob = result.payloadBlob
        || new Blob(outputParts.current, { type: 'text/plain;charset=utf-8' });
      startTransition(() => {
        if (result.context_id) setContext(result.context_id);
        outputBlob.current = finalBlob;
        setOutputLabel(
          finalBlob.size > STREAM_DISPLAY_CHARS
            ? `${formatBytes(finalBlob.size)} complete · preview capped · Download for full file`
            : 'Transformation completed'
        );
        setStats({
          ...(result.stats || {}),
          ...(result.chunks > 1 ? { chunks_processed: result.chunks } : {}),
        });
        setLastRun(new Date().toLocaleTimeString());
        setError('');
        setProgress(null);
      });
    } catch (err) {
      if (generation !== runGeneration.current) return;
      startTransition(() => {
        setError(err.message || 'Unexpected request failure.');
        adoptOutput('', null);
        setStats(null);
        setProgress(null);
      });
    } finally {
      if (generation === runGeneration.current) setBusy(false);
    }
  };

  const reset = () => {
    const next = format === 'text' ? '' : sample;
    inputFile.current = null;
    adoptInput(next, '');
    adoptOutput('');
    setError('');
    setStats(null);
    setContext('');
    setProgress(null);
  };
  const copy = async () => {
    if (outputBlob.current && outputBlob.current.size > MAX_INLINE_CHARS) {
      setError('Output is too large for clipboard. Use Download.');
      return;
    }
    const text = outputFull.current || output;
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      setError('Clipboard access was blocked by the browser. Use Download instead.');
    }
  };
  const switchDirection = () => {
    setOperation(x => x === 'encode' ? 'decode' : 'encode');
    if (outputBlob.current && outputBlob.current.size > MAX_SINGLE_SHOT_BYTES) {
      // Keep file-sized output as a synthetic File for the next chunked pass.
      const next = new File([outputBlob.current], 'protected-output.txt', { type: 'text/plain' });
      inputFile.current = next;
      inputFull.current = '';
      setInputLabel(`protected-output.txt · ${formatBytes(next.size)} · chunked stream`);
      setInput(previewText(outputFull.current || ''));
      adoptOutput('', null);
    } else if (outputFull.current || output) {
      adoptInput(outputFull.current || output, outputLabel ? 'From previous output' : '');
      adoptOutput('', null);
    }
    setStats(null);
    setError('');
  };
  const switchFormat = (next) => {
    setFormat(next);
    adoptOutput('');
    setStats(null);
    setError('');
    if (next === 'text') adoptInput('EXAMPLE\\analyst authenticated to dc01.corp.example from 10.20.3.7', '');
    else if (next === 'messages') adoptInput(JSON.stringify([{ role: 'user', content: 'Analyze the activity of 10.20.3.7 and dc01.corp.example.' }], null, 2), '');
    else adoptInput(sample, '');
  };
  const onPickFile = async (event) => {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) return;
    if (file.size > MAX_FILE_BYTES) {
      setError(`File exceeds ${formatBytes(MAX_FILE_BYTES)} console limit.`);
      return;
    }
    try {
      setFormat('text');
      adoptOutput('');
      setStats(null);
      setError('');
      // Streamed path: keep File handle; only preview the head (supports ~1 GiB).
      if (file.size > MAX_SINGLE_SHOT_BYTES) {
        const head = await file.slice(0, Math.min(file.size, PREVIEW_CHARS * 4)).text();
        inputFile.current = file;
        inputFull.current = '';
        setInputLabel(`${file.name} · ${formatBytes(file.size)} · chunked stream`);
        setInput(previewText(head));
      } else {
        const text = await file.text();
        adoptInput(text, `${file.name} · ${formatBytes(file.size)}`);
      }
    } catch {
      setError('Unable to read the selected file in the browser.');
    }
  };

  return <div className="app">
    <aside className="sidebar">
      <div className="brand"><Logo/><small>DATA PRIVACY GATEWAY</small></div>
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
            <label className="field"><span>Tenant ID <em>(stable aliases)</em></span><input spellCheck="false" value={tenant} onChange={e=>setTenant(e.target.value)} placeholder="Same tenant → same aliases"/></label>
            <label className="field"><span>Development API key {keyBound?<em>(auto-connected)</em>:null}</span><div className="password-wrap"><input type={visibleKey?'text':'password'} autoComplete="off" spellCheck="false" value={apiKey} readOnly={keyBound} onChange={e=>{setApiKey(e.target.value);setKeyBound(false);}} placeholder={keyBound?'Connected from gateway .env':'Paste your local API key'}/><button title="Show/hide local key" onClick={()=>setVisibleKey(v=>!v)} type="button">{visibleKey?<EyeOff size={16}/>:<Eye size={16}/>}</button></div></label>
          </div>
          <div className="context-row"><div><Radio size={15}/><b>Active privacy context</b><span>Context-scoped, time-limited mappings</span></div><input aria-label="Privacy context ID" value={context} onChange={e=>setContext(e.target.value)} placeholder="Created automatically on first encode" spellCheck="false"/></div>
        </section>
        <div className="editor-heading"><div><h2>Transformation studio</h2><p>Inspect the exact protected representation before it reaches an external model.</p></div><div className="mode-switch"><button className={operation==='encode'?'selected':''} onClick={()=>{setOperation('encode');setStats(null);setError('');}}><LockKeyhole size={15}/> Encode</button><button className={operation==='decode'?'selected':''} onClick={()=>{setOperation('decode');setStats(null);setError('');}}><ArrowRightLeft size={15}/> Decode</button></div></div>
        <section className="editor-grid">
          <div className="editor-card">
            <div className="editor-header">
              <div className="editor-label">
                <span className="editor-icon blue"><FileJson2 size={17}/></span>
                <div>
                  <strong>Input payload</strong>
                  <small>{inputLabel || 'Original or encoded data'}</small>
                </div>
              </div>
              <span className="editor-number">01 / INPUT</span>
            </div>
            <textarea
              value={input}
              onChange={e => {
                const next = e.target.value;
                inputFile.current = null;
                inputFull.current = next;
                setInputLabel('');
                setInput(next);
              }}
              spellCheck="false"
              aria-label="Input payload"
              placeholder="Paste JSON/text, or Upload CSV/TXT up to 1 GiB (chunked)"
            />
            <div className="editor-footer">
              <div><span className="dot-blue"/> Up to 1 GiB via Upload · streamed in ~4 MiB line chunks</div>
              <div className="editor-footer-actions">
                <input ref={fileInputRef} type="file" accept=".csv,.txt,.json,.log,text/plain,text/csv,application/json" hidden onChange={onPickFile}/>
                <button type="button" onClick={() => fileInputRef.current?.click()}><Upload size={14}/> Upload file</button>
                <button type="button" onClick={reset}><RotateCcw size={14}/> Reset</button>
              </div>
            </div>
          </div>
          <div className="direction-float"><button type="button" title="Swap direction and use output as input" onClick={switchDirection}><ArrowRightLeft size={18}/></button></div>
          <div className="editor-card">
            <div className="editor-header">
              <div className="editor-label">
                <span className="editor-icon violet"><ShieldCheck size={17}/></span>
                <div>
                  <strong>{operation==='encode'?'Protected output':'Rehydrated output'}</strong>
                  <small>{outputLabel || (operation==='encode'?'Provider-safe aliases':'Locally restored identity values')}</small>
                </div>
              </div>
              <span className="editor-number">02 / OUTPUT</span>
            </div>
            <textarea
              ref={outputAreaRef}
              readOnly
              value={output}
              spellCheck="false"
              aria-label="Protected output"
              placeholder={operation==='encode'?'Your tokenized payload will appear here…':'Your decoded response will appear here…'}
            />
            <div className="editor-footer">
              <div><span className="dot-green"/>{busy && output ? 'Streaming into output…' : (output ? 'Transformation completed' : 'Awaiting transformation')}</div>
              <div className="editor-footer-actions">
                <button type="button" onClick={copy} disabled={!(outputBlob.current || outputFull.current || output)}>{copied?<Check size={14}/>:<Copy size={14}/>} {copied?'Copied':'Copy'}</button>
                <button type="button" onClick={() => downloadBlob(operation==='encode'?'protected-output.txt':'rehydrated-output.txt', outputBlob.current || outputFull.current || output)} disabled={!(outputBlob.current || outputFull.current || output)}><Download size={14}/> Download</button>
              </div>
            </div>
          </div>
        </section>
        <div className="action-row">
          <div className="tip"><Info size={16}/><span>Credential aliases are not revealed by standard decode.</span></div>
          <button className="execute" type="button" onClick={execute} disabled={busy} aria-busy={busy}>
            <span className="execute-icon" aria-hidden="true">
              {busy ? <LoaderCircle size={18} className="spin"/> : <Play size={18} fill="currentColor"/>}
            </span>
            <span className="execute-label">
              {busy
                ? (progress ? `Chunk ${progress.done + 1}/${progress.total}…` : 'Processing…')
                : (operation === 'encode' ? 'Protect payload' : 'Rehydrate payload')}
            </span>
            <span className="execute-arrow" aria-hidden="true"><ArrowUpRight size={17}/></span>
          </button>
        </div>
        {progress ? (
          <div className="chunk-progress" aria-live="polite">
            Processing chunk {Math.min(progress.done + 1, progress.total)} of {progress.total}
            <i style={{ width: `${Math.round((progress.done / Math.max(progress.total, 1)) * 100)}%` }} />
          </div>
        ) : null}
        <div className="studio-status" aria-live="polite">
          {error ? (
            <div role="alert" className="alert error" key="studio-error">
              <AlertCircle size={18}/>
              <div><strong>Request unsuccessful</strong><span>{error}</span></div>
              <button type="button" onClick={()=>setError('')}>×</button>
            </div>
          ) : null}
          {stats ? (
            <div className="result-bar" key="studio-stats">
              <div className="result-title">
                <CheckCircle2 size={19}/>
                <div>
                  <strong>Transformation successful</strong>
                  <span>Last processed {lastRun} · Context <code>{(context || 'ctx').slice(0,19)}…</code></span>
                </div>
              </div>
              <div className="result-metrics">
                {Object.entries(stats).map(([k,v]) => (
                  <div key={k}><strong>{v}</strong><span>{k.replaceAll('_',' ')}</span></div>
                ))}
              </div>
            </div>
          ) : null}
        </div>
        <footer className="footer"><span><ShieldCheck size={15}/> soorinsec.ir · Secure AI Infrastructure</span><span>Never expose production credentials in the browser console.</span></footer>
      </div>:<div className="page guide-page"><div className="eyebrow">DEVELOPER RESOURCES</div><h1>Integration <span>Guide</span></h1><p className="subtitle">Connect any AI product through an authenticated privacy context and an explicit encode/decode boundary.</p><div className="guide-cards"><div><span className="guide-icon"><Code2/></span><h3>1. Create a context</h3><p>POST /v1/contexts</p><code>{'{"profile":"agentic-soc-v1","tenant_id":null}'}</code></div><div><span className="guide-icon"><LockKeyhole/></span><h3>2. Encode before egress</h3><p>POST /v1/encode</p><code>{'{"context_id":"ctx_...","format":"messages","payload":[...]}'}</code></div><div><span className="guide-icon"><ArrowRightLeft/></span><h3>3. Restore locally</h3><p>POST /v1/decode</p><code>{'{"context_id":"ctx_...","format":"text","payload":"..."}'}</code></div></div><div className="guide-tip"><Info size={19}/><div><b>Production integration</b><span className="guide-tip-body">The browser key-input console is for local development only. Use the Python SDK with server-side credentials, TLS, trusted tenant identity and an outbound network egress guard in production.</span></div></div><button className="back-workspace" onClick={()=>setTab('workspace')}>Back to workspace <ArrowUpRight size={17}/></button></div>}
    </main>
  </div>;
}

export default App;
