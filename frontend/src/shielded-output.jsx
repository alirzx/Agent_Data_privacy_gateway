import { useEffect, useRef } from 'react';

/**
 * Closed Shadow DOM output pane. Browser extensions cannot query inside
 * mode:"closed" roots, which stops content-script crashes during streaming.
 */
export function ShieldedOutput({ value, placeholder, ariaLabel = 'Protected output' }) {
  const hostRef = useRef(null);
  const nodesRef = useRef(null);

  useEffect(() => {
    const host = hostRef.current;
    if (!host || nodesRef.current) return;
    const shadow = host.attachShadow({ mode: 'closed' });
    const style = document.createElement('style');
    style.textContent = `
      :host { display: block; height: 300px; min-height: 190px; }
      textarea {
        box-sizing: border-box;
        display: block;
        width: 100%;
        height: 100%;
        min-height: 190px;
        border: 0;
        resize: vertical;
        padding: 14px 16px;
        font: 13px/1.68 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        background: #fbfdfe;
        color: #16304a;
        outline: none;
      }
      textarea::placeholder { color: #9aa8bb; }
    `;
    const ta = document.createElement('textarea');
    ta.readOnly = true;
    ta.spellcheck = false;
    ta.setAttribute('aria-label', ariaLabel);
    shadow.append(style, ta);
    nodesRef.current = { ta };
  }, [ariaLabel]);

  useEffect(() => {
    const ta = nodesRef.current?.ta;
    if (!ta) return;
    if (ta.value !== (value || '')) {
      ta.value = value || '';
      ta.scrollTop = ta.scrollHeight;
    }
    ta.placeholder = placeholder || '';
  }, [value, placeholder]);

  return <div className="shielded-output" ref={hostRef} />;
}
