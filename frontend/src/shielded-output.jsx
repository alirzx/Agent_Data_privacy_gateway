import { useLayoutEffect, useRef } from 'react';

/**
 * Closed Shadow DOM output pane. Browser extensions cannot query inside
 * mode:"closed" roots, which stops content-script crashes during streaming.
 */
export function ShieldedOutput({ value, placeholder, ariaLabel = 'Protected output' }) {
  const hostRef = useRef(null);
  const nodesRef = useRef(null);

  useLayoutEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    if (!nodesRef.current) {
      const shadow = host.attachShadow({ mode: 'closed' });
      const style = document.createElement('style');
      style.textContent = `
        :host {
          display: block;
          box-sizing: border-box;
          width: 100%;
          height: 300px;
          min-height: 190px;
          position: relative;
          background: #fbfdfe;
        }
        textarea {
          box-sizing: border-box;
          position: absolute;
          inset: 0;
          width: 100%;
          height: 100%;
          min-height: 190px;
          border: 0;
          resize: none;
          padding: 18px 20px;
          font: 12px/1.7 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
          background: #fbfdfe;
          color: #16304a;
          outline: none;
          white-space: pre;
          overflow: auto;
          tab-size: 2;
        }
        textarea::placeholder { color: #9aa8bb; }
        textarea:focus {
          outline: none;
          box-shadow: inset 0 0 0 1px rgba(20, 200, 184, 0.45);
        }
      `;
      const ta = document.createElement('textarea');
      ta.readOnly = true;
      ta.spellcheck = false;
      shadow.append(style, ta);
      nodesRef.current = { ta };
    }
    const ta = nodesRef.current.ta;
    ta.setAttribute('aria-label', ariaLabel);
    const next = value || '';
    if (ta.value !== next) {
      ta.value = next;
      ta.scrollTop = ta.scrollHeight;
    }
    ta.placeholder = placeholder || '';
  }, [value, placeholder, ariaLabel]);

  return <div className="shielded-output" ref={hostRef} />;
}
