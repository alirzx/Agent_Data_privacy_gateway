/**
 * Read-only output pane matching the input textarea layout.
 * Kept as a light-DOM textarea so it always fills the editor card;
 * streaming updates are already throttled in App.jsx.
 */
export function ShieldedOutput({ value, placeholder, ariaLabel = 'Protected output' }) {
  return (
    <textarea
      className="shielded-output-field"
      readOnly
      spellCheck={false}
      aria-label={ariaLabel}
      placeholder={placeholder || ''}
      value={value || ''}
      data-gramm="false"
      data-gramm_editor="false"
      data-enable-grammarly="false"
    />
  );
}
