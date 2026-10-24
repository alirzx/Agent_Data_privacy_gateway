/** Line-aware chunking so multi-GB CSV/text can be encoded without one huge request. */

export const CHUNK_TARGET_BYTES = 4 * 1024 * 1024;
export const MAX_SINGLE_SHOT_BYTES = 8 * 1024 * 1024;

/**
 * Split plain text on newlines into ~targetBytes chunks (never mid-line).
 * @param {string} text
 * @param {number} [targetBytes]
 * @returns {string[]}
 */
export function splitTextIntoLineChunks(text, targetBytes = CHUNK_TARGET_BYTES) {
  if (!text) return [''];
  if (new Blob([text]).size <= targetBytes) return [text];
  const chunks = [];
  let start = 0;
  const length = text.length;
  while (start < length) {
    let end = Math.min(length, start + targetBytes);
    if (end < length) {
      const nl = text.lastIndexOf('\n', end - 1);
      if (nl >= start) end = nl + 1;
    }
    chunks.push(text.slice(start, end));
    start = end;
  }
  return chunks.length ? chunks : [''];
}

/**
 * Read a File as sequential line-complete text chunks without loading the whole file.
 * @param {File} file
 * @param {number} [targetBytes]
 * @returns {AsyncGenerator<string, void, void>}
 */
export async function* iterateFileLineChunks(file, targetBytes = CHUNK_TARGET_BYTES) {
  if (!file.stream) {
    const text = await file.text();
    for (const part of splitTextIntoLineChunks(text, targetBytes)) yield part;
    return;
  }
  const reader = file.stream().pipeThrough(new TextDecoderStream()).getReader();
  let pending = '';
  let chunk = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    pending += value;
    let cut;
    while ((cut = pending.lastIndexOf('\n')) >= 0) {
      const line = pending.slice(0, cut + 1);
      pending = pending.slice(cut + 1);
      if (new Blob([chunk + line]).size > targetBytes && chunk) {
        yield chunk;
        chunk = line;
      } else {
        chunk += line;
      }
    }
  }
  chunk += pending;
  if (chunk) yield chunk;
}

/**
 * Encode/decode large plain text via many /v1 calls sharing one context.
 * Accepts an array or async iterable of chunks so 1 GiB files need not be
 * fully buffered before the first request.
 * @param {object} args
 */
export async function transformTextChunked({
  chunks,
  operation,
  callApi,
  apiKey,
  profile,
  tenant,
  contextId,
  onProgress,
  knownTotal = null,
}) {
  let context = contextId || null;
  const blobParts = [];
  let stats = null;
  let index = 0;
  let preview = '';
  const totalHint = knownTotal || (Array.isArray(chunks) ? chunks.length : null);
  for await (const piece of chunks) {
    index += 1;
    onProgress?.({
      done: index - 1,
      total: totalHint || index,
      phase: operation,
    });
    let outPiece = '';
    if (operation === 'encode') {
      const result = await callApi('/v1/encode', apiKey, {
        context_id: context,
        profile,
        tenant_id: tenant,
        purpose: 'llm-egress',
        format: 'text',
        payload: piece,
      });
      context = result.context_id;
      outPiece = String(result.payload ?? '');
      stats = result.stats;
    } else {
      if (!context) throw new Error('Enter the Context ID from a previous encoding operation.');
      const result = await callApi('/v1/decode', apiKey, {
        context_id: context,
        format: 'text',
        payload: piece,
        purpose: 'llm-response',
        reveal_credentials: false,
      });
      outPiece = String(result.payload ?? '');
      stats = result.stats;
    }
    blobParts.push(outPiece);
    if (preview.length < 6000) preview = (preview + outPiece).slice(0, 12000);
  }
  onProgress?.({ done: index, total: index, phase: operation });
  const blob = new Blob(blobParts, { type: 'text/plain;charset=utf-8' });
  return {
    context_id: context,
    payloadBlob: blob,
    payloadPreview: preview,
    stats,
    chunks: index,
  };
}
