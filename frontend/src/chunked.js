/** Line-aware chunking so multi-GB CSV/text can be encoded without one huge request. */

// Stay under the gateway JSON body cap with headroom for escaping/envelope.
// Files at or below this size are encoded in a single request (no mid-stream cuts).
export const MAX_SINGLE_SHOT_BYTES = 48 * 1024 * 1024;
// Only used when the file exceeds the single-shot cap (multi-hundred-MB / GiB jobs).
export const CHUNK_TARGET_BYTES = 8 * 1024 * 1024;

/**
 * Split plain text on newlines into ~targetBytes chunks (never mid-line).
 * @param {string} text
 * @param {number} [targetBytes]
 * @returns {string[]}
 */
export function splitTextIntoLineChunks(text, targetBytes = CHUNK_TARGET_BYTES) {
  if (!text) return [''];
  const size = utf8Bytes(text);
  if (size <= targetBytes) return [text];
  const chunks = [];
  let start = 0;
  const length = text.length;
  while (start < length) {
    // Estimate char window from target bytes (ASCII-heavy SOC CSV ≈ 1 byte/char).
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

function utf8Bytes(text) {
  if (typeof TextEncoder !== 'undefined') {
    return new TextEncoder().encode(text).length;
  }
  return new Blob([text]).size;
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
  let chunkBytes = 0;
  const encoder = new TextEncoder();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    pending += value;
    let cut;
    while ((cut = pending.lastIndexOf('\n')) >= 0) {
      const line = pending.slice(0, cut + 1);
      pending = pending.slice(cut + 1);
      const lineBytes = encoder.encode(line).length;
      if (chunkBytes && chunkBytes + lineBytes > targetBytes) {
        yield chunk;
        chunk = line;
        chunkBytes = lineBytes;
      } else {
        chunk += line;
        chunkBytes += lineBytes;
      }
    }
  }
  chunk += pending;
  if (chunk) yield chunk;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Encode/decode large plain text via many /v1 calls sharing one context.
 * Retries transient network/5xx failures so long jobs do not die mid-stream.
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
  onChunk,
  knownTotal = null,
  retries = 4,
}) {
  let context = contextId || null;
  const blobParts = [];
  let stats = null;
  let index = 0;
  let bytesOut = 0;
  const totalHint = knownTotal || (Array.isArray(chunks) ? chunks.length : null);
  for await (const piece of chunks) {
    index += 1;
    onProgress?.({
      done: index - 1,
      total: totalHint || index,
      phase: operation,
    });
    let outPiece = '';
    let lastError = null;
    for (let attempt = 0; attempt < retries; attempt += 1) {
      try {
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
        lastError = null;
        break;
      } catch (err) {
        lastError = err;
        const msg = String(err?.message || err || '');
        const transient = /network|abort|timeout|HTTP 502|HTTP 503|HTTP 504|fetch/i.test(msg);
        if (!transient || attempt === retries - 1) throw err;
        await sleep(500 * (2 ** attempt));
      }
    }
    if (lastError) throw lastError;
    blobParts.push(outPiece);
    bytesOut += utf8Bytes(outPiece);
    await onChunk?.({
      piece: outPiece,
      index,
      total: totalHint || index,
      context_id: context,
      stats,
      bytesOut,
    });
  }
  onProgress?.({ done: index, total: index, phase: operation });
  const blob = new Blob(blobParts, { type: 'text/plain;charset=utf-8' });
  return {
    context_id: context,
    payloadBlob: blob,
    stats,
    chunks: index,
  };
}
