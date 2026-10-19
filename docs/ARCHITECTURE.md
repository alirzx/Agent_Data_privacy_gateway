# Architecture and Data Flow

## Goal

One privacy service, not a custom redactor embedded independently in each Soorin product. The v0.1 service has a pure detection/codec core, a stateless HTTP API tier and a shared encrypted mapping store. Applications retain responsibility for routing, RAG, graph retrieval, prompts and LLM orchestration.

```
                 Soorin Copilot / Agentic SOC
                             |
               [final model-facing context]
                             v
            Python SDK / TLS / service identity
                             |
                 POST /v1/encode
                             |
                   PolicyRegistry
                             |
                   Detector
               explicit / schema / text
                             |
               Context-aware alias codec
                 /               \
         HMAC identity        random credential
                 \               /
                  Encrypted Mapping
                   |           |
             per-context DEK   wrapped KEK
                   |           |
                    Redis CAS store
                             |
                     Safe Payload
                             |
                 EXTERNAL LLM (product)
                             |
                    Provider response
                             |
                 POST /v1/decode
                             |
        owner + tenant + purpose authorization
                             |
             exact-token mapping lookup
                             |
             canonical internal response
```

## Why provider routing is not in this repository

Embedding Arvan, OpenAI, LiteLLM or LangChain in the DLP service would add uncontrolled network and credential responsibility. Products call the privacy service before their existing provider transport and decode after the response. An optional *future* reverse-proxy mode could enforce the egress boundary physically. v0.1 is NOT an egress firewall; operators must restrict direct provider network access with deployment policies.

## Identity algorithms

- For non-credential kinds: canonicalize (IP normalization, casefold for identities, etc), derive an isolated HMAC namespace from master key + tenant (or unique context when tenantless), compute `HMAC-SHA256(version || kind || canonical value)` and render a typed alias (32 hex characters). A value appearing repeatedly in messages can be recognized across nested fields and text; no raw ID is present in the alias itself.
- For credentials: random 128-bit alias suffix, with reuse *within the same active context* using a keyed lookup index; aliases vary across contexts.
- HMAC tokens are **not decryptable**. `decode` is an authorized reverse mapping lookup, not reverse cryptography.
- Public IOC preservation is contextual: free-text global public IPs are not pseudonymized automatically; explicitly typed `src_ip` or registered asset IPs are pseudonymized in the default profiles.

## Encapsulation and cryptography

Each context has an independent random 256-bit DEK; its wrapped form is stored inside the encrypted context document. Each original value is AES-256-GCM encrypted under the context DEK with associated data binding the alias and context ID. The **entire** context document (including indices, wrapped DEK, tenant binding and metadata) is additionally AES-256-GCM encrypted with a purpose-separated master-derived encryption key. AES-GCM nonces are random 96-bit values. Stored Redis values have no raw identity strings or readable aliases. The master key is a 32-byte random secret, Base64-encoded in external configuration; it is never generated automatically on application startup.

The current `v1` design uses one master KEK and requires preserving that key to decode existing contexts. **Do not rotate or remove it without a migration design.** To use a managed KMS, implement versioned key wrapping and key-rotation procedures before production.

## Context lifecycle and concurrency

1. Authenticated principal creates or implicitly creates a context.
2. Service verifies tenant membership against its *configured* principal allow-list.
3. Context has an absolute TTL; decode must present the same context identifier and authentication principal.
4. On encode, the current encrypted blob is read/decrypted, new registrations added and the whole encrypted snapshot atomically replaced via optimistic CAS (Redis `WATCH/MULTI`). Retry at most six times, then fail closed.
5. Encrypted mapping keys expire through store TTL; explicit DELETE removes the context immediately.
6. Decode reads only aliases registered inside that specific context; unknown/modified aliases are not guessed.

The development memory store is encrypted but is not shared across processes. Redis is required for multiple workers/containers.

## Typed detection

Resolution order:

1. Trusted explicit registrations from authenticated product.
2. JSON paths/field keys, including nested OCSF (`device.name`, `src_endpoint.ip`, etc.).
3. Conservative free-text lexical matches (internal IP, Windows domain principal, internal FQDN, MAC, file path, known credential shapes).
4. Existing candidates are substituted in free text (longest spans first) so cross-field identity references remain consistent.
5. A final scan refuses any remaining high-confidence sensitive pattern; refusal is preferable to leaking a value.

The detector intentionally does **not** classify arbitrary bare words (`SIEM`, `Change`) as hostnames. Ambiguous short hostnames and custom identifiers must arrive as typed data or explicit registrations from the source product.

## Where integration occurs

**Soorin Copilot**: `app/src/core/llm/client.py` `chat` and `stream_chat` are common egress points, but `EntityResolution`, `RoutingContext`, `Planner`, `InvestigatorContext`, `ContextComposer`, `Synthesizer` and Retry/Repair paths should propagate validated identity registrations. Graph/RAG/Product/Memory remain canonical until the final model projection. Perform a second token-budget check after tokenization.

**Agentic SOC**: retain `safe_ainvoke()` and `safe_astream()` as the call boundary; implement a selectable `remote` privacy adapter and preserve `LLMInputContract`. Use canonical authenticated tenant resolution, not untrusted `X-Tenant-Id`. Run the original sanitized real-provider fixtures in parallel with local tests. Do not conflate DLP failures with LLM JSON/schema errors.

## Operational limitations

Streaming must **buffer the whole provider response** until a vetted incremental decoder exists. The current gateway API accepts complete payloads, not open SSE streams; use whole-response protection in client adapters. Memory data already present in a provider prompt needs the same policy regardless of its source. Unauthorized client/tenant requests must fail before any outside-model call.
