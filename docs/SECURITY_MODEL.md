# Security Model and Threat Analysis

## Trust boundary

- Trusted: authenticated internal product callers, an appropriately isolated privacy service, and its configured Redis/Key Management infrastructure.
- Untrusted: external LLM providers, their caches/logs, model responses, user-supplied text, RAG chunks, external/tool-produced content, and client-provided tenant claims unless verified by configuration.
- Sensitive: original host, IP, user, email, asset identifiers, internal paths, organizational references and all credential values. The encrypted mapping store must be defended as highly sensitive even though ciphertext is persisted.

## Enforced in v0.1

| Property | Implementation |
|---|---|
| Service authentication | HMAC constant-time comparison against configured SHA-256 API key digests |
| Tenant authorization | Explicit configured tenant allow-list per authenticated client |
| Context access | Bound to owner client ID, tenant membership and server-side TTL |
| Alias generation | HMAC-SHA256 for context-/tenant-scoped registry lookup; random 128-bit typed aliases cached in the expiring registry |
| Credential unlinkability | **Not guaranteed** across contexts sharing a tenant: current registry may reuse an alias until expiry. Credential originals are withheld on normal decode. |
| Encrypted original mappings | AES-256-GCM per-entry DEK with alias/context AAD |
| Encrypted storage | AES-256-GCM of whole Redis blob, including indices |
| DEK protection | Wrapped under separate master-derived KEK |
| Multi-worker writes | Redis optimistic transaction with bounded retries |
| Unknown token handling | Do not reconstruct/guess; count as unresolved |
| Default credential output | `[PROTECTED_CREDENTIAL]`, never original secret |
| Strict credential recovery | Additional principal capability + explicit purpose |
| UI | Development only, manually entered ephemeral API key never persisted by React |
| Transport size | HTTP Content-Length check and parsed-payload size cap; deploy ingress body cap |

## Not yet provided (DO NOT claim full production certification)

- Automated KMS/HSM integration, KEK rotation, rewrap migration, breach-resistant secret deletion guarantees, formal cryptographic review.
- Per-tenant authorization from an authoritative enterprise identity provider or mTLS workload identity; SHA-256 API-key hash mapping is appropriate only with sufficient random entropy and secure configuration distribution.
- Production operator UI with federated SSO, RBAC and session management. The browser's development API-key console MUST stay disabled in production.
- Hardened streaming alias-boundary decoder, object-level embedded attachments/images/OCR privacy, probabilistic PII/NER detection, complex base64/encoded-secret inspection.
- Formal prompt injection defense; network-layer prevention of provider bypass; provider data-processing agreements.
- Tamper-evident audit backend, anomaly monitoring, Redis TLS/ACL credentials, geo restrictions, rate limiting and WAF/ingress body size for clients without Content-Length.
- Per-context secure erasure guarantee (Redis AOF/backups may retain ciphertext until retention expiry); investigate operational retention and backups.

## Policy caveats

- Alias correlation remains possible within a tenant; aliases are **pseudonyms**, not anonymization. Behavioral patterns, scores, relationships and metadata can identify an organization. Adopt data minimization at product context composition too.
- Sensitive values not matched by a deterministic detector can still escape, particularly a proprietary device naming convention or unknown binary encoding. Prefer explicit, trusted registrations from source schemas. Never advertise zero leakage based solely on regex passes.
- Rehydration can restore incorrectly if the LLM alters tokens. Unknown tokens stay intact; higher-assurance applications may fail on unknown aliases rather than passing them through.
- A secret value embedded into a normal LLM response by any other channel could still be displayed if it was not registered as an alias. This service is not a complete content-filtering replacement.
- Never put real API keys into `user` prompt content to be forwarded to a provider; provider HTTP Authorization must stay outside the model-visible `payload`.

## Production checklist

1. Replace the dev API key with long random service credentials; place hashed digests in secrets-backed configuration; bind tenant permissions strictly.
2. Disable `DLP_DEV_MODE` and `DLP_UI_ENABLED`; use an authenticated, TLS-terminated server-to-server deployment.
3. Use Redis with `rediss://`, authentication/ACL, protected private network and encryption/retention controls. Test CAS behavior across processes.
4. Restrict all AI products' direct external-provider egress; require the DLP SDK or a future privacy-aware model proxy as a network-enforced boundary.
5. Store `DLP_MASTER_KEY_B64` in Vault/KMS and design versioned key rotation. Never rotate it blindly while contexts are active.
6. Set payload limits both in the reverse proxy and API. Set per-client request rate limits and Redis memory monitoring.
7. Enforce protected credential recovery through a separate privileged service identity, purpose, audit trail and no browser access.
8. Disable request-body logs, Sentry payload capture, debug trace dumps, HTTP request replay, provider prompt logging and unredacted OpenTelemetry spans.
9. Add adversarial benchmarks for evasion (escaped JSON, Unicode confusables, base64, line breaks, shell quotes and provider token mutations).
10. Perform an independent security review before protecting live customer data.
