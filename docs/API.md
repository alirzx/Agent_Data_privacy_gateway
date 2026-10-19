# REST API Reference (v0.1)

All `/v1/*` paths require `Authorization: Bearer <service-api-key>`. Keys are validated against configured SHA-256 digests; the raw keys are never persisted by the gateway. JSON responses are marked `Cache-Control: no-store`. `GET /health` and `GET /ready` are unauthenticated for private-network liveness checks. OpenAPI `/docs` is available **only in dev mode**.

## Contexts

**POST `/v1/contexts`**

```json
{"tenant_id":"organization-uuid-or-trusted-string","profile":"agentic-soc-v1","ttl_seconds":3600}
```

Tenant authorization comes from the caller's configured allow-list. This field is not an authorization credential. Omit or set null for explicitly authorized tenantless access. Return HTTP 201 with:

```json
{"context_id":"ctx_<32 hex>","tenant_id":null,"profile":"agentic-soc-v1","policy_version":"1.0.0","expires_at":"2026-...+00:00"}
```

**GET `/v1/contexts/{context_id}`** returns authorized metadata; **DELETE `/v1/contexts/{context_id}`** returns 204 and deletes context. Contexts have absolute TTL; expiration is not refreshed by decode.

## POST `/v1/encode`

```json
{
  "context_id": null,
  "profile": "agentic-soc-v1",
  "tenant_id": null,
  "purpose": "llm-egress",
  "format": "json",
  "payload": {"src_ip":"10.20.3.7", "user":"CORP\\alice", "severity":"high"},
  "registrations": [
    {"kind":"IP","value":"10.20.3.7","source":"resolved_entity","role":"internal_asset"}
  ]
}
```

If `context_id` is omitted, one is created automatically using `profile` and `tenant_id`. If present, it determines the immutable tenant/profile; request-provided profile does not override an existing context. `format` is `text` (str), `json` (JSON value), or `messages` (array of role/content objects). `registrations` are additional **trusted** semantic hints. Avoid user-controlled registrations, because a malicious client could alter classification intentionally.

Return includes `context_id`, `policy_version`, `format`, transformed `payload`, `expires_at`, and `stats` containing only counters (not original values).

A post-projection check rejects identified classified values if they remain. On failure, do not send the original request to an LLM. The detection engine is conservative; unrecognized arbitrary identifiers still require product-specific schema hints.

## POST `/v1/decode`

```json
{
  "context_id":"ctx_<32 hex>",
  "format":"json",
  "payload":{"hostname":"HOST_0123456789ABCDEF0123456789ABCDEF"},
  "purpose":"llm-response",
  "reveal_credentials":false
}
```

Only exact aliases registered in **that context** can be restored. Default credential aliases become `[PROTECTED_CREDENTIAL]`. Unknown aliases remain unchanged and increment `unknown_aliases`. For explicit credential recovery, both `purpose="credential-recovery"` and `reveal_credentials=true` are necessary, *and* the authenticated service principal must have `allow_secret_decode=true`. Normal UI and SDK never request this privilege.

## POST `/v1/classify`

Payload shape resembles `/v1/encode` but has no `context_id`. Returns counts by `kind` and total detected. Original values are not echoed; no mapping is persisted.

## GET `/v1/policies`

Lists permitted profile names and versions. YAML profiles are trusted operator-managed files. A context bound to an old policy version becomes invalid after incompatible profile changes: recreate it. This avoids silent semantic-policy drift.

## Errors

| HTTP | Meaning |
|---|---|
| 400 | Invalid context, policy or leakage verification failure |
| 401 | Missing/invalid service credential |
| 403 | Tenant/context access denied or credential recovery unauthorized |
| 413 | Body exceeds declared/parsed size limit |
| 422 | Pydantic request shape invalid (never echoes input values) |
| 503 | Unavailable context storage on readiness check |

Do not retry a privacy failure by bypassing the gateway. Client retry for CAS conflicts/timeouts must reuse the same context and be bounded; never retry unsafe side effects without idempotency controls.
