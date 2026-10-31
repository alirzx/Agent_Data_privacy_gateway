# Soorin Data Privacy Gateway

**An independent, provider-neutral privacy enforcement service for agentic AI, SOC/NOC analysis and asset intelligence.**

**Release:** `v0.1.0` · **Status:** functional development release, **not yet production certified**.

The gateway creates semantically typed **aliases** for private identities before external-model egress, stores authenticated-encrypted reverse mappings, and rehydrates recognized aliases for authorized internal callers. **Provider-visible aliases are not ciphertext**: original values are encrypted only inside the gateway's mapping vault.

```
Agent / Copilot  →  /v1/encode  →  External LLM  →  /v1/decode  →  Local caller
                        │                               │
                        └── Encrypted context ↔ mapping ┘
```

- Schema-first detection for JSON, conversational text and LLM messages.
- SOC/NOC entities: IPv4/IPv6, opaque IPs, MAC, CIDR/subnet, hostname, FQDN, domain, URL, user/Windows principal, email, asset, filesystem paths and organization references.
- Credential patterns: password, access/API keys, bearer/JWT, cookies, private keys and generic secrets. Credential aliases **never reveal original secrets on normal decode**.
- Tenant-/context-scoped HMAC lookup keys into an expiring registry of random typed aliases. The current implementation may reuse credential aliases across contexts in the same tenant; normal decode never reveals credential originals.
- Authenticated encryption via AES-256-GCM, per-context DEKs wrapped with a master-derived KEK; encrypted context blobs with strict TTL.
- Optimistic CAS for multi-worker Redis, HTTP service, sync/async Python SDK, React + vanilla CSS operator demo UI.
- Profiles for `generic-v1`, `agentic-soc-v1`, `soorin-copilot-v1`; source-specific typed registrations.
- Docker multi-stage build, Docker Compose, Makefile, sample data, regression tests and docs. A GitHub Actions workflow is not currently committed.

## Quick start: local development

Prerequisites: **Python 3.11+**, Node 20+ (22 recommended), npm, and optionally Docker + Compose.

```bash
python3 scripts/init_dev_env.py  # throwaway localhost DEV only; do not run if .env exists
python3 -m venv .venv
source .venv/bin/activate
pip install -e './backend[dev]' -e ./sdk/python
make test
```

Terminal 1:

```bash
make api
# FastAPI: http://127.0.0.1:8484
# OpenAPI (local dev only): http://127.0.0.1:8484/docs
```

Terminal 2:

```bash
cd frontend
npm install
npm run dev
# React: http://127.0.0.1:5173
```

Open the UI, enter the local API key printed by `init_dev_env.py`, then press **Protect payload**. The UI has two editors: original input and provider-safe output. You can reverse the direction to decode a response using the active context ID. The key lives **only in component memory**, not localStorage or browser cookies; do not use a production credential in this demo console.

## Environment configuration

The repository includes [`.env.example`](.env.example), a **fail-closed template** (blank master key and no authorized clients). Copy it to `.env` and configure `DLP_MASTER_KEY_B64` and restricted `DLP_CLIENTS_JSON` for a real service. Alternatively run `scripts/init_dev_env.py` for a local-only development instance. The local `.env` file is ignored by Git. See [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) for secure key generation, network boundaries, and rotation.

## Quick start: Docker Compose

```bash
python3 scripts/init_dev_env.py # skip if .env already exists
docker compose up --build -d
curl http://127.0.0.1:8484/ready
# UI (dev-mode only): http://127.0.0.1:8484/
```

Compose overrides the store backend to Redis; Redis is **not exposed on a host port**. **IMPORTANT:** the checked-in Compose file publishes the API on *all host interfaces* via `8484:8484`, not only loopback, and does not attach to a shared SOC network by default. For localhost testing, override the published port with `127.0.0.1:8484:8484`; for SOC integration attach only the API service to an existing private Docker network. The dev-only `/v1/dev/console` can disclose the demo API key when enabled, so never expose it on a shared network. Configure TLS/authenticated Redis, per-service credentials, and a proper proxy/service mesh for real deployments. **Do not deploy the bundled Compose unchanged on an Internet-facing host.**

## API example

Run from a shell that already loaded your `.env`:

```bash
set -a; source .env; set +a
curl -sS http://127.0.0.1:8484/v1/encode \
  -H "Authorization: Bearer $DLP_DEMO_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"profile":"agentic-soc-v1","format":"json","payload":{"src_ip":"10.20.3.7","hostname":"dc01.corp.example","severity":"high"}}'
```

The response includes the new `context_id`, `payload`, and non-sensitive counts. Save the `context_id` securely. Use it for `/v1/decode` after your LLM returns. Normal decode replaces credential aliases with `[PROTECTED_CREDENTIAL]` rather than disclosing them.

See [`docs/API.md`](docs/API.md) and [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md) for practical product adapters.

## Repository layout

| Path | Responsibility |
|---|---|
| `backend/app/core/detection.py` | Typed/schema/text entity detection |
| `backend/app/core/engine.py` | Context, encode/decode, signed alias generation, validation |
| `backend/app/core/policy.py` | Operator-defined allow-listed policy profiles |
| `backend/app/security/` | Authenticated service principals, encryption/key separation |
| `backend/app/storage/` | Memory dev store, Redis multi-worker CAS storage |
| `backend/app/main.py` | FastAPI authentication, routes, transport validation |
| `sdk/python/` | Python sync/async integration client |
| `frontend/` | React demo console with vanilla CSS |
| `profiles/` | Versioned generic, SOC and Copilot policy sets |
| `backend/tests/` | Local regression/security tests |
| `docs/` | Security model, architecture, integration, deployment, testing |

## Fundamental security constraints

1. **Never submit the unprotected payload if the DLP API is unavailable.** Fail closed.
2. **Never trust `tenant_id` supplied by an unauthenticated caller.** The service maps authenticated clients to an operator-configured tenant allow-list.
3. The `context_id` is not a bearer token; owner identity and tenant authorization are checked on every operation.
4. Host and user aliases can correlate within a tenant by design. Choose tenantless contexts or a narrower alias namespace for higher unlinkability.
5. Secret values may be encrypted inside the vault, but **normal LLM-response rehydration never reveals them**. Explicit credential recovery additionally requires a dedicated, authorized service identity and purpose.
6. Neither regex nor schema-based detection guarantees the absence of every unknown private value. Product-specific registrations and egress validation are required for high assurance.
7. Never log `INTERNAL_INPUT`, reverse mappings or protected secrets in production. Distributed tracing should store only counts and safe classifications.
8. **The current release does not include hardened incremental streaming, vault-backed KEK rotation, SSO/OIDC UI authentication, confidential-computing attestation, formal audit log persistence or comprehensive external red-team validation.** See `docs/ROADMAP.md` before production launch.

## Tests

```bash
make test
python -m compileall -q backend/app sdk/python/soorin_privacy
```

The sample fixtures contain **synthetic/test data only**, never real secrets or live customer records. All backend tests run offline; no external AI provider is needed.

## License and operations

No license has been selected by the organization yet. Before publishing this repository, choose a license and verify the provenance of test fixtures. Original Agentic SOC code is a design reference; this repository has independent implementations. See `docs/SECURITY_MODEL.md` for the actual trust assumptions.
