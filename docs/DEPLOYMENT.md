# Deployment and Configuration

## Environment template and setup

The tracked [`.env.example`](../.env.example) contains **no live keys** and is intentionally **not runnable** until `DLP_MASTER_KEY_B64` and an authorized `DLP_CLIENTS_JSON` are configured. Copy with `cp .env.example .env && chmod 600 .env` only if no `.env` exists. Never overwrite a working `.env` or regenerate a master key while any existing encrypted contexts must be decoded. For a new throwaway local demo, `python3 scripts/init_dev_env.py` creates its own `.env` and refuses to overwrite an existing file. Never commit a real `.env`.

**Integration mode:** set `DLP_DEV_MODE=false`, `DLP_UI_ENABLED=false`, keep `DLP_DEMO_API_KEY` empty, use Redis and a distinct per-service API key in `DLP_CLIENTS_JSON`. The SOC service must use its own API key, not the DLP master key. Allow only trusted canonical tenant UUIDs and set `allow_secret_decode=false`. Docker Compose overrides `DLP_STORE_BACKEND=redis`, `DLP_REDIS_URL=redis://redis:6379/0`, `DLP_PROFILE_DIR=/opt/dlp/profiles`, and the payload limits, whatever the native `.env` says. Bind only the API container to a shared private SOC Docker network; Redis stays on its own private network.

**Secret rotation:** an exposed DLP demo API key must be revoked. If a master key was exposed, schedule replacement and treat contexts encrypted under the old key as needing expiry or explicit migration; immediately changing the key without migration makes existing contexts undecodable. Do not paste credentials into tickets or chats. Backups of Redis can retain ciphertext after contexts expire.

## Local development

`python3 scripts/init_dev_env.py` creates `.env` with mode `DLP_DEV_MODE=true`, randomly generated AES key and local API key. Restrict file permissions to 0600. `make api` runs one in-process encrypted memory store; restarting invalidates its mappings. `make ui` serves the React frontend via Vite, proxying API calls to loopback FastAPI.

## Docker Compose baseline

The included Compose file uses:

- `privacy-api`: FastAPI served by non-root UID 10001, read-only filesystem, tmpfs, all Linux capabilities dropped, PID/CPU/memory caps, no access logs. **The checked-in Compose binds `8484:8484` on all host interfaces. Override with `127.0.0.1:8484:8484` for localhost testing.**
- `redis`: private network, volume-backed encrypted context ciphertext, healthcheck, memory cap, AOF persistence. No published Redis port.
- Frontend built in multi-stage Docker image and served only when `DLP_UI_ENABLED=true` and `DLP_DEV_MODE=true`.

Do not use the bundled Docker Compose as an unmodified production deployment. It defines only its own `edge` and private networks; an independently deployed Agentic SOC requires an additional shared-network override for the API container. Replace the internal Redis setup with authenticated/TLS-managed Redis, and provide ingress HTTPS/mTLS plus network egress constraints.

## Environment variables

| Variable | Required | Explanation |
|---|---|---|
| `DLP_MASTER_KEY_B64` | YES | Base64-encoded random 32-byte key. Store in KMS/Vault-backed secret infrastructure. |
| `DLP_CLIENTS_JSON` | YES in production | JSON array of per-client ID, SHA-256 key digest, tenants allow-list, and permissions. |
| `DLP_DEV_MODE` | NO | Off by default. Allows memory backend and development UI. |
| `DLP_DEMO_API_KEY` | Dev only | Ephemeral plaintext key for single local developer service principal. Never production. |
| `DLP_UI_ENABLED` | Dev only | Serves compiled React demo UI if dist exists; disallowed in prod. |
| `DLP_STORE_BACKEND` | YES | `redis` in production; `memory` only in dev. |
| `DLP_REDIS_URL` | Redis mode | Use `rediss://` and scoped auth in production. |
| `DLP_PROFILE_DIR` | NO | YAML profiles directory. Set `/opt/dlp/profiles` in container. |
| `DLP_CONTEXT_TTL` | NO | Default 3600 seconds. |
| `DLP_MAX_CONTEXT_TTL` | NO | Maximum 86400 seconds; must be >= default. |
| `DLP_MAX_ENTRIES` | NO | Maximum encrypted mapping entries/context (default **1,000,000**; Compose explicitly sets the same). |
| `DLP_MAX_PAYLOAD_BYTES` | NO | Default **64 MiB** (`67108864`) per request; Compose sets the same. The frontend currently uses roughly **2 MiB** line-aware chunks for large files. Enforce ingress body size too. |
| `DLP_CORS_ORIGINS` | Dev only | Allowed React dev origins, not `*`. |

## Service client setup

Generate an independently random credential per product. Supply the hashed credential, not the plaintext, in `DLP_CLIENTS_JSON`:

```python
import secrets, hashlib
key = secrets.token_urlsafe(48)
print("service credential:", key)
print("SHA-256 digest:", hashlib.sha256(key.encode()).hexdigest())
```

Example JSON (fill digest with actual 64 hex characters):

```json
[
  {
    "client_id": "soorin-copilot",
    "key_sha256": "<sha256-of-long-random-key>",
    "tenants": ["<canonical-tenant-uuid>"],
    "allow_tenantless": false,
    "allow_secret_decode": false
  }
]
```

Do not allow browsers to use product service keys. A production operator UI needs a separate authenticated Backend-for-Frontend and a least-privileged session proxy.

## Key lifecycle

The initial AES key is not automatically rotated. A key loss irrecoverably blocks context decryption (by design). Versioned KEK envelope rotation, rewrapping of active DEKs, KMS/HSM integration and an audited secret recovery workflow must be designed before handling production secrets. Contexts expire independently of application session duration.

## Resource sizing

The service loads **no LLM, no CUDA, no GPU and no large NLP model**. CPU/memory are predominantly a function of JSON size, regex matching and number of context aliases. Included Compose caps are example development values, not performance-certified sizing. Run your own P50/P95/P99 benchmarks with realistic Copilot/Splunk payloads and concurrency. Memory and Redis storage quotas must be monitored.

## Monitoring

Current health endpoints provide liveness/readiness; no persistent audit sink or Prometheus metrics are implemented yet. Put authentication failures, policy deny counts, context TTL misses and latency into your organization's centralized telemetry without recording payloads or identities. Implement a hardened `/metrics` endpoint before enterprise launch.
