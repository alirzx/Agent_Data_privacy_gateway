# Deployment and Configuration

## Environment template and setup

The tracked [`.env.example`](../.env.example) contains **no live keys** and is intentionally **not runnable** until `DLP_MASTER_KEY_B64` and an authorized `DLP_CLIENTS_JSON` are configured. Copy with `cp .env.example .env && chmod 600 .env` only if no `.env` exists. Never overwrite a working `.env` or regenerate a master key while any existing encrypted contexts must be decoded. For a new throwaway local demo, `python3 scripts/init_dev_env.py` creates its own `.env` and refuses to overwrite an existing file. Never commit a real `.env`.

**Integration mode:** set `DLP_DEV_MODE=false`, `DLP_UI_ENABLED=false`, keep `DLP_DEMO_API_KEY` empty, use Redis and a distinct per-service API key in `DLP_CLIENTS_JSON`. The SOC service must use its own API key, not the DLP master key. Allow only trusted canonical tenant UUIDs and set `allow_secret_decode=false`. Docker Compose overrides `DLP_STORE_BACKEND=redis`, `DLP_REDIS_URL=redis://redis:6379/0`, `DLP_PROFILE_DIR=/opt/dlp/profiles`, and the payload limits, whatever the native `.env` says. Bind only the API container to a shared private SOC Docker network; Redis stays on its own private network.

**Secret rotation:** an exposed DLP demo API key must be revoked. If a master key was exposed, schedule replacement and treat contexts encrypted under the old key as needing expiry or explicit migration; immediately changing the key without migration makes existing contexts undecodable. Do not paste credentials into tickets or chats. Backups of Redis can retain ciphertext after contexts expire.

## Local development

`python3 scripts/init_dev_env.py` creates `.env` with mode `DLP_DEV_MODE=true`, randomly generated AES key and local API key. Restrict file permissions to 0600. `make api` runs one in-process encrypted memory store; restarting invalidates its mappings. `make ui` serves the React frontend via Vite, proxying API calls to loopback FastAPI.

## Docker Compose baseline

The included Compose file uses:

- `privacy-api`: FastAPI served by non-root UID 10001, read-only filesystem, tmpfs, all Linux capabilities dropped, PID/CPU/memory caps, no access logs. The **development** Compose binds only `127.0.0.1:8484:8484`; the independent **production** Compose publishes no host ports and exposes only a Caddy TLS endpoint to the SOC network.
- `redis`: private network, volume-backed encrypted context ciphertext, healthcheck, memory cap, AOF persistence. No published Redis port.
- Frontend built in multi-stage Docker image and served only when `DLP_UI_ENABLED=true` and `DLP_DEV_MODE=true`.

Do not use the development Docker Compose as a production deployment. Use `docker-compose.production.yml` for the independent Agentic SOC HTTPS integration; it explicitly isolates Redis, enforces Redis TLS/ACL authentication and exposes only Caddy on the shared network.

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

## Python package mirrors for restricted-network Docker builds

The runtime image installs Python packages from one HTTPS index **at a time**, in a strict sequence:

1. Liara: `https://package-mirror.liara.ir/repository/pypi/simple/`
2. Chabokan: `https://mirror2.chabokan.net/pypi/simple/`
3. Official PyPI: `https://pypi.org/simple/` (last resort)

If installing either the Python build tools (`pip`, `setuptools`, `wheel`) or the application dependencies fails, that attempt moves to the next index. The build fails if all three sources fail. This is **sequential fallback**, not `--extra-index-url` mixing. TLS verification stays on, insecure HTTP indexes are rejected, and default pip timeouts/retries are 30 seconds/2 retries per request. A successful Simple API probe does not prove that all wheel downloads are reachable: verify a full Docker build.

Default build (no local Dockerfile edits or production `.env` changes required):

```bash
cd /root/Agent_Data_privacy_gateway
python3 ops/check_production_config.py --env .env
docker compose -p soorin-privacy-v2 -f docker-compose.production.yml config --quiet
docker compose -p soorin-privacy-v2 -f docker-compose.production.yml build privacy-api
```

The defaults are overridable at build time, for example:

```bash
docker compose -p soorin-privacy-v2 -f docker-compose.production.yml build \
  --build-arg PIP_INDEX_PRIMARY=https://package-mirror.liara.ir/repository/pypi/simple/ \
  --build-arg PIP_INDEX_SECONDARY=https://mirror2.chabokan.net/pypi/simple/ \
  --build-arg PIP_INDEX_FALLBACK=https://pypi.org/simple/ \
  --build-arg PIP_DEFAULT_TIMEOUT=45 \
  --build-arg PIP_RETRIES=2 \
  privacy-api
```

Only use package indexes operated by trusted parties. A mirror is a package supply-chain trust decision; for higher assurance, pin dependencies and verify wheel hashes in a separate hardening change. No secrets, API credentials, or private package tokens belong in Docker build arguments. The frontend's npm installation and the apt installation use different registries and are not changed by these Python-specific settings. The existing `soorin-privacy` Compose project on server 55 remains untouched when using `-p soorin-privacy-v2`.

## Server 55 production integration

Deploy independently from Agentic_SOC using **only** `docker-compose.production.yml`, never merge it with development `docker-compose.yml`. Both projects use the existing `aisoc-privacy` external Docker bridge.

```text
Agentic_SOC API + Agents  →  HTTPS https://privacy-gateway:8443
    |                                     |
    | SOC CA trust override                 Caddy (privacy-https)
    |                                     | internal-only private_http
    |                                     v
    |                               privacy-api (FastAPI)
    |                                     | verified rediss:// TLS + ACL
    |                                     v
    +----------------------------- Redis (private_store only)
```

Only `privacy-https` is on the shared network. Neither FastAPI nor Redis publishes a host port or joins the SOC network. Caddy's HTTPS server certificate must have a DNS SAN matching `DLP_GATEWAY_DNS_NAME` (default `privacy-gateway`). Redis's TLS server certificate must have DNS SAN `redis` and be signed by the CA in `DLP_REDIS_CA_HOST_PATH`. The private CA used for gateway HTTPS must be mounted into both SOC services via its existing `infra/compose/privacy-ca.override.yml`. Do **not** disable TLS verification.

### Required DevOps environment and secrets

Keep `.env` at mode 0600 and provision the following outside Git:

| Configuration | Purpose |
|---|---|
| `DLP_MASTER_KEY_B64` | Base64 encoding of 32 random bytes; preserve while contexts exist. Never share with SOC. |
| `DLP_CLIENTS_JSON` | Each client's SHA256 service key digest, canonical SOC tenant UUID allowlist, no tenantless access, no secret decode. |
| `DLP_DEV_MODE=false`, `DLP_UI_ENABLED=false`, `DLP_DEMO_API_KEY=` | Production Compose enforces these values. |
| `DLP_STORE_BACKEND=redis` | Redis storage is required. |
| `DLP_REDIS_URL` | Authenticated Redis TLS URL, not overwritten by production Compose. |
| `DLP_GATEWAY_DNS_NAME`, `DLP_SHARED_NETWORK` | Defaults `privacy-gateway` and `aisoc-privacy`. |
| `DLP_TLS_CERT_HOST_PATH`, `DLP_TLS_KEY_HOST_PATH`, `DLP_TLS_CA_HOST_PATH` | Absolute host paths for HTTPS certificate, key and CA chain. CA file is for preflight and SOC trust. |
| `DLP_REDIS_TLS_CERT_HOST_PATH`, `DLP_REDIS_TLS_KEY_HOST_PATH`, `DLP_REDIS_CA_HOST_PATH` | Absolute paths for Redis TLS server certificate, key and CA chain. |
| `DLP_REDIS_ACL_HOST_PATH`, `DLP_REDIS_PASSWORD_HOST_PATH` | Redis ACL file and matching healthcheck credential file. |
| `DLP_CONTEXT_TTL`, `DLP_MAX_CONTEXT_TTL` | Defaults 3600 and 86400 seconds. |
| `DLP_MAX_PAYLOAD_BYTES`, `DLP_MAX_ENTRIES` | Defaults 67108864 (64 MiB) and 1000000. |
| `DLP_API_CPUS`, `DLP_API_MEMORY_LIMIT` | Optional, defaults 2.0 CPU and 4g RAM. |
| `DLP_REDIS_CPUS`, `DLP_REDIS_MEMORY_LIMIT`, `DLP_REDIS_MAXMEMORY` | Optional, defaults 1 CPU, 2g RAM, 1gb Redis maxmemory. |

Redis URL template (URL-encode reserved characters in password):

```text
rediss://dlp:<URL_ENCODED_PASSWORD>@redis:6379/0?ssl_ca_certs=/run/secrets/redis-ca.pem&ssl_cert_reqs=required&ssl_check_hostname=True
```

Redis ACL must disable the default user and authorize a `dlp` user for the required operations. The file must be readable inside the Redis container, but must never be world-readable on the host. Provision a long random Redis password in a separate file and create its ACL without disclosing the password:

```bash
python3 ops/generate_redis_acl.py --password-file /ABSOLUTE/PATH/redis-password --output /ABSOLUTE/PATH/redis-users.acl
```

Certificates and private keys are supplied via read-only host bind mounts, **not committed**. DevOps owns certificate renewal and graceful reload. Restrict filesystem access based on the actual container UID. Do not log rendered Compose configuration because it may reveal credentials.

**Caddy capability note:** The upstream `caddy:2.10-alpine` executable carries a `NET_BIND_SERVICE` file capability. With `cap_drop: [ALL]` and `no-new-privileges:true` alone, the container can fail before reading the Caddyfile with `exec /usr/bin/caddy: operation not permitted` (exit 255). The production proxy explicitly adds only `NET_BIND_SERVICE` while keeping all other capabilities dropped and `no-new-privileges` enabled. Redis and the API do not receive this capability. Recreate only `privacy-https` after deploying this Compose change; no image rebuild or TLS key permission changes are needed.

### Exact deployment commands on server 55

```bash
cd /opt/apps/soorin/data_privacy_gateway
chmod 600 .env
python3 ops/check_production_config.py --env .env

docker network inspect aisoc-privacy >/dev/null 2>&1 || docker network create aisoc-privacy

docker compose -f docker-compose.production.yml config --quiet
docker compose -f docker-compose.production.yml build privacy-api
docker compose -f docker-compose.production.yml up -d --no-build redis privacy-api privacy-https
docker compose -f docker-compose.production.yml ps
docker compose -f docker-compose.production.yml logs --tail=60 redis privacy-api privacy-https
```

`ops/check_production_config.py` verifies local configuration, TLS certificate names, key pairing, Redis ACL and CA trust. It does **not** replace Docker runtime tests. If an existing development project named `soorin-privacy` is on the host, stop its containers without deleting volumes before switching the same Compose project to the production file; do not use `down -v`.

### Acceptance with Agentic_SOC

SOC uses `AISOC_LLM_PRIVACY_ENABLED=1`, `AISOC_LLM_PRIVACY_REQUIRED=1`, `AISOC_PRIVACY_BACKEND=remote`, `AISOC_PRIVACY_REMOTE_URL=https://privacy-gateway:8443`, `AISOC_PRIVACY_REMOTE_PROFILE=agentic-soc-v1`, and `AISOC_PRIVACY_REMOTE_API_KEY` (the raw service credential, not the DLP master key). Configure `AISOC_PRIVACY_EXTERNAL_NETWORK=aisoc-privacy` and `AISOC_PRIVACY_CA_BUNDLE_HOST` pointing at the trusted DLP HTTPS CA. Use *both* SOC Compose overrides: `privacy-network.override.yml` and `privacy-ca.override.yml`.

Verify inside the SOC container: HTTPS `/health` and `/ready` with CA validation, authenticated policies, context/create, classify, encode, decode and delete; then run `services/agents/scripts/check_remote_privacy_gateway.py` for a **real canonical tenant UUID** allowed in DLP. Verify 401 for invalid Bearer, 403 for unauthorized tenants, fail-closed behavior on outage, certificate rejection for an untrusted CA, and no direct API or Redis host exposure. Use synthetic payloads before real LLM calls. A successful Docker build is not equivalent to successful SOC E2E testing.

### Remaining production concerns

No Redis replication, secret-manager integration, mTLS client authentication, automatic certificate renewal, external rate limiter, production performance benchmarking or tamper-evident auditing is implemented here. Redis AOF reliability depends on the host's memory-overcommit settings. Losing the master key makes stored contexts unrecoverable. Monitor memory, CPU, latency and TTL errors. The gateway is not an outbound LLM firewall; SOC must enforce DLP fail-closed at the egress boundary.
