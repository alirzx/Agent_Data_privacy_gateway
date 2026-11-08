# Gateway production acceptance checkpoint — 2026-11-08

## Evidence received from server 55

**Scope:** Independent `soorin-privacy-v2` deployment using production FastAPI, Caddy HTTPS and Redis TLS/ACL. The `soorin-privacy-ui-test` Compose project is a separate in-memory development UI and does not prove production authorization or persistence.

**Source revision tested:** `0b7c526ac9007d7457ae07d2dc9a87e4df308dce`, synced across personal, organization and server. The deployment preflight passed, the three production containers were healthy/running, and all 12 expected secret/certificate files were present and nonempty as root. Credentials are stored outside Git in `/opt/soorin/secrets/dlp/`; do not record their actual values.

**Live smoke test (user-reported PASS, using synthetic Splunk-like alert and the existing SOC bearer token):**

- Verified Gateway HTTPS `/health` and Redis-backed `/ready`.
- Missing and invalid bearer rejected; correct token accepted.
- `agentic-soc-v1` policy available.
- Unauthorized and tenantless context creation rejected.
- Sensitive Splunk fields classified without including raw values.
- Authorized canonical tenant context created and inspected.
- Synthetic Splunk identities tokenized; non-credential decode restored original data.
- Synthetic credentials removed before egress; forbidden credential recovery returned 403.
- Invalid format rejected; context deleted.
- Final script message: `PASS: Production synthetic Splunk smoke test completed`.

**Result:** Standalone core production request flow passed. **This does not prove Agentic_SOC integration, TLS failure rejection, context persistence, cross-context alias stability, credential masking on ordinary decode, file/large-message behavior, service restart recovery, concurrent load, or fail-closed LLM egress.**

## Follow-up

The smoke script was extended after this successful run to test unknown CA rejection, profile and tenant mismatch, unknown aliases, LLM messages, same-tenant alias stability, credential masking, and deleted-context access. **These new assertions are pending execution**, not yet passed.

Before SOC cutover:
1. Run the extended test against the same production Gateway from `aisoc-privacy`, with the existing SOC token, CA and canonical tenant; capture only PASS/FAIL lines.
2. Validate production container network attachments, no published production API/Redis ports, certificate expiry, live Compose resource limits, and disk/swap pressure.
3. Inspect SOC checkout/branch/worktree and Compose overlays before applying any changes. Build SOC API and Agents in a controlled way; check HTTPS, CA and tenant from inside both running containers.
4. Run SOC E2E, fail-closed egress, and tenant-bound workflow tests.
5. **Only after successful cutover** stop the old `soorin-privacy` API and Redis and remove obsolete images selectively; preserve old Redis volumes/backups until rollback window ends. Do not prune unrelated resources.

No secrets, token digests, UUIDs, private certificates or customer payloads are committed in this report.
