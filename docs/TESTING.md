# Testing, Verification and Regression Plan

## Offline tests

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e './backend[dev]'
make test
```

Tests include AES-GCM encryption/integrity and context binding; authenticated tenant isolation; deterministic identity and context-scoped credential aliases; credential recovery restrictions; expired/deleted contexts; nested OCSF and structured Copilot JSON; Windows principal, private/opaque IPs, MAC/CIDR, public IOC preservation; exact rehydration and unknown alias rejection; JSON-serialized LLM message handling; concurrent writes and payload limits.

## Real sample fixtures

- `examples/soc_notable.json` resembles a sanitized Splunk/OCSF Password Spray finding. `B_309` is a nonstandard *opaque* source identifier in a typed IP field; `T1110.003` must remain meaningful. `SIEM` and `Windows Registry Change` are not hosts.
- `examples/copilot_context.json` combines task, asset profile, Graph and memory references and demonstrates cross-field alias reuse.

Both fixtures use test-only identities and secret strings; do not copy customer notables into public repositories. For source-specific full workflow evaluation use the existing Agentic SOC `privacy_real_eval/` harness with approved read-only evaluation and human-private trace files.

## Next gates before production

1. SOC: all six sanitized Splunk scenarios × Auto-Triage and Investigator, with all four trace stages and real-provider comparison.
2. Copilot: Router/Repair, Planner, Investigator, Synthesizer, streaming-recovery and multi-turn memory/Graph/RAG semantic continuity.
3. Negative coverage: mixed-case identities, Windows escapes in JSON strings, unusual Unicode, delimiters, emails inside URLs, nested credential paths, unknown/modified tokens, cross-tenant/cross-client restore attempts, concurrent CAS collisions.
4. Benchmarks: 1 KB / 10 KB / 100 KB / 1 MB JSON, 10/50/200 concurrent requests, P50/P95/P99 encode/decode, peak resident memory and Redis blob growth.
5. Security testing: mTLS/ACL, cross-origin browser access, ingress body-size without Content-Length, Redis outage, master-key rotation, encryption failure, payload logging, bypassed Provider calls, long-tail detector false negatives.
6. External review against OWASP LLM and API security guidance before handling confidential customer production data.

## Result interpretation

A passing offline test asserts only a specific security/function invariant. It does not prove model reasoning quality or full production safety. The Agentic SOC 12 Oct 2026 Auto-Triage JSON parse failure remains diagnostically separate from DLP unless the provider trace establishes otherwise.
