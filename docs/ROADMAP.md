# Roadmap

## v0.1 (this repository)

- Provider-neutral stateless service boundary, tenant-aware/tenantless contexts, typed deterministic detector, HMAC aliases, restricted credential aliasing, AES-GCM encrypted mapping, Redis CAS, API, SDK, React local demo, Compose/CI and offline regression suite.
- Security profile: evaluation-ready development release; **not certified for live production private data**.

## v0.2 (integration hardening)

- Complete product field catalogs from Soorin Copilot asset profile/detection, Graph/structured context, Chat Memory and Agentic SOC canonical OCSF schemas.
- Typed SDK context passed through all Router/Repair, Planner, Investigator, Synthesizer, `safe_ainvoke`, `safe_astream`, raw-HTTP provider flows; no bypass integration tests.
- Redis TLS/Auth, audited workload identity and rate limiting, ingress maximum raw-body size, strict response alias validation.
- Per-workflow HMAC scopes and more accurate lexical detection and collision testing.

## v0.3 (streaming and distributed operations)

- Correct incremental decode across chunk-split aliases, no streaming egress to browser until safe decode boundary.
- Prometheus/OpenTelemetry metrics without sensitive payloads, append-only audit metadata, policy preview/diff, key version metadata and KMS transit backend.
- Readiness, distributed concurrency, TTL and fail-closed chaos tests; resource benchmarks and load generator.

## v1.0 (reviewed production)

- Security review, enterprise SSO/OIDC operator UI with audit and RBAC, managed KMS rewrap/recovery and rotation playbooks.
- Threat data protection coverage for arbitrary documents/attachments and known obfuscation patterns; optional local NER as defense-in-depth, not a replacement for typed schema.
- Formal semantic quality/utility benchmarks on Soorin's sanctioned sanitized SOC/NOC workflows and real deployment topology.
- Deployment profiles for Kubernetes and selected company infrastructure, network-enforced provider egress control.
