# Integrating Soorin Copilot and Agentic SOC

These are integration **instructions and source-specific targets**, not patches applied to the upstream repositories. Source references were checked against `Soorin_Copilot/dev` at `71473fd9` and `Agentic_SOC/data-preventing-layer` at `b4873e56` (2026-10-19).

## Universal contract

```python
async with AsyncPrivacyClient("http://privacy-api:8484", api_key=SERVICE_KEY) as privacy:
    context = await privacy.create_context(tenant_id=TRUSTED_TENANT, profile=PROFILE)
    projected = await privacy.encode(messages, format="messages", context_id=context["context_id"], registrations=IDENTITY_HINTS)
    # This is the ONLY data that can be sent to an untrusted provider.
    provider_response = await your_model_call(projected["payload"])
    local = await privacy.decode(provider_response, format="text", context_id=context["context_id"])
    return local["payload"]
```

`IDENTITY_HINTS` are constructed **from trusted internal entity resolution**, not untrusted prompt text or unauthenticated headers. `TRUSTED_TENANT` is the platform-authoritative tenant identifier. The DLP service will reject any tenant not allowed for the service credential.

**Do not reuse a `context_id` across authenticated caller identities or unrelated tenants.** Use a workflow-level context for multi-step investigation, retry and repair when aliases must stay stable. If the context expires, abort or restart the protected workflow; never bypass the service.

## Soorin Copilot integration seam

Source: `app/src/core/llm/client.py`

Recommended design:

1. Inject one `AsyncPrivacyClient` or synchronous `PrivacyClient` alongside `LLMClient`, with service key loaded from a secret manager.
2. Pass an authenticated `PrivacyCallContext(context_id, tenant_id, registrations, policy_profile)` to the single `chat()` and `stream_chat()` boundaries; never acquire tenant identity from the prompt.
3. Before calls in `SemanticIntentRouter` (`intent_router` and `intent_router_repair`), collect `ResolvedEntity` and `SessionRoutingState` identity metadata, and use one context for both calls.
4. Planner (`agent/planner.py`) passes trusted typed `task.entities`; decode **before** `PlanValidator`.
5. Investigator (`agent/investigator.py`) projects the final compacted JSON after `InvestigatorContextBuilder` and keeps its action/evidence ledger canonical. Decode before `AgentDecision` validation and tool execution.
6. Synthesizer (`agent/nodes.py` / `context/synthesizer_prompt.py`) protects the final `model_messages` after `ContextComposer` has allocated evidence. Run an additional post-encoding token budget check.
7. Recovery/retry must call the same protected LLM boundary. Do not let `provider.chat` or `provider.stream_chat` become a bypass route.
8. Streaming: until a trusted incremental decoder exists, **buffer the entire provider stream**, decode in full, then emit to the UI. This sacrifices time-to-first-token but prevents partial alias exposure.
9. Keep Graph/Neo4j, asset-profile/detection, RAG, and Memory retrieval canonical inside the private network. Model-facing projections are where DLP applies. If embeddings/rerankers later become external, they need a separate DLP boundary.
10. Product-level JWT/session permissions remain product concerns; the DLP's service credential and tenant allow-list are not a substitute for a user access-control system.

## Agentic SOC integration seam

Source: `services/agents/app/llm/contract.py` (`safe_ainvoke`, `safe_astream`, `safe_chat_completions_request`).

Recommended migration:

1. Add `AISOC_PRIVACY_BACKEND={local,remote}` and `AISOC_PRIVACY_REMOTE_URL`, default `local` while running regression tests.
2. Preserve `LLMInputContract` and validated tenant resolution (`privacy/tenant.py`). Keep provider routing in the existing `llm/factory.py` and LiteLLM layer.
3. Replace the implementation behind `PrivacyGateway.project_messages` / `.process_response` only for remote backend; **do not duplicate redaction in individual agents**.
4. Use one DLP context for the entire Investigator workflow (Recon, Forensic, Responder, ReportWriter), including retries.
5. Ensure the canonical Splunk/OCSF normalization and Fused Alert conversion remain identical between harness and production. DLP is not responsible for reconstructing business semantics omitted upstream.
6. Replay all sanitized fixtures in `privacy_real_eval/mock_data` with comparison of `INTERNAL_INPUT`, `PROVIDER_INPUT`, `PROVIDER_RESPONSE`, `LOCAL_RESPONSE`. Exclude sensitive traces from source control. Only use real provider APIs with explicit operator approval.
7. First prove identity safety/rehydration independently of forensic verdict quality; LLM hallucinations and `json.loads` empty-output failures are separate concerns.
8. Retire the legacy pseudonymizer only after end-to-end parity and a rollback plan. Never enable 'fallback to raw prompt' if remote DLP fails.

## Typed registrations

Consider a Copilot entity already resolved as a private organization asset:

```python
registrations = [
    {"kind": "IP", "value": entity.ip, "source": "copilot.entity_resolution", "role": "organization_asset"},
    {"kind": "HOST", "value": entity.hostname, "source": "asset_profile.hostname", "role": "organization_host"},
]
```

This removes ambiguity between a public IOC and an organization-owned public IP. Avoid registering unknown strings as `HOST` just because they look like English words; specifically avoid reintroducing the prior `SIEM`/`Change` over-tokenization bug.

## Provider guidance

Add a brief **system instruction** to provider messages, once per protected workflow:

> Some organizational identities have been replaced with typed, opaque aliases. Treat aliases as stable identifiers for this workflow, preserve their exact spelling in structured outputs and tool arguments, and never attempt to infer the hidden original values.

Never send the encrypted mapping vault, the service key, or `context_id` into the LLM prompt. `context_id` is an internal capability reference between authenticated services, not a model argument.

## Separate model JSON validation

DLP returns sanitized/rehydrated strings, not a valid SOC verdict or valid Agent plan by itself. Validate provider `finish_reason`, nonempty `content`, JSON schema and plan/action safety **after** decode, and avoid silently accepting malformed or hallucinated output. A truncated DeepSeek response is not proof of a DLP defect.
