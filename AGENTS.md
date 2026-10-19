# Contribution rules for coding assistants and maintainers

- This repository provides a **security boundary**. Fail closed; never add fallback paths that send raw input to an external provider.
- Never log original payloads, passwords, tokens, decrypted mapping values, API keys, context DEKs or master keys.
- Add a regression test for every detected false positive/false negative, especially Windows principals, public IOC preservation, JSON-in-LLM-message cases, multi-tenant isolation, and secret recovery.
- Detector decisions must prefer trusted schema/registration over ambiguous free text. Do not classify arbitrary bare English words as hostnames.
- Keep DLP core independent of model providers, LangChain, LangGraph, React and specific Soorin applications; product details should live in profiles/typed adapters.
- HMAC identifiers are not encryption. Persist reversible originals only as AEAD-encrypted mappings with context ownership checks.
- Credential restoration must require a dedicated privileged client and explicit recovery purpose; ordinary decode returns protected placeholders.
- Preserve typed call contracts and access-control separation. Never use untrusted request headers as authoritative tenant membership.
- Frontend is strictly a localhost development console. No production API keys or secrets in client-side source, cookies, localStorage or telemetry.
- Run backend tests, type/syntax checks, a frontend build, and a Docker smoke before calling a feature production-ready. Cite untested areas in PR descriptions.
- Keep developer fixtures synthetic and do not copy source production notable logs or private customer data into Git.
