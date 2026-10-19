"""Context-scoped irreversible-at-egress aliases with authorized reversible mappings."""
from __future__ import annotations

import hashlib
import hmac
import json
import ipaddress
import os
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException

from app.core.detection import (KIND_RE, Detector, canonical, ip_kind, normalize_key)
from app.core.policy import Policy, PolicyRegistry
from app.models import Registration
from app.security.auth import Principal
from app.security.crypto import Crypto
from app.storage.store import BlobStore


class PrivacyError(ValueError):
    pass


def _utc(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _walk_strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _walk_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_strings(child)


def _is_secret(kind: str) -> bool:
    return kind.startswith("CRED_")


class PrivacyEngine:
    def __init__(self, *, crypto: Crypto, store: BlobStore, policies: PolicyRegistry,
                 max_entries: int = 10000, default_ttl: int = 3600, max_ttl: int = 86400):
        self.crypto, self.store, self.policies = crypto, store, policies
        self.max_entries, self.default_ttl, self.max_ttl = max_entries, default_ttl, max_ttl

    @staticmethod
    def _key(context_id: str) -> str:
        if not re.fullmatch(r"ctx_[a-f0-9]{32}", context_id):
            raise PrivacyError("Invalid context identifier")
        return "dlp:v1:ctx:" + context_id

    async def create_context(self, principal: Principal, *, tenant_id: str | None, profile: str,
                             ttl_seconds: int | None = None) -> dict:
        principal.authorize_tenant(tenant_id)
        policy = self.policies.get(profile)
        ttl = ttl_seconds or self.default_ttl
        if ttl < 60 or ttl > self.max_ttl:
            raise PrivacyError("Context TTL outside configured limits")
        now = int(time.time())
        context_id = "ctx_" + uuid.uuid4().hex
        dek = os.urandom(32)
        context = {
            "context_id": context_id, "tenant_id": tenant_id, "owner": principal.client_id,
            "profile": profile, "policy_version": policy.version, "created_at": now,
            "expires_at": now + ttl, "namespace": tenant_id or context_id,
            "wrapped_dek": self.crypto.wrap_dek(context_id, dek), "items": {}, "index": {}, "revision": 0,
        }
        if not await self.store.create(self._key(context_id), self.crypto.encrypt_root(context_id, context), ttl):
            raise PrivacyError("Context creation collision")
        return self._public(context)

    @staticmethod
    def _public(context: dict) -> dict:
        return {
            "context_id": context["context_id"], "tenant_id": context["tenant_id"],
            "profile": context["profile"], "policy_version": context["policy_version"],
            "expires_at": _utc(context["expires_at"]),
        }

    async def _load(self, principal: Principal, context_id: str) -> tuple[dict, bytes]:
        raw = await self.store.get(self._key(context_id))
        if raw is None:
            raise PrivacyError("Context not found or expired")
        context = self.crypto.decrypt_root(context_id, raw)
        if int(context["expires_at"]) <= int(time.time()):
            raise PrivacyError("Context expired")
        if context["owner"] != principal.client_id:
            raise HTTPException(403, detail="Context access denied")
        principal.authorize_tenant(context["tenant_id"])
        policy = self.policies.get(context["profile"])
        if policy.version != context["policy_version"]:
            raise PrivacyError("Policy version mismatch: context must be recreated")
        return context, raw

    @staticmethod
    def _validate_payload(payload: Any, fmt: str) -> None:
        if fmt == "text" and not isinstance(payload, str):
            raise PrivacyError("Text format requires a string")
        if fmt == "messages" and not (isinstance(payload, list) and all(isinstance(m, dict) and isinstance(m.get("role"), str) and "content" in m for m in payload)):
            raise PrivacyError("Messages format requires an array of role/content objects")
        if fmt not in {"text", "json", "messages"}:
            raise PrivacyError("Unsupported format")

    def _token(self, context: dict, dek: bytes, kind: str, original: str) -> str:
        if kind == "IP":
            # A typed, malformed IP must remain opaque instead of leaking.
            kind = "IP_OPAQUE" if ip_kind(original) == "IP_OPAQUE" else "IP"
        if kind == "USER" and re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", original):
            kind = "EMAIL"
        try:
            canonical_value = canonical(kind, original)
        except ValueError:
            canonical_value = original.strip()
        digest = hmac.new(self.crypto.derive("lookup:" + context["context_id"]),
                          f"{kind}\x00{canonical_value}".encode(), hashlib.sha256).hexdigest()
        existing = context["index"].get(digest)
        if existing:
            return existing
        if len(context["items"]) >= self.max_entries:
            raise PrivacyError("Context mapping entry limit reached")
        prefix = ip_kind(original) if kind == "IP" else kind
        if _is_secret(kind):
            alias = f"{prefix}_{os.urandom(16).hex().upper()}"
        else:
            namespace_key = self.crypto.derive("token-namespace:" + context["namespace"])
            token_payload = f"v1\x00{kind}\x00{canonical_value}".encode()
            alias = f"{prefix}_{hmac.new(namespace_key, token_payload, hashlib.sha256).hexdigest()[:32].upper()}"
        # Exact spelling of first registered occurrence is retained for authorized restore.
        context["items"][alias] = {
            "kind": kind,
            "encrypted_original": Crypto.encrypt_original(dek, context["context_id"], alias, original),
        }
        context["index"][digest] = alias
        return alias

    def _project(self, payload: Any, detector: Detector, context: dict, dek: bytes,
                 registrations: list[Registration]) -> tuple[Any, dict[str, int]]:
        discovered = detector.discover(payload, registrations)
        pairs: list[tuple[str, str, str]] = []
        for item in discovered:
            alias = self._token(context, dek, item.kind, item.value)
            pairs.append((item.value, alias, item.kind))
            # Also replace its JSON-escaped spelling in serialized LLM messages.
            # A Windows identity CORP\alice is rendered as CORP\\alice in JSON.
            escaped = json.dumps(item.value, ensure_ascii=False)[1:-1]
            if escaped != item.value:
                pairs.append((escaped, alias, item.kind))
        pairs.sort(key=lambda entry: (-len(entry[0]), -int(_is_secret(entry[2])), entry[1]))

        def text_replace(text: str) -> str:
            # Replace long matches first, preserve exact aliases and word boundaries.
            # Avoid cascading replacements by operating on the ORIGINAL string once.
            matches: list[tuple[int, int, str]] = []
            for original, alias, kind in pairs:
                if len(original) < 2:
                    continue
                # A single ordinary word as a HOST should never become a free-text
                # global replacement unless it has strong syntactic specificity.
                if kind == "HOST" and original.casefold() in {"siem", "change", "windows", "registry", "source", "unknown"}:
                    continue
                flags = re.IGNORECASE if kind in {"HOST", "EMAIL", "USER", "ASSET", "IP_OPAQUE"} else 0
                for m in re.finditer(rf"(?<![A-Za-z0-9_]){re.escape(original)}(?![A-Za-z0-9_])", text, flags):
                    matches.append((m.start(), m.end(), alias))
            # Distinct semantic candidates may overlap (URL/host, CIDR/IP,
            # Windows principal/path). Prefer longest interval, never splice tokens.
            matches.sort(key=lambda m: (-(m[1] - m[0]), m[0]))
            selected: list[tuple[int, int, str]] = []
            for m in matches:
                if not any(m[0] < n[1] and n[0] < m[1] for n in selected):
                    selected.append(m)
            for start, end, alias in sorted(selected, reverse=True):
                text = text[:start] + alias + text[end:]
            return text

        def walk(value: Any, path: tuple[str, ...] = (), siblings: dict | None = None, depth: int = 0):
            if depth > 32:
                raise PrivacyError("Input nesting exceeds 32 levels")
            if isinstance(value, dict):
                return {k: walk(v, (*path, str(k)), value, depth + 1) for k, v in value.items()}
            if isinstance(value, list):
                return [walk(v, (*path, str(i)), siblings, depth + 1) for i, v in enumerate(value)]
            if isinstance(value, str):
                sem = detector._semantics(path, siblings)
                if sem:
                    # A typed value must match its own kind (or normalized IP/EMAIL).
                    for original, alias, kind in pairs:
                        if value == original and (kind == sem or (sem == "IP" and kind == "IP_OPAQUE") or (sem == "USER" and kind == "EMAIL")):
                            return alias
                return text_replace(value)
            return value

        result = walk(payload)
        # Boundary invariant: none of the classified source values may survive.
        rendered = list(_walk_strings(result))
        for original, _alias, _kind in pairs:
            if any(original in content for content in rendered):
                raise PrivacyError("Leakage validation failed: classified identity remained in output")
        # Defense-in-depth: detect any residual high-confidence private value.
        remaining = detector.discover(result)
        if remaining:
            # Already-tokenized aliases are excluded by Detector._accepted.
            raise PrivacyError("Leakage validation failed: unmatched sensitive pattern")
        return result, {
            "tokenized_unique": len(set(alias for _o, alias, _k in pairs)),
            "mapping_entries": len(context["items"]),
            "credential_aliases": sum(1 for _o, _a, kind in pairs if _is_secret(kind)),
        }

    async def encode(self, principal: Principal, *, context_id: str, fmt: str, payload: Any,
                     registrations: list[Registration]) -> dict:
        self._validate_payload(payload, fmt)
        for attempt in range(6):
            context, previous = await self._load(principal, context_id)
            policy = self.policies.get(context["profile"])
            dek = self.crypto.unwrap_dek(context_id, context["wrapped_dek"])
            protected, stats = self._project(payload, Detector(policy), context, dek, registrations)
            context["revision"] += 1
            remain = context["expires_at"] - int(time.time())
            if remain <= 0:
                raise PrivacyError("Context expired")
            encrypted = self.crypto.encrypt_root(context_id, context)
            if await self.store.cas(self._key(context_id), previous, encrypted, remain):
                return {
                    "context_id": context_id, "policy_version": policy.version, "format": fmt,
                    "payload": protected, "expires_at": _utc(context["expires_at"]), "stats": stats,
                }
        raise PrivacyError("Concurrent context update conflict: retry the request")

    async def decode(self, principal: Principal, *, context_id: str, fmt: str, payload: Any,
                     reveal_credentials: bool = False, purpose: str = "llm-response") -> dict:
        self._validate_payload(payload, fmt)
        if reveal_credentials and (not principal.allow_secret_decode or purpose != "credential-recovery"):
            raise HTTPException(403, detail="Credential recovery not authorized for this client/purpose")
        context, _raw = await self._load(principal, context_id)
        dek = self.crypto.unwrap_dek(context_id, context["wrapped_dek"])
        items = context["items"]
        stats = {"rehydrated": 0, "restricted_credentials": 0, "unknown_aliases": 0}
        token_re = re.compile(r"(?<![A-Za-z0-9_])(?:CRED_[A-Z_]+|IP_(?:V4|V6)_[A-Z_]+|IP_OPAQUE|HOST|USER|EMAIL|ASSET|MAC|SUBNET|DOMAIN|URL_INTERNAL|PATH|TICKET|CASE|REFERENCE|PHONE|EMPLOYEE_ID|USER_SID|ORG_ID|AD_GROUP|CLOUD_RESOURCE|DEVICE_SERIAL|SPLUNK_INDEX)_[A-F0-9]{24,40}(?![A-Za-z0-9_])")

        def restore_text(text: str) -> str:
            stripped = text.strip()
            # Structured JSON carried *as text* in LLM messages needs its
            # string escapes re-encoded after restoration (Windows principals,
            # filesystem paths, quotes, newlines, etc.). Restore the parsed
            # value recursively rather than splice raw identities into JSON.
            if stripped.startswith(("{", "[")) and len(stripped) <= 262144:
                try:
                    nested = json.loads(stripped)
                except (json.JSONDecodeError, ValueError):
                    nested = None
                if isinstance(nested, (dict, list)):
                    return json.dumps(walk(nested), ensure_ascii=False, separators=(",", ":"))

            def replacement(match: re.Match[str]) -> str:
                alias = match.group()
                entry = items.get(alias)
                if entry is None:
                    stats["unknown_aliases"] += 1
                    return alias
                if _is_secret(entry["kind"]) and not reveal_credentials:
                    stats["restricted_credentials"] += 1
                    return "[PROTECTED_CREDENTIAL]"
                original = Crypto.decrypt_original(dek, context_id, alias, entry["encrypted_original"])
                stats["rehydrated"] += 1
                return original
            return token_re.sub(replacement, text)

        def walk(value: Any, depth: int = 0):
            if depth > 32:
                raise PrivacyError("Output nesting exceeds 32 levels")
            if isinstance(value, str):
                return restore_text(value)
            if isinstance(value, dict):
                return {key: walk(child, depth + 1) for key, child in value.items()}
            if isinstance(value, list):
                return [walk(child, depth + 1) for child in value]
            return value

        return {"context_id": context_id, "format": fmt, "payload": walk(payload), "stats": stats}

    async def delete(self, principal: Principal, context_id: str) -> None:
        await self._load(principal, context_id)
        await self.store.delete(self._key(context_id))

    def classify(self, *, profile: str, payload: Any, fmt: str,
                 registrations: list[Registration]) -> dict:
        self._validate_payload(payload, fmt)
        policy = self.policies.get(profile)
        entries = Detector(policy).discover(payload, registrations)
        counts: dict[str, int] = {}
        for item in entries:
            counts[item.kind] = counts.get(item.kind, 0) + 1
        return {"profile": policy.name, "policy_version": policy.version, "counts": counts,
                "total_detected": len(entries), "includes_original_values": False}
