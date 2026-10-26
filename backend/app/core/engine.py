"""Context-scoped irreversible-at-egress aliases with authorized reversible mappings."""
from __future__ import annotations

import asyncio
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

    def _registry_key(self, namespace: str, digest: str) -> str:
        """Opaque namespace alias registry: digest → alias (never stores originals)."""
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise PrivacyError("Invalid alias registry digest")
        ns_hash = hmac.new(
            self.crypto.derive("alias-registry-ns"),
            namespace.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return f"dlp:v1:nsalias:{ns_hash}:{digest}"

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

    def _registry_digest(self, namespace: str, kind: str, canonical_value: str) -> str:
        return hmac.new(
            self.crypto.derive("lookup:" + namespace),
            f"{kind}\x00{canonical_value}".encode(),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def _decode_registry_alias(raw: bytes | None) -> str | None:
        if raw is None:
            return None
        try:
            alias = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise PrivacyError("Corrupt alias registry entry") from exc
        if not KIND_RE.fullmatch(alias):
            return None
        return alias

    async def _mint_registry_alias(self, reg_key: str, prefix: str) -> str:
        candidate = f"{prefix}_{os.urandom(16).hex().upper()}"
        if not KIND_RE.fullmatch(candidate):
            raise PrivacyError("Generated alias failed validation")
        payload = candidate.encode("ascii")
        if await self.store.create(reg_key, payload, self.max_ttl):
            return candidate
        winner = self._decode_registry_alias(await self.store.get(reg_key))
        if winner is None:
            raise PrivacyError("Alias registry race lost without winner")
        return winner

    async def _resolve_alias(self, *, namespace: str, kind: str, canonical_value: str, prefix: str) -> str:
        """First write wins in the durable registry; later encodes only read the stored alias."""
        reg_key = self._registry_key(namespace, self._registry_digest(namespace, kind, canonical_value))
        stored = self._decode_registry_alias(await self.store.get(reg_key))
        if stored is not None:
            return stored
        return await self._mint_registry_alias(reg_key, prefix)

    async def _resolve_aliases_batch(
        self,
        *,
        namespace: str,
        specs: list[tuple[str, str, str]],
    ) -> list[str]:
        """Resolve many registry aliases with one mget, then create only the misses."""
        if not specs:
            return []
        keys = [
            self._registry_key(namespace, self._registry_digest(namespace, kind, canonical_value))
            for kind, canonical_value, _prefix in specs
        ]
        values = await self.store.mget(keys)
        aliases: list[str | None] = []
        for idx, raw in enumerate(values):
            alias = self._decode_registry_alias(raw)
            if alias is None and raw is not None:
                await self.store.delete(keys[idx])
            aliases.append(alias)
        resolved: list[str] = []
        for idx, alias in enumerate(aliases):
            if alias is None:
                _kind, _canonical, prefix = specs[idx]
                alias = await self._mint_registry_alias(keys[idx], prefix)
            resolved.append(alias)
        return resolved

    def _normalize_token_kind(self, kind: str, original: str) -> str:
        if kind == "IP":
            return "IP_OPAQUE" if ip_kind(original) == "IP_OPAQUE" else "IP"
        if kind == "USER" and re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", original):
            return "EMAIL"
        return kind

    @staticmethod
    def _storage_original(kind: str, original: str) -> str:
        """Persist a stable reversible spelling (collapse Splunk DOMAIN\\\\user escapes)."""
        if kind == "USER" and "\\" in original and not original.startswith("\\\\") and not re.match(r"^[A-Za-z]:\\", original):
            domain, _sep, account = original.partition("\\")
            return f"{domain}\\{account.lstrip('\\')}"
        return original

    async def _token(self, context: dict, dek: bytes, kind: str, original: str) -> str:
        kind = self._normalize_token_kind(kind, original)
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
        alias = await self._resolve_alias(
            namespace=context["namespace"],
            kind=kind,
            canonical_value=canonical_value,
            prefix=prefix,
        )
        # Prefer collapsed Windows principal spelling so JSON-escaped forms restore cleanly.
        context["items"][alias] = {
            "kind": kind,
            "encrypted_original": Crypto.encrypt_original(
                dek, context["context_id"], alias, self._storage_original(kind, original),
            ),
        }
        context["index"][digest] = alias
        return alias

    async def _bind_tokens(
        self,
        context: dict,
        dek: bytes,
        discovered: list,
    ) -> list[tuple[str, str, str]]:
        """Map discovered values to aliases with batched registry lookups."""
        prepared: list[tuple[str, str, str, str, str]] = []
        for item in discovered:
            kind = self._normalize_token_kind(item.kind, item.value)
            try:
                canonical_value = canonical(kind, item.value)
            except ValueError:
                canonical_value = item.value.strip()
            digest = hmac.new(
                self.crypto.derive("lookup:" + context["context_id"]),
                f"{kind}\x00{canonical_value}".encode(),
                hashlib.sha256,
            ).hexdigest()
            prepared.append((item.value, kind, canonical_value, digest, ip_kind(item.value) if kind == "IP" else kind))

        pairs: list[tuple[str, str, str]] = []
        pending_idx: list[int] = []
        pending_specs: list[tuple[str, str, str]] = []
        for idx, (original, kind, canonical_value, digest, prefix) in enumerate(prepared):
            existing = context["index"].get(digest)
            if existing:
                pairs.append((original, existing, kind))
                continue
            pending_idx.append(idx)
            pending_specs.append((kind, canonical_value, prefix))

        if pending_specs:
            if len(context["items"]) + len(pending_specs) > self.max_entries:
                raise PrivacyError("Context mapping entry limit reached")
            aliases = await self._resolve_aliases_batch(
                namespace=context["namespace"],
                specs=pending_specs,
            )
            for slot, alias in zip(pending_idx, aliases, strict=True):
                original, kind, _canonical, digest, _prefix = prepared[slot]
                context["items"][alias] = {
                    "kind": kind,
                    "encrypted_original": Crypto.encrypt_original(
                        dek,
                        context["context_id"],
                        alias,
                        self._storage_original(kind, original),
                    ),
                }
                context["index"][digest] = alias
                pairs.append((original, alias, kind))

        expanded: list[tuple[str, str, str]] = []
        for original, alias, kind in pairs:
            expanded.append((original, alias, kind))
            # Also replace its JSON-escaped spelling in serialized LLM messages.
            escaped = json.dumps(original, ensure_ascii=False)[1:-1]
            if escaped != original:
                expanded.append((escaped, alias, kind))
        expanded.sort(key=lambda entry: (-len(entry[0]), -int(_is_secret(entry[2])), entry[1]))
        return expanded

    async def _project(self, payload: Any, detector: Detector, context: dict, dek: bytes,
                       registrations: list[Registration]) -> tuple[Any, dict[str, int]]:
        # Detection is CPU-heavy on multi-MB CSV; keep the event loop free for /health.
        discovered = await asyncio.to_thread(detector.discover, payload, registrations)
        pairs = await self._bind_tokens(context, dek, discovered)

        def _case_insensitive(kind: str) -> bool:
            return kind in {
                "HOST", "EMAIL", "USER", "ASSET", "IP_OPAQUE", "SPLUNK_INDEX", "PATH", "DOMAIN",
            }

        def _boundary_ok(kind: str, original: str, text: str, start: int, end: int) -> bool:
            before = text[start - 1] if start > 0 else ""
            after = text[end] if end < len(text) else ""
            if kind == "USER" and "\\" not in original:
                if before and (before.isalnum() or before in "_\\"):
                    return False
                if after and (after.isalnum() or after == "_"):
                    return False
                return True
            if kind == "PATH":
                if before and before.isalnum():
                    return False
                if after and after.isalnum():
                    return False
                return True
            if before and (before.isalnum() or before == "_"):
                return False
            if after and (after.isalnum() or after == "_"):
                return False
            return True

        def _should_skip_global_replace(kind: str, original: str) -> bool:
            if len(original) < 2:
                return True
            if kind == "HOST" and original.casefold() in {"siem", "change", "windows", "registry", "source", "unknown"}:
                return True
            if kind in {"USER", "HOST", "ASSET"} and len(original) < 3 and "\\" not in original:
                return True
            return False

        def _boundary_prefix_suffix(kind: str, original: str) -> tuple[str, str]:
            if kind == "USER" and "\\" not in original:
                return r"(?<![A-Za-z0-9_\\])", r"(?![A-Za-z0-9_])"
            if kind == "PATH":
                return r"(?<![A-Za-z0-9])", r"(?![A-Za-z0-9])"
            return r"(?<![A-Za-z0-9_])", r"(?![A-Za-z0-9_])"

        # Precompile batched alternation regexes (longest-first) so multi-MB CSV
        # is scanned a handful of times instead of once per identity.
        # Keep batches modest so the regex engine stays linear on dense CSV.
        _REPLACE_BATCH = 120

        def _build_replace_plans(allow_short: bool) -> list[tuple[re.Pattern[str], dict[str, str]]]:
            groups: dict[tuple[str, str, bool], list[tuple[str, str]]] = {}
            for original, alias, kind in pairs:
                if _should_skip_global_replace(kind, original) and not allow_short:
                    continue
                if len(original) < 2:
                    continue
                if kind == "HOST" and original.casefold() in {"siem", "change", "windows", "registry", "source", "unknown"}:
                    continue
                prefix, suffix = _boundary_prefix_suffix(kind, original)
                key = (prefix, suffix, _case_insensitive(kind))
                groups.setdefault(key, []).append((original, alias))
            plans: list[tuple[re.Pattern[str], dict[str, str]]] = []
            for (prefix, suffix, ignore_case), items in groups.items():
                items.sort(key=lambda entry: len(entry[0]), reverse=True)
                mapping: dict[str, str] = {}
                for original, alias in items:
                    mapping[original.casefold() if ignore_case else original] = alias
                flags = re.IGNORECASE if ignore_case else 0
                for offset in range(0, len(items), _REPLACE_BATCH):
                    batch = items[offset: offset + _REPLACE_BATCH]
                    alternation = "|".join(re.escape(original) for original, _alias in batch)
                    pattern = re.compile(rf"{prefix}(?:{alternation}){suffix}", flags)
                    plans.append((pattern, mapping))
            return plans

        _plans_normal = _build_replace_plans(False)
        _plans_short = _build_replace_plans(True)

        def text_replace(text: str, *, allow_short: bool = False) -> str:
            plans = _plans_short if allow_short else _plans_normal
            if not plans:
                return text
            # Collect non-overlapping matches across all batches, longest first.
            matches: list[tuple[int, int, str]] = []
            for pattern, mapping in plans:
                ignore_case = bool(pattern.flags & re.IGNORECASE)
                for match in pattern.finditer(text):
                    raw = match.group()
                    alias = mapping.get(raw.casefold() if ignore_case else raw)
                    if alias is None:
                        continue
                    matches.append((match.start(), match.end(), alias))
            if not matches:
                return text
            matches.sort(key=lambda item: (-(item[1] - item[0]), item[0]))
            covered = bytearray(len(text))
            selected: list[tuple[int, int, str]] = []
            for start, end, alias in matches:
                view = covered[start:end]
                if view and any(view):
                    continue
                covered[start:end] = b"\x01" * (end - start)
                selected.append((start, end, alias))
            # Build once — reverse slice concatenation is O(n*matches) on multi-MB CSV.
            selected.sort(key=lambda item: item[0])
            parts: list[str] = []
            cursor = 0
            for start, end, alias in selected:
                if start < cursor:
                    continue
                parts.append(text[cursor:start])
                parts.append(alias)
                cursor = end
            parts.append(text[cursor:])
            return "".join(parts)

        def walk(value: Any, path: tuple[str, ...] = (), siblings: dict | None = None, depth: int = 0):
            if depth > 32:
                raise PrivacyError("Input nesting exceeds 32 levels")
            if isinstance(value, dict):
                return {k: walk(v, (*path, str(k)), value, depth + 1) for k, v in value.items()}
            if isinstance(value, list):
                return [walk(v, (*path, str(i)), siblings, depth + 1) for i, v in enumerate(value)]
            if isinstance(value, str):
                sem = detector._semantics(path, siblings)
                if sem and sem != "IDENTITY":
                    for original, alias, kind in pairs:
                        if value == original and (kind == sem or (sem == "IP" and kind == "IP_OPAQUE") or (sem == "USER" and kind == "EMAIL")):
                            return alias
                    if sem in {"USER", "HOST", "ASSET", "EMAIL", "IP", "SPLUNK_INDEX", "PATH", "DOMAIN"}:
                        if "\n" in value or "\r" in value or len(value) < 3:
                            return text_replace(value, allow_short=True)
                return text_replace(value)
            return value

        def finalize() -> tuple[Any, dict[str, int]]:
            result = walk(payload)
            rendered = list(_walk_strings(result))
            # Defense-in-depth: residual high-confidence identities after projection.
            remaining = detector.discover(result)
            if remaining:
                raise PrivacyError("Leakage validation failed: unmatched sensitive pattern")
            return result, {
                "tokenized_unique": len(set(alias for _o, alias, _k in pairs)),
                "mapping_entries": len(context["items"]),
                "credential_aliases": sum(1 for _o, _a, kind in pairs if _is_secret(kind)),
            }

        return await asyncio.to_thread(finalize)

    async def encode(self, principal: Principal, *, context_id: str, fmt: str, payload: Any,
                     registrations: list[Registration]) -> dict:
        self._validate_payload(payload, fmt)
        # More CAS retries: detection now yields via to_thread so concurrent encodes overlap more.
        for attempt in range(24):
            context, previous = await self._load(principal, context_id)
            policy = self.policies.get(context["profile"])
            dek = self.crypto.unwrap_dek(context_id, context["wrapped_dek"])
            protected, stats = await self._project(payload, Detector(policy), context, dek, registrations)
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
            await asyncio.sleep(0.001 * (attempt + 1))
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
