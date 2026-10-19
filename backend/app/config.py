"""Fail-closed configuration. Never log credentials, original payloads or encryption keys."""
from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from pathlib import Path


def _truthy(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    master_key: bytes
    clients: tuple[dict, ...]
    store_backend: str
    redis_url: str
    profile_dir: Path
    dev_mode: bool
    ui_enabled: bool
    max_payload_bytes: int
    max_entries: int
    default_ttl_seconds: int
    max_ttl_seconds: int
    cors_origins: tuple[str, ...]

    @classmethod
    def from_env(cls) -> "Settings":
        raw = os.getenv("DLP_MASTER_KEY_B64", "")
        try:
            key = base64.b64decode(raw, validate=True)
        except Exception as exc:
            raise RuntimeError("DLP_MASTER_KEY_B64 must be valid Base64") from exc
        if len(key) != 32:
            raise RuntimeError("DLP_MASTER_KEY_B64 must decode to exactly 32 bytes")
        dev = _truthy("DLP_DEV_MODE")
        clients = json.loads(os.getenv("DLP_CLIENTS_JSON", "[]"))
        if not isinstance(clients, list):
            raise RuntimeError("DLP_CLIENTS_JSON must be an array")
        if dev and os.getenv("DLP_DEMO_API_KEY"):
            import hashlib

            clients.append({
                "client_id": "local-dev", "key_sha256": hashlib.sha256(os.environ["DLP_DEMO_API_KEY"].encode()).hexdigest(),
                "tenants": ["*"], "allow_tenantless": True, "allow_secret_decode": False,
            })
        if not clients:
            raise RuntimeError("Configure DLP_CLIENTS_JSON or explicit local dev credentials")
        store = os.getenv("DLP_STORE_BACKEND", "memory")
        if store not in {"memory", "redis"}:
            raise RuntimeError("DLP_STORE_BACKEND must be memory or redis")
        if store == "memory" and not dev:
            raise RuntimeError("Memory backend is development-only; configure Redis for production")
        ui_enabled = _truthy("DLP_UI_ENABLED")
        if ui_enabled and not dev:
            raise RuntimeError("Browser API-key demo UI requires DLP_DEV_MODE. Use an authenticated BFF for production UI")
        base = Path(__file__).resolve().parents[2]
        profiles = Path(os.getenv("DLP_PROFILE_DIR", str(base / "profiles")))
        return cls(
            master_key=key,
            clients=tuple(clients),
            store_backend=store,
            redis_url=os.getenv("DLP_REDIS_URL", "redis://localhost:6379/0"),
            profile_dir=profiles,
            dev_mode=dev,
            ui_enabled=ui_enabled,
            max_payload_bytes=int(os.getenv("DLP_MAX_PAYLOAD_BYTES", "1048576")),
            max_entries=int(os.getenv("DLP_MAX_ENTRIES", "10000")),
            default_ttl_seconds=int(os.getenv("DLP_CONTEXT_TTL", "3600")),
            max_ttl_seconds=int(os.getenv("DLP_MAX_CONTEXT_TTL", "86400")),
            cors_origins=tuple(x.strip() for x in os.getenv("DLP_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if x.strip()) if dev else (),
        )
