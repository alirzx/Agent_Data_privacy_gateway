from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def settings():
    return Settings(
        master_key=b"\xa5" * 32,
        clients=(
            {"client_id": "copilot", "key_sha256": hashlib.sha256(b"test-copilot-key").hexdigest(),
             "tenants": ["tenant-1"], "allow_tenantless": True, "allow_secret_decode": False},
            {"client_id": "soc", "key_sha256": hashlib.sha256(b"test-soc-key").hexdigest(),
             "tenants": ["tenant-2"], "allow_tenantless": False, "allow_secret_decode": False},
            {"client_id": "recovery", "key_sha256": hashlib.sha256(b"test-recovery-key").hexdigest(),
             "tenants": ["tenant-1"], "allow_tenantless": True, "allow_secret_decode": True},
        ),
        store_backend="memory", redis_url="", profile_dir=ROOT / "profiles", dev_mode=True,
        ui_enabled=False, max_payload_bytes=1_048_576, max_entries=1000,  # keep tight in unit tests
        default_ttl_seconds=3600, max_ttl_seconds=86400, cors_origins=(),
        demo_api_key=None,
    )


@pytest.fixture
def client(settings):
    with TestClient(create_app(settings)) as client:
        yield client


@pytest.fixture
def auth():
    return {"Authorization": "Bearer test-copilot-key"}
