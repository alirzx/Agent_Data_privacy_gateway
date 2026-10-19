"""Service-to-service identity. Client-supplied tenant headers are NEVER authoritative."""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from fastapi import Header, HTTPException, Request


@dataclass(frozen=True)
class Principal:
    client_id: str
    tenants: frozenset[str]
    allow_tenantless: bool
    allow_secret_decode: bool

    def authorize_tenant(self, tenant_id: str | None) -> None:
        if tenant_id is None and not self.allow_tenantless:
            raise HTTPException(403, detail="Tenantless contexts are not authorized")
        if tenant_id is not None and tenant_id not in self.tenants and "*" not in self.tenants:
            raise HTTPException(403, detail="Tenant not authorized")


def get_principal(request: Request, authorization: str | None = Header(default=None)) -> Principal:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, detail="Bearer service credential required", headers={"WWW-Authenticate": "Bearer"})
    supplied = hashlib.sha256(authorization[7:].encode()).hexdigest()
    for entry in request.app.state.settings.clients:
        digest = str(entry.get("key_sha256", ""))
        if len(digest) == 64 and hmac.compare_digest(supplied, digest):
            return Principal(
                client_id=str(entry["client_id"]),
                tenants=frozenset(str(t) for t in entry.get("tenants", [])),
                allow_tenantless=bool(entry.get("allow_tenantless", False)),
                allow_secret_decode=bool(entry.get("allow_secret_decode", False)),
            )
    raise HTTPException(401, detail="Invalid service credential", headers={"WWW-Authenticate": "Bearer"})
