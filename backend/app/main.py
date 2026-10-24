"""Internal privacy service API. Never log request/response payload bodies."""
from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.config import Settings
from app.core.engine import PrivacyEngine, PrivacyError
from app.core.policy import PolicyRegistry
from app.models import (ClassifyRequest, ContextCreate, ContextResponse, DecodeRequest,
                        DecodeResponse, EncodeRequest, EncodeResponse)
from app.security.auth import Principal, get_principal
from app.security.crypto import Crypto
from app.storage.store import MemoryBlobStore, RedisBlobStore

logger = logging.getLogger("soorin_dlp")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    policies = PolicyRegistry(settings.profile_dir)
    store = (MemoryBlobStore() if settings.store_backend == "memory" else RedisBlobStore(settings.redis_url))
    engine = PrivacyEngine(
        crypto=Crypto(settings.master_key), store=store, policies=policies,
        max_entries=settings.max_entries, default_ttl=settings.default_ttl_seconds,
        max_ttl=settings.max_ttl_seconds,
    )
    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        if callable(getattr(store, "close", None)):
            await store.close()

    app = FastAPI(title="Soorin Data Privacy Gateway", version="0.1.0", docs_url="/docs" if settings.dev_mode else None,
                  redoc_url=None, openapi_url="/openapi.json" if settings.dev_mode else None, lifespan=lifespan)
    app.state.settings = settings
    app.state.engine = engine
    app.state.store = store
    if settings.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins),
                           allow_credentials=False, allow_methods=["GET", "POST", "DELETE"],
                           allow_headers=["authorization", "content-type"])

    @app.middleware("http")
    async def request_guards(request: Request, call_next):
        length = request.headers.get("content-length")
        if length:
            try:
                if int(length) > settings.max_payload_bytes:
                    return JSONResponse(status_code=413, content={"code": "PAYLOAD_TOO_LARGE", "detail": "Request exceeds payload limit"})
            except ValueError:
                return JSONResponse(status_code=400, content={"code": "BAD_LENGTH", "detail": "Invalid content length"})
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' http://localhost:8484 http://127.0.0.1:8484; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        return response

    @app.exception_handler(PrivacyError)
    async def privacy_error(_request: Request, exc: PrivacyError):
        # No offending plaintext value is ever interpolated into error detail.
        return JSONResponse(status_code=400, content={"code": "PRIVACY_ERROR", "detail": str(exc)})

    @app.exception_handler(ValueError)
    async def value_error(_request: Request, _exc: ValueError):
        return JSONResponse(status_code=400, content={"code": "INVALID_INPUT", "detail": "Invalid input or privacy policy"})

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, _exc: RequestValidationError):
        # Pydantic error details may contain input values: do not expose them.
        return JSONResponse(status_code=422, content={"code": "INVALID_REQUEST", "detail": "Request validation failed"})

    def bound(request: Request, value: object) -> None:
        try:
            size = len(json.dumps(jsonable_encoder(value), ensure_ascii=False).encode())
        except (TypeError, ValueError):
            raise PrivacyError("Payload is not valid JSON") from None
        if size > request.app.state.settings.max_payload_bytes:
            raise HTTPException(413, detail="Payload exceeds configured limit")

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "soorin-data-privacy-gateway"}

    @app.get("/ready")
    async def ready():
        try:
            good = await store.ping()
        except Exception:
            good = False
        if not good:
            raise HTTPException(503, detail="Encrypted context storage unavailable")
        return {"status": "ready", "store": settings.store_backend}

    @app.get("/v1/policies")
    async def list_policies(_principal: Principal = Depends(get_principal)):
        return {"policies": policies.names()}

    @app.post("/v1/contexts", response_model=ContextResponse, status_code=201)
    async def create_context(body: ContextCreate, principal: Principal = Depends(get_principal)):
        return await engine.create_context(principal, tenant_id=body.tenant_id,
                                           profile=body.profile, ttl_seconds=body.ttl_seconds)

    @app.get("/v1/contexts/{context_id}", response_model=ContextResponse)
    async def context_info(context_id: str, principal: Principal = Depends(get_principal)):
        context, _ = await engine._load(principal, context_id)
        return engine._public(context)

    @app.delete("/v1/contexts/{context_id}", status_code=204)
    async def delete_context(context_id: str, principal: Principal = Depends(get_principal)):
        await engine.delete(principal, context_id)

    @app.post("/v1/encode", response_model=EncodeResponse)
    async def encode(body: EncodeRequest, request: Request, principal: Principal = Depends(get_principal)):
        bound(request, body)
        if body.purpose == "evaluation" and not settings.dev_mode:
            raise HTTPException(403, detail="Evaluation purpose disabled in production")
        if body.context_id:
            existing, _ = await engine._load(principal, body.context_id)
            if body.profile is not None and body.profile != existing["profile"]:
                raise PrivacyError("Profile does not match existing context")
            if body.tenant_id is not None and body.tenant_id != existing["tenant_id"]:
                raise PrivacyError("Tenant does not match existing context")
            context_id = body.context_id
        else:
            info = await engine.create_context(principal, tenant_id=body.tenant_id,
                                               profile=body.profile or "generic-v1")
            context_id = info["context_id"]
        return await engine.encode(principal, context_id=context_id, fmt=body.format,
                                   payload=body.payload, registrations=body.registrations)

    @app.post("/v1/decode", response_model=DecodeResponse)
    async def decode(body: DecodeRequest, request: Request, principal: Principal = Depends(get_principal)):
        bound(request, body)
        return await engine.decode(principal, context_id=body.context_id, fmt=body.format,
                                   payload=body.payload, purpose=body.purpose,
                                   reveal_credentials=body.reveal_credentials)

    @app.post("/v1/classify")
    async def classify(body: ClassifyRequest, request: Request, _principal: Principal = Depends(get_principal)):
        bound(request, body)
        return engine.classify(profile=body.profile, payload=body.payload, fmt=body.format,
                               registrations=body.registrations)

    if settings.ui_enabled:
        built = Path(__file__).resolve().parents[2] / "frontend" / "dist"
        # In-container location is /opt/dlp/frontend/dist, not relative backend path.
        if not built.exists():
            built = Path(__file__).resolve().parents[3] / "frontend" / "dist"
        if built.exists() and (built / "index.html").exists():
            app.mount("/assets", StaticFiles(directory=built / "assets"), name="assets")

            @app.get("/")
            async def index():
                return FileResponse(built / "index.html")

            @app.get("/favicon.svg")
            async def favicon():
                return FileResponse(built / "favicon.svg", media_type="image/svg+xml")

    return app
