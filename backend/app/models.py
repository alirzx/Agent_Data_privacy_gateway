from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class Registration(BaseModel):
    kind: str
    value: str = Field(min_length=1, max_length=4096)
    source: str = Field(default="client", max_length=128)
    role: str = Field(default="", max_length=128)


class ContextCreate(BaseModel):
    tenant_id: str | None = Field(default=None, max_length=128)
    profile: str = Field(default="generic-v1", pattern=r"^[a-z0-9-]{1,64}$")
    ttl_seconds: int | None = Field(default=None, ge=60, le=86400)


class ContextResponse(BaseModel):
    context_id: str
    tenant_id: str | None
    profile: str
    policy_version: str
    expires_at: str


class EncodeRequest(BaseModel):
    context_id: str | None = None
    profile: str | None = Field(default=None, pattern=r"^[a-z0-9-]{1,64}$")
    tenant_id: str | None = None
    purpose: Literal["llm-egress", "evaluation"] = "llm-egress"
    format: Literal["text", "json", "messages"] = "json"
    payload: Any
    registrations: list[Registration] = Field(default_factory=list, max_length=250)


class EncodeResponse(BaseModel):
    context_id: str
    policy_version: str
    format: str
    payload: Any
    expires_at: str
    stats: dict[str, int]


class DecodeRequest(BaseModel):
    context_id: str
    format: Literal["text", "json", "messages"] = "json"
    payload: Any
    purpose: Literal["llm-response", "credential-recovery"] = "llm-response"
    reveal_credentials: bool = False


class DecodeResponse(BaseModel):
    context_id: str
    format: str
    payload: Any
    stats: dict[str, int]


class ClassifyRequest(BaseModel):
    profile: str = "generic-v1"
    format: Literal["text", "json", "messages"] = "json"
    payload: Any
    registrations: list[Registration] = Field(default_factory=list, max_length=250)


class ErrorResponse(BaseModel):
    detail: str
    code: str
