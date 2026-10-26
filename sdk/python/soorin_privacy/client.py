"""Stateless callers with explicit context ownership. Do not log payloads or credentials."""
from __future__ import annotations
from typing import Any
import httpx


class PrivacySDKError(RuntimeError):
    def __init__(self, code: int, message: str):
        super().__init__(f"Privacy gateway returned HTTP {code}: {message}")
        self.status_code = code


def _parse(resp: httpx.Response) -> dict:
    try:
        data = resp.json()
    except ValueError:
        raise PrivacySDKError(resp.status_code, "invalid_gateway_response") from None
    if not resp.is_success:
        raise PrivacySDKError(resp.status_code, str(data.get("code", "gateway_request_failed")))
    return data


class PrivacyClient:
    def __init__(self, base_url: str, api_key: str, *, timeout: float = 600.0,
                 transport: httpx.BaseTransport | None = None):
        if not api_key:
            raise ValueError("api_key is required")
        self._client = httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout,
                                    headers={"Authorization": f"Bearer {api_key}"},
                                    transport=transport, follow_redirects=False)

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _request(self, method: str, path: str, **kwargs):
        return _parse(self._client.request(method, path, **kwargs))

    def create_context(self, *, tenant_id: str | None = None, profile: str = "generic-v1",
                       ttl_seconds: int | None = None) -> dict:
        return self._request("POST", "/v1/contexts", json={"tenant_id": tenant_id, "profile": profile, "ttl_seconds": ttl_seconds})

    def encode(self, payload: Any, *, format: str = "json", context_id: str | None = None,
               profile: str | None = None, tenant_id: str | None = None,
               registrations: list[dict] | None = None) -> dict:
        return self._request("POST", "/v1/encode", json={"payload": payload, "format": format,
             "context_id": context_id, "profile": profile, "tenant_id": tenant_id,
             "registrations": registrations or []})

    def decode(self, payload: Any, *, context_id: str, format: str = "json") -> dict:
        return self._request("POST", "/v1/decode", json={"payload": payload, "format": format, "context_id": context_id,
                   "purpose": "llm-response", "reveal_credentials": False})

    def encode_text_file(self, path: str, *, context_id: str | None = None, profile: str | None = None,
                         tenant_id: str | None = None, chunk_bytes: int = 8_388_608,
                         output_path: str | None = None) -> dict:
        """Encode a plain-text/CSV file. Small files go in one request; larger files chunk."""
        import os
        from pathlib import Path

        src = Path(path)
        out = Path(output_path) if output_path else src.with_suffix(src.suffix + ".protected")
        file_size = src.stat().st_size
        # One shot when the file fits a single gateway body (with JSON envelope headroom).
        single_shot_cap = min(chunk_bytes * 6, 48 * 1024 * 1024)
        if file_size <= single_shot_cap:
            text = src.read_text(encoding="utf-8", errors="replace")
            result = self.encode(
                text, format="text", context_id=context_id, profile=profile, tenant_id=tenant_id
            )
            out.write_text(str(result.get("payload", "")), encoding="utf-8", newline="")
            return {
                "context_id": result["context_id"],
                "output_path": str(out),
                "stats": result.get("stats"),
                "chunks": 1,
                "bytes": os.path.getsize(out),
            }
        context = context_id
        stats = None
        chunks = 0
        with src.open("r", encoding="utf-8", errors="replace", newline="") as reader, out.open(
            "w", encoding="utf-8", newline=""
        ) as writer:
            buf: list[str] = []
            size = 0
            def flush() -> None:
                nonlocal context, stats, chunks, buf, size
                if not buf:
                    return
                piece = "".join(buf)
                buf, size = [], 0
                result = self.encode(
                    piece, format="text", context_id=context, profile=profile, tenant_id=tenant_id
                )
                context = result["context_id"]
                stats = result.get("stats")
                writer.write(str(result.get("payload", "")))
                chunks += 1

            for line in reader:
                encoded = line.encode("utf-8", errors="replace")
                if size and size + len(encoded) > chunk_bytes:
                    flush()
                buf.append(line)
                size += len(encoded)
            flush()
        return {"context_id": context, "output_path": str(out), "stats": stats, "chunks": chunks, "bytes": os.path.getsize(out)}

    def delete_context(self, context_id: str) -> None:
        resp = self._client.delete(f"/v1/contexts/{context_id}")
        if resp.status_code != 204:
            _parse(resp)


class AsyncPrivacyClient:
    def __init__(self, base_url: str, api_key: str, *, timeout: float = 600.0,
                 transport: httpx.AsyncBaseTransport | None = None):
        if not api_key:
            raise ValueError("api_key is required")
        self._client = httpx.AsyncClient(base_url=base_url.rstrip("/"), timeout=timeout,
                                         headers={"Authorization": f"Bearer {api_key}"},
                                         transport=transport, follow_redirects=False)

    async def aclose(self):
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        await self.aclose()

    async def _request(self, method: str, path: str, **kwargs):
        return _parse(await self._client.request(method, path, **kwargs))

    async def create_context(self, *, tenant_id: str | None = None, profile: str = "generic-v1",
                             ttl_seconds: int | None = None) -> dict:
        return await self._request("POST", "/v1/contexts", json={"tenant_id": tenant_id, "profile": profile, "ttl_seconds": ttl_seconds})

    async def encode(self, payload: Any, *, format: str = "json", context_id: str | None = None,
                     profile: str | None = None, tenant_id: str | None = None,
                     registrations: list[dict] | None = None) -> dict:
        return await self._request("POST", "/v1/encode", json={"payload": payload, "format": format,
             "context_id": context_id, "profile": profile, "tenant_id": tenant_id,
             "registrations": registrations or []})

    async def decode(self, payload: Any, *, context_id: str, format: str = "json") -> dict:
        return await self._request("POST", "/v1/decode", json={"payload": payload, "format": format, "context_id": context_id,
                    "purpose": "llm-response", "reveal_credentials": False})

    async def delete_context(self, context_id: str) -> None:
        resp = await self._client.delete(f"/v1/contexts/{context_id}")
        if resp.status_code != 204:
            _parse(resp)
