"""Encrypted blob persistence with atomic compare-and-swap; no plaintext Redis mappings."""
from __future__ import annotations

import asyncio
from typing import Protocol


class Conflict(Exception):
    pass


class BlobStore(Protocol):
    async def get(self, key: str) -> bytes | None: ...
    async def create(self, key: str, value: bytes, ttl: int) -> bool: ...
    async def cas(self, key: str, original: bytes, value: bytes, ttl: int) -> bool: ...
    async def delete(self, key: str) -> None: ...
    async def ping(self) -> bool: ...


class MemoryBlobStore:
    """Single-process encrypted development backend; never use across workers."""

    def __init__(self):
        self._items: dict[str, tuple[bytes, float]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> bytes | None:
        async with self._lock:
            value = self._items.get(key)
            if not value:
                return None
            if value[1] <= asyncio.get_running_loop().time():
                self._items.pop(key, None)
                return None
            return value[0]

    async def create(self, key: str, value: bytes, ttl: int) -> bool:
        async with self._lock:
            old = self._items.get(key)
            if old and old[1] > asyncio.get_running_loop().time():
                return False
            self._items[key] = (value, asyncio.get_running_loop().time() + ttl)
            return True

    async def cas(self, key: str, original: bytes, value: bytes, ttl: int) -> bool:
        async with self._lock:
            current = self._items.get(key)
            if not current or current[1] <= asyncio.get_running_loop().time() or current[0] != original:
                return False
            self._items[key] = (value, min(current[1], asyncio.get_running_loop().time() + ttl))
            return True

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._items.pop(key, None)

    async def ping(self) -> bool:
        return True


class RedisBlobStore:
    """Cluster-safe CAS by WATCH/MULTI; use trusted private Redis with TLS/Auth in production."""

    def __init__(self, url: str):
        import redis.asyncio as redis

        self._client = redis.from_url(url, decode_responses=False, socket_connect_timeout=2, socket_timeout=3)

    async def get(self, key: str) -> bytes | None:
        return await self._client.get(key)

    async def create(self, key: str, value: bytes, ttl: int) -> bool:
        return bool(await self._client.set(key, value, ex=ttl, nx=True))

    async def cas(self, key: str, original: bytes, value: bytes, ttl: int) -> bool:
        from redis.exceptions import WatchError

        async with self._client.pipeline(transaction=True) as pipe:
            try:
                await pipe.watch(key)
                if await pipe.get(key) != original:
                    await pipe.unwatch()
                    return False
                pipe.multi()
                pipe.set(key, value, ex=ttl)
                await pipe.execute()
                return True
            except WatchError:
                return False

    async def delete(self, key: str) -> None:
        await self._client.delete(key)

    async def ping(self) -> bool:
        return bool(await self._client.ping())

    async def close(self) -> None:
        await self._client.aclose()
