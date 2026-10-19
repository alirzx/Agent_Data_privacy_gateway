"""Authenticated encryption and key separation. Key material never reaches the HTTP response."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))


class Crypto:
    def __init__(self, master_key: bytes) -> None:
        if len(master_key) != 32:
            raise ValueError("Master key must contain 32 random bytes")
        self._master_key = master_key

    def derive(self, label: str) -> bytes:
        return hmac.new(self._master_key, ("soorin-dlp-v1:" + label).encode(), hashlib.sha256).digest()

    def encrypt_root(self, context_id: str, value: dict) -> bytes:
        plain = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        nonce = os.urandom(12)
        cipher = AESGCM(self.derive("root-encryption")).encrypt(nonce, plain, f"root:{context_id}".encode())
        return nonce + cipher

    def decrypt_root(self, context_id: str, ciphertext: bytes) -> dict:
        plain = AESGCM(self.derive("root-encryption")).decrypt(ciphertext[:12], ciphertext[12:], f"root:{context_id}".encode())
        result = json.loads(plain)
        if result.get("context_id") != context_id:
            raise ValueError("Context binding mismatch")
        return result

    def wrap_dek(self, context_id: str, dek: bytes) -> str:
        nonce = os.urandom(12)
        ct = AESGCM(self.derive("key-encryption")).encrypt(nonce, dek, f"dek:{context_id}".encode())
        return _b64(nonce + ct)

    def unwrap_dek(self, context_id: str, wrapped: str) -> bytes:
        blob = _unb64(wrapped)
        return AESGCM(self.derive("key-encryption")).decrypt(blob[:12], blob[12:], f"dek:{context_id}".encode())

    @staticmethod
    def encrypt_original(dek: bytes, context_id: str, token: str, original: str) -> str:
        nonce = os.urandom(12)
        ciphertext = AESGCM(dek).encrypt(nonce, original.encode(), f"entry:{context_id}:{token}".encode())
        return _b64(nonce + ciphertext)

    @staticmethod
    def decrypt_original(dek: bytes, context_id: str, token: str, blob: str) -> str:
        value = _unb64(blob)
        return AESGCM(dek).decrypt(value[:12], value[12:], f"entry:{context_id}:{token}".encode()).decode()
