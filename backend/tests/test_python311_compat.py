"""Regression coverage for the Gateway's declared Python 3.11 runtime."""

from app.core.engine import PrivacyEngine


def test_storage_original_collapses_escaped_windows_principal() -> None:
    assert PrivacyEngine._storage_original("USER", r"CORP\\svc-maint") == r"CORP\svc-maint"


def test_storage_original_preserves_windows_path() -> None:
    value = r"C:\Windows\System32\reg.exe"
    assert PrivacyEngine._storage_original("PATH", value) == value
