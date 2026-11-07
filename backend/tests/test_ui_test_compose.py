"""Ensure the permanent loopback UI demo cannot join production networks."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_ui_compose_isolated_from_production():
    compose = yaml.safe_load((ROOT / "docker-compose.ui-test.yml").read_text())
    assert set(compose["services"]) == {"privacy-ui-test"}
    ui = compose["services"]["privacy-ui-test"]
    assert ui["image"] == "soorin-privacy-v2-privacy-api:latest"
    assert ui["env_file"] == ".env.ui-test"
    assert ui["ports"] == ["127.0.0.1:18484:8484"]
    assert ui["restart"] == "unless-stopped"
    assert ui["read_only"] is True
    assert ui["cap_drop"] == ["ALL"]
    assert ui["security_opt"] == ["no-new-privileges:true"]
    assert "--workers" in ui["command"]
    assert ui["command"][ui["command"].index("--workers") + 1] == "1"
    assert "networks" not in ui
    assert "volumes" not in ui
    assert "depends_on" not in ui
    assert "DLP_MASTER_KEY_B64" not in (ROOT / "docker-compose.ui-test.yml").read_text()
    assert ".env.ui-test" in (ROOT / ".gitignore").read_text()


def test_ui_env_provisioner_refuses_overwrite():
    source = (ROOT / "ops/init_ui_test_env.py").read_text()
    assert "TARGET.exists() or TARGET.is_symlink()" in source
    assert "os.O_EXCL" in source
    assert "0o600" in source
    assert '"DLP_STORE_BACKEND": "memory"' in source
    assert '"DLP_CLIENTS_JSON": "[]"' in source
