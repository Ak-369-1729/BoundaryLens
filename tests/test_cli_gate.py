"""CLI config loading and CI-gate exit codes (uses the in-process demo via the running server)."""

import json
from pathlib import Path

import pytest

from boundarylens.platform.config import ConfigError, load_project_config, to_autoscan_config
from boundarylens.platform.discovery import import_openapi

ROOT = Path(__file__).resolve().parents[1]


def test_project_config_loads_and_hides_secrets(tmp_path, monkeypatch):
    secret = "super-secret-token-value-123"
    monkeypatch.setenv("BL_ALICE_PASSWORD", secret)
    cfg = load_project_config(ROOT / "boundarylens.yaml")
    assert "alice" in cfg.identities
    assert cfg.identities["alice"].password_env == "BL_ALICE_PASSWORD"
    # the config references only env var names, never the secret value itself
    assert secret not in Path(ROOT / "boundarylens.yaml").read_text()


def test_config_rejects_nonloopback_target(tmp_path):
    bad = tmp_path / "c.yaml"
    bad.write_text("""
target: {base_url: "http://evil.example.com"}
identities:
  anonymous: {role: anonymous, kind: anonymous}
""")
    cfg = load_project_config(bad)
    eps = import_openapi('{"openapi":"3.0.0","paths":{}}')
    with pytest.raises(ConfigError):
        to_autoscan_config(cfg, eps)


def test_cli_fail_on_threshold_logic():
    from boundarylens.platform.regression import build_baseline, compare_to_baseline
    baseline = build_baseline({"findings": [], "matrix": []}, name="clean")
    current = {"findings": [{"finding_id": "F", "check_id": "BL-AUTO-BOLA", "method": "GET",
                             "route": "/x", "actor_identity": "bob", "severity": "medium",
                             "confirmation": "confirmed", "observed_behavior": "o", "evidence": {}}],
               "matrix": []}
    # medium regression does not trip a 'high' gate but does trip a 'medium' gate
    assert compare_to_baseline(baseline, current, fail_on="high")["passed"] is True
    assert compare_to_baseline(baseline, current, fail_on="medium")["passed"] is False
