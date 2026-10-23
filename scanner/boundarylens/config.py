"""Runtime configuration from environment variables. Local demo defaults only."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass
class Settings:
    manifest_path: str = os.environ.get("BL_MANIFEST", str(REPO_ROOT / "manifests" / "ledgerly.yaml"))
    database_url: str = os.environ.get("BL_DATABASE_URL", "sqlite:///" + str(REPO_ROOT / "boundarylens.db"))
    host: str = os.environ.get("BL_HOST", "127.0.0.1")
    port: int = int(os.environ.get("BL_PORT", "8080"))
    frontend_dist: str = os.environ.get("BL_FRONTEND_DIST", str(REPO_ROOT / "frontend" / "dist"))
    allowed_hosts: set[str] = field(default_factory=lambda: {
        h.strip().lower() for h in os.environ.get("BL_ALLOWED_HOSTS", "").split(",") if h.strip()})
    require_ack: bool = os.environ.get("BL_REQUIRE_ACK", "true").lower() == "true"


def load_settings() -> Settings:
    return Settings()
