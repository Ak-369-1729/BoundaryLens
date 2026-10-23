import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scanner"))
sys.path.insert(0, str(ROOT / "demo_app"))

# Deterministic local demo credentials for the test run.
os.environ.setdefault("BL_ALICE_PASSWORD", "alice-local-demo")
os.environ.setdefault("BL_BOB_PASSWORD", "bob-local-demo")
os.environ.setdefault("BL_ADMIN_PASSWORD", "admin-local-demo")
os.environ.setdefault("LEDGERLY_ALICE_PASSWORD", "alice-local-demo")
os.environ.setdefault("LEDGERLY_BOB_PASSWORD", "bob-local-demo")
os.environ.setdefault("LEDGERLY_ADMIN_PASSWORD", "admin-local-demo")


@pytest.fixture
def manifest():
    from boundarylens.manifest import load_manifest
    return load_manifest(ROOT / "manifests" / "ledgerly.yaml")
