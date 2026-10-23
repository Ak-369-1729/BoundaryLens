"""Optional browser smoke test: the built dashboard renders and talks to the backend.

Skipped automatically unless BL_BROWSER_SMOKE=1 and a running backend is reachable at
BL_SMOKE_URL (default http://127.0.0.1:8080) with the frontend built. Playwright and its
Chromium are required (PLAYWRIGHT_BROWSERS_PATH points at the preinstalled browser here).
"""

import os

import pytest

URL = os.environ.get("BL_SMOKE_URL", "http://127.0.0.1:8080")

pytestmark = pytest.mark.skipif(
    os.environ.get("BL_BROWSER_SMOKE") != "1",
    reason="set BL_BROWSER_SMOKE=1 with a running backend to enable the browser smoke test",
)


def _launch(p):
    """Use the preinstalled Chromium if its version differs from the pip package's default."""
    import glob
    exe = os.environ.get("BL_CHROMIUM_PATH")
    if not exe:
        matches = sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome"))
        exe = matches[-1] if matches else None
    kwargs = {"executable_path": exe} if exe and os.path.exists(exe) else {}
    return p.chromium.launch(**kwargs)


def test_dashboard_renders_overview():
    pw = pytest.importorskip("playwright.sync_api")
    with pw.sync_playwright() as p:
        browser = _launch(p)
        page = browser.new_page()
        page.goto(URL, wait_until="networkidle")
        # The sidebar brand and the Overview heading must render.
        assert page.inner_text("body").strip() != ""
        page.wait_for_selector("text=BoundaryLens")
        page.wait_for_selector("text=Overview")
        # Configured identities from the API are rendered in the overview.
        page.wait_for_selector("text=alice")
        browser.close()
