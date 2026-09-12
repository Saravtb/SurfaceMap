"""Screenshot capture for discovered web hosts, via Playwright (optional
dependency; the rest of the tool works fine without it).
"""
try:
    from playwright.sync_api import sync_playwright

    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

DEFAULT_TIMEOUT_MS = 15000
DEFAULT_VIEWPORT = {"width": 1280, "height": 800}


def is_available() -> bool:
    return HAS_PLAYWRIGHT


class ScreenshotSession:
    """Launches one browser instance and reuses it across many captures,
    since starting Chromium per host would be far too slow.
    """

    def __init__(self, timeout_ms: int = DEFAULT_TIMEOUT_MS, viewport: dict = None):
        if not HAS_PLAYWRIGHT:
            raise RuntimeError(
                "playwright nao instalado. Rode: pip install playwright && "
                "playwright install chromium"
            )
        self.timeout_ms = timeout_ms
        self.viewport = viewport or DEFAULT_VIEWPORT
        self._playwright = None
        self._browser = None

    def __enter__(self):
        self._playwright = sync_playwright().start()
        try:
            self._browser = self._playwright.chromium.launch(
                args=["--ignore-certificate-errors", "--no-sandbox"]
            )
        except Exception:
            self._playwright.stop()
            self._playwright = None
            raise
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._browser:
            self._browser.close()
        if self._playwright:
            self._playwright.stop()

    def capture(self, url: str, output_path: str) -> dict:
        page = self._browser.new_page(viewport=self.viewport, ignore_https_errors=True)
        try:
            page.goto(url, timeout=self.timeout_ms, wait_until="load")
            page.screenshot(path=output_path, full_page=False)
            return {"path": output_path, "error": None}
        except Exception as exc:
            return {"path": None, "error": str(exc)}
        finally:
            page.close()
