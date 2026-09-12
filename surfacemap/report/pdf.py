"""PDF export of the generated HTML report, via Playwright/Chromium - the
same optional dependency used by modules.screenshot for host screenshots.
"""
import os

from surfacemap.modules.screenshot import HAS_PLAYWRIGHT, is_available

if HAS_PLAYWRIGHT:
    from playwright.sync_api import sync_playwright

DEFAULT_MARGIN = {"top": "1.5cm", "bottom": "1.5cm", "left": "1.2cm", "right": "1.2cm"}


def export_html_to_pdf(html_path: str, pdf_path: str, timeout_ms: int = 30000) -> dict:
    """Renders `html_path` (a local file, with any relative assets such as
    screenshots/*.png sitting next to it) to `pdf_path` using headless
    Chromium. Returns {"path": pdf_path, "error": None} on success or
    {"path": None, "error": "..."} on failure.
    """
    if not is_available():
        raise RuntimeError(
            "playwright nao instalado. Rode: pip install playwright && "
            "playwright install chromium"
        )

    abs_html_path = os.path.abspath(html_path)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--no-sandbox"])
            try:
                page = browser.new_page()
                page.goto(f"file://{abs_html_path}", timeout=timeout_ms, wait_until="load")
                page.pdf(
                    path=pdf_path,
                    format="A4",
                    print_background=True,
                    margin=DEFAULT_MARGIN,
                )
                return {"path": pdf_path, "error": None}
            finally:
                browser.close()
    except Exception as exc:
        return {"path": None, "error": str(exc)}
