import os
import tempfile
import unittest

from surfacemap.modules import screenshot


class TestScreenshotAvailability(unittest.TestCase):
    def test_is_available_returns_bool(self):
        self.assertIsInstance(screenshot.is_available(), bool)


@unittest.skipUnless(screenshot.is_available(), "playwright nao instalado neste ambiente")
class TestScreenshotCapture(unittest.TestCase):
    def test_capture_local_html_file(self):
        fd, html_path = tempfile.mkstemp(suffix=".html")
        with os.fdopen(fd, "w") as f:
            f.write("<html><body style='background:red'><h1>surfacemap test</h1></body></html>")

        fd2, png_path = tempfile.mkstemp(suffix=".png")
        os.close(fd2)

        try:
            with screenshot.ScreenshotSession(timeout_ms=5000) as session:
                result = session.capture(f"file://{html_path}", png_path)
            self.assertIsNone(result["error"])
            self.assertTrue(os.path.exists(png_path))
            self.assertGreater(os.path.getsize(png_path), 0)
        finally:
            os.unlink(html_path)
            if os.path.exists(png_path):
                os.unlink(png_path)

    def test_capture_reports_error_for_unreachable_url(self):
        fd, png_path = tempfile.mkstemp(suffix=".png")
        os.close(fd)
        os.unlink(png_path)

        try:
            with screenshot.ScreenshotSession(timeout_ms=2000) as session:
                result = session.capture("http://127.0.0.1:1", png_path)
            self.assertIsNotNone(result["error"])
            self.assertFalse(os.path.exists(png_path))
        finally:
            if os.path.exists(png_path):
                os.unlink(png_path)


if __name__ == "__main__":
    unittest.main()
