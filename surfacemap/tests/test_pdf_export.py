import os
import tempfile
import unittest

from surfacemap.modules.screenshot import is_available
from surfacemap.report import pdf


class TestPdfExportAvailability(unittest.TestCase):
    def test_is_available_returns_bool(self):
        self.assertIsInstance(pdf.is_available(), bool)


@unittest.skipUnless(is_available(), "playwright nao instalado neste ambiente")
class TestPdfExportCapture(unittest.TestCase):
    def test_export_html_to_pdf_produces_valid_pdf(self):
        fd, html_path = tempfile.mkstemp(suffix=".html")
        with os.fdopen(fd, "w") as f:
            f.write("<html><body><h1>Relatorio de teste</h1><p>conteudo</p></body></html>")

        fd2, pdf_path = tempfile.mkstemp(suffix=".pdf")
        os.close(fd2)

        try:
            result = pdf.export_html_to_pdf(html_path, pdf_path)
            self.assertIsNone(result["error"])
            self.assertTrue(os.path.exists(pdf_path))
            with open(pdf_path, "rb") as f:
                header = f.read(5)
            self.assertEqual(header, b"%PDF-")
            self.assertGreater(os.path.getsize(pdf_path), 0)
        finally:
            os.unlink(html_path)
            if os.path.exists(pdf_path):
                os.unlink(pdf_path)

    def test_export_reports_error_for_missing_html(self):
        fd, pdf_path = tempfile.mkstemp(suffix=".pdf")
        os.close(fd)
        os.unlink(pdf_path)

        try:
            result = pdf.export_html_to_pdf("/nonexistent/path/report.html", pdf_path)
            self.assertIsNotNone(result["error"])
            self.assertFalse(os.path.exists(pdf_path))
        finally:
            if os.path.exists(pdf_path):
                os.unlink(pdf_path)


if __name__ == "__main__":
    unittest.main()
