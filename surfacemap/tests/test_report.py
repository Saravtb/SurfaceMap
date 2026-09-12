import unittest

from surfacemap.report import builder


SAMPLE_DATA = {
    "target": "example.com",
    "started_at": "2026-01-01T00:00:00+00:00",
    "finished_at": "2026-01-01T00:05:00+00:00",
    "dns": {"A": ["93.184.216.34"], "MX": [], "NS": ["ns1.example.com"]},
    "zone_transfer": {"ns1.example.com": {"vulnerable": False, "detail": "refused"}},
    "whois": "Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar",
    "subdomains": {"passive": ["www.example.com"], "active": {"www.example.com": "93.184.216.34"}},
    "hosts": {
        "example.com": {
            "ip": "93.184.216.34",
            "port_scanner": "builtin",
            "ports": {
                80: {"service": "http", "product": None, "version": None, "extrainfo": None},
                443: {"service": "https", "product": "nginx", "version": "1.18.0", "extrainfo": None},
            },
            "http": {
                "https": {
                    "url": "https://example.com",
                    "status": 200,
                    "server": "nginx",
                    "title": "Example Domain",
                    "technologies": ["Nginx"],
                },
                "http": {"url": "http://example.com", "status": None, "error": "timeout"},
            },
            "dir_enum": [{"path": "robots.txt", "status": 200, "url": "https://example.com/robots.txt"}],
        }
    },
}


class TestReportBuilder(unittest.TestCase):
    def test_markdown_contains_key_sections(self):
        md = builder.to_markdown(SAMPLE_DATA)
        self.assertIn("example.com", md)
        self.assertIn("Registros DNS", md)
        self.assertIn("Subdominios", md)
        self.assertIn("robots.txt", md)

    def test_html_is_well_formed_and_escaped(self):
        out = builder.to_html(SAMPLE_DATA)
        self.assertIn("<html", out)
        self.assertIn("example.com", out)
        self.assertIn("Nginx", out)

    def test_save_all_reports(self):
        import tempfile
        import os

        with tempfile.TemporaryDirectory() as tmp:
            paths = builder.save_all_reports(SAMPLE_DATA, tmp)
            for path in paths.values():
                self.assertTrue(os.path.exists(path))


if __name__ == "__main__":
    unittest.main()
