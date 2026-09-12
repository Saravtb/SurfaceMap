import os
import tempfile
import unittest

from surfacemap.modules import nmap_scan

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0" extrainfo="Ubuntu"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class TestNmapXmlParsing(unittest.TestCase):
    def _write_sample(self):
        fd, path = tempfile.mkstemp(suffix=".xml")
        with os.fdopen(fd, "w") as f:
            f.write(SAMPLE_XML)
        return path

    def test_only_open_ports_are_returned(self):
        path = self._write_sample()
        try:
            result = nmap_scan.parse_nmap_xml(path)
        finally:
            os.unlink(path)

        self.assertEqual(set(result.keys()), {80, 443})

    def test_service_details_are_extracted(self):
        path = self._write_sample()
        try:
            result = nmap_scan.parse_nmap_xml(path)
        finally:
            os.unlink(path)

        self.assertEqual(result[80]["service"], "http")
        self.assertEqual(result[80]["product"], "nginx")
        self.assertEqual(result[80]["version"], "1.18.0")
        self.assertEqual(result[443]["service"], "https")
        self.assertIsNone(result[443]["product"])

    def test_no_host_element_returns_empty(self):
        fd, path = tempfile.mkstemp(suffix=".xml")
        with os.fdopen(fd, "w") as f:
            f.write("<nmaprun></nmaprun>")
        try:
            result = nmap_scan.parse_nmap_xml(path)
        finally:
            os.unlink(path)
        self.assertEqual(result, {})

    def test_build_command_uses_port_spec_and_extra_args(self):
        cmd = nmap_scan.build_command("10.0.0.1", port_spec="80,443", extra_args="-sV -sC", output_path="/tmp/x.xml")
        self.assertIn("-sV", cmd)
        self.assertIn("-sC", cmd)
        self.assertIn("80,443", cmd)
        self.assertIn("10.0.0.1", cmd)

    def test_build_command_defaults_to_top_ports_when_no_spec(self):
        cmd = nmap_scan.build_command("10.0.0.1", output_path="/tmp/x.xml")
        self.assertIn("--top-ports", cmd)


if __name__ == "__main__":
    unittest.main()
