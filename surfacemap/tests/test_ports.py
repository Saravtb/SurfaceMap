import unittest

from surfacemap.modules import ports


class TestPortRangeParsing(unittest.TestCase):
    def test_range(self):
        self.assertEqual(ports.parse_port_range("1-5"), [1, 2, 3, 4, 5])

    def test_list(self):
        self.assertEqual(ports.parse_port_range("80,443,22"), [22, 80, 443])

    def test_mixed(self):
        self.assertEqual(ports.parse_port_range("22,80-82"), [22, 80, 81, 82])

    def test_dedup(self):
        self.assertEqual(ports.parse_port_range("80,80,80-81"), [80, 81])


if __name__ == "__main__":
    unittest.main()
