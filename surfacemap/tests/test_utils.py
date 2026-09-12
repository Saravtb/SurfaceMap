import unittest

from surfacemap import utils


class TestDomainValidation(unittest.TestCase):
    def test_valid_domains(self):
        for domain in ["example.com", "sub.example.com", "exemplo.com.br", "a-b.co"]:
            self.assertTrue(utils.is_valid_domain(domain), domain)

    def test_invalid_domains(self):
        for domain in ["", "not a domain", "-example.com", "example..com", "example"]:
            self.assertFalse(utils.is_valid_domain(domain), domain)

    def test_ip_detection(self):
        self.assertTrue(utils.is_ip_address("192.168.0.1"))
        self.assertTrue(utils.is_ip_address("::1"))
        self.assertFalse(utils.is_ip_address("example.com"))


if __name__ == "__main__":
    unittest.main()
