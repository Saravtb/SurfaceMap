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


class TestClassifyTarget(unittest.TestCase):
    def test_domain(self):
        self.assertEqual(utils.classify_target("example.com"), "domain")
        self.assertEqual(utils.classify_target("my-site.com"), "domain")

    def test_ip(self):
        self.assertEqual(utils.classify_target("192.168.1.10"), "ip")
        self.assertEqual(utils.classify_target("::1"), "ip")

    def test_cidr(self):
        self.assertEqual(utils.classify_target("192.168.1.0/24"), "cidr")

    def test_range(self):
        self.assertEqual(utils.classify_target("192.168.1.10-192.168.1.20"), "range")
        self.assertEqual(utils.classify_target("192.168.1.10-20"), "range")

    def test_invalid_cidr_raises(self):
        with self.assertRaises(ValueError):
            utils.classify_target("192.168.1.0/abc")

    def test_garbage_raises(self):
        with self.assertRaises(ValueError):
            utils.classify_target("not a valid target !!")


class TestExpandIpTargets(unittest.TestCase):
    def test_single_ip(self):
        self.assertEqual(list(utils.expand_ip_targets("10.0.0.5")), ["10.0.0.5"])

    def test_cidr_slash_30_excludes_network_and_broadcast(self):
        # /30 = 4 addresses, hosts() excludes network (.0) and broadcast (.3)
        result = list(utils.expand_ip_targets("10.0.0.0/30"))
        self.assertEqual(result, ["10.0.0.1", "10.0.0.2"])

    def test_cidr_slash_31_includes_both_addresses(self):
        result = list(utils.expand_ip_targets("10.0.0.0/31"))
        self.assertEqual(result, ["10.0.0.0", "10.0.0.1"])

    def test_full_range(self):
        result = list(utils.expand_ip_targets("10.0.0.1-10.0.0.4"))
        self.assertEqual(result, ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"])

    def test_shorthand_last_octet_range(self):
        result = list(utils.expand_ip_targets("10.0.0.250-253"))
        self.assertEqual(result, ["10.0.0.250", "10.0.0.251", "10.0.0.252", "10.0.0.253"])

    def test_shorthand_octet_out_of_bounds_raises(self):
        with self.assertRaises(ValueError):
            list(utils.expand_ip_targets("10.0.0.1-999"))

    def test_reversed_range_raises(self):
        with self.assertRaises(ValueError):
            list(utils.expand_ip_targets("10.0.0.10-10.0.0.1"))

    def test_large_cidr_is_lazy(self):
        # A /8 has millions of addresses; consuming only the first few via
        # itertools.islice-style iteration must not hang or blow up memory.
        gen = utils.expand_ip_targets("10.0.0.0/8")
        first_three = [next(gen) for _ in range(3)]
        self.assertEqual(first_three, ["10.0.0.1", "10.0.0.2", "10.0.0.3"])


if __name__ == "__main__":
    unittest.main()
