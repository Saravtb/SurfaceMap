"""DNS reconnaissance: record lookups and AXFR (zone transfer) testing."""
import socket

try:
    import dns.resolver
    import dns.zone
    import dns.query

    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]


def get_dns_records(domain: str, timeout: float = 5.0) -> dict:
    """Query common DNS record types for a domain."""
    records = {rtype: [] for rtype in RECORD_TYPES}

    if HAS_DNSPYTHON:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        for rtype in RECORD_TYPES:
            try:
                answers = resolver.resolve(domain, rtype)
                records[rtype] = sorted(str(r).strip('"') for r in answers)
            except Exception:
                records[rtype] = []
    else:
        try:
            records["A"] = sorted(set(socket.gethostbyname_ex(domain)[2]))
        except Exception:
            records["A"] = []

    return records


def attempt_zone_transfer(domain: str, timeout: float = 5.0) -> dict:
    """Attempt an AXFR zone transfer against each authoritative nameserver.

    A successful transfer indicates a serious misconfiguration and is
    reported as such; failures (the expected, correct behaviour) are
    reported without being treated as errors.
    """
    if not HAS_DNSPYTHON:
        return {"error": "dnspython not installed; skipping AXFR test"}

    result = {}
    try:
        ns_answers = dns.resolver.resolve(domain, "NS")
    except Exception as exc:
        return {"error": f"could not resolve NS records: {exc}"}

    for ns in ns_answers:
        ns_host = str(ns).rstrip(".")
        try:
            ns_ip = socket.gethostbyname(ns_host)
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=timeout))
            names = sorted(str(n) for n in zone.nodes.keys())
            result[ns_host] = {"vulnerable": True, "records": names}
        except Exception as exc:
            result[ns_host] = {"vulnerable": False, "detail": str(exc)}

    return result
