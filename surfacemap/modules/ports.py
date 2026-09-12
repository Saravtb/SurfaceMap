"""TCP connect port scanning."""
import concurrent.futures
import socket

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    465, 587, 993, 995, 1433, 1521, 1723, 2049, 3268, 3306, 3389,
    5432, 5900, 5985, 5986, 6379, 8000, 8080, 8443, 8888, 9000,
    9090, 9200, 11211, 27017,
]


def scan_port(ip: str, port: int, timeout: float = 1.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) == 0:
                try:
                    service = socket.getservbyport(port, "tcp")
                except OSError:
                    service = "unknown"
                return port, service
    except Exception:
        pass
    return None


def scan_ports(ip: str, ports=None, threads: int = 50, timeout: float = 1.5) -> dict:
    """TCP connect scan. Returns {port: {service, product, version, extrainfo}}.

    product/version/extrainfo are always None here (no banner grabbing) -
    the schema matches modules.nmap_scan.scan_ports so callers and report
    templates can treat either backend the same way.
    """
    ports = ports or TOP_PORTS
    open_ports = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(scan_port, ip, p, timeout) for p in ports]
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                port, service = res
                open_ports[port] = {
                    "service": service,
                    "product": None,
                    "version": None,
                    "extrainfo": None,
                }
    return dict(sorted(open_ports.items()))


def parse_port_range(spec: str):
    """Parse '1-1024', '80,443,8080', or a mix into a sorted list of ports."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)
