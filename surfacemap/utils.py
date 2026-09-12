import concurrent.futures
import ipaddress
import json
import re
import socket

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def is_valid_domain(value: str) -> bool:
    return bool(DOMAIN_RE.match(value))


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def resolve_ip(host: str):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def resolve_ptr(ip: str, timeout: float = 3.0):
    """Reverse DNS lookup, bounded by `timeout` (socket has no native
    per-call timeout for gethostbyaddr, so it runs in a worker thread)."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(socket.gethostbyaddr, ip)
        try:
            hostname, _, _ = future.result(timeout=timeout)
            return hostname
        except Exception:
            return None


def classify_target(spec: str) -> str:
    """Classify a CLI target as 'domain', 'ip', 'cidr' or 'range'.

    Raises ValueError if the spec doesn't match any supported shape.
    """
    spec = spec.strip()
    if not spec:
        raise ValueError("alvo vazio")

    if "/" in spec:
        try:
            ipaddress.ip_network(spec, strict=False)
            return "cidr"
        except ValueError:
            raise ValueError(f"'{spec}' contem '/' mas nao e um bloco CIDR valido")

    if "-" in spec:
        left = spec.split("-", 1)[0].strip()
        if is_ip_address(left):
            # Full validation (and any malformed-range errors) happens
            # lazily in expand_ip_targets; this only disambiguates from
            # domains that happen to contain a hyphen (e.g. "my-site.com").
            return "range"

    if is_ip_address(spec):
        return "ip"

    if is_valid_domain(spec):
        return "domain"

    raise ValueError(f"'{spec}' nao e um dominio, endereco IP, bloco CIDR ou range de IPs valido")


def expand_ip_targets(spec: str):
    """Lazily yield IP address strings for a single IP, CIDR block, or range.

    Supports:
      - a single IP: "192.168.1.10"
      - CIDR notation: "192.168.1.0/24" (network/broadcast excluded unless
        the block has 1 or 2 addresses, i.e. /31 or /32)
      - full range: "192.168.1.10-192.168.1.20"
      - shorthand last-octet range: "192.168.1.10-20"

    Uses a generator so huge blocks (e.g. /8) don't get materialized in
    memory - callers should cap consumption (e.g. itertools.islice).
    """
    spec = spec.strip()

    if "/" in spec:
        network = ipaddress.ip_network(spec, strict=False)
        addresses = network if network.num_addresses <= 2 else network.hosts()
        for addr in addresses:
            yield str(addr)
        return

    if "-" in spec:
        start_str, _, end_str = spec.partition("-")
        start_str = start_str.strip()
        end_str = end_str.strip()

        try:
            start_ip = ipaddress.ip_address(start_str)
        except ValueError:
            raise ValueError(f"IP invalido no inicio do range: '{start_str}'")

        if "." in end_str or ":" in end_str:
            try:
                end_ip = ipaddress.ip_address(end_str)
            except ValueError:
                raise ValueError(f"IP invalido no fim do range: '{end_str}'")
        else:
            if start_ip.version != 4:
                raise ValueError("Range abreviado (ultimo octeto) so e suportado para IPv4")
            try:
                last_octet = int(end_str)
            except ValueError:
                raise ValueError(f"Range invalido: '{spec}'")
            if not (0 <= last_octet <= 255):
                raise ValueError(f"Ultimo octeto fora do intervalo 0-255: '{end_str}'")
            octets = start_str.split(".")
            octets[-1] = str(last_octet)
            end_ip = ipaddress.ip_address(".".join(octets))

        if int(end_ip) < int(start_ip):
            raise ValueError(f"Fim do range e menor que o inicio: '{spec}'")

        current, end_int = int(start_ip), int(end_ip)
        while current <= end_int:
            yield str(ipaddress.ip_address(current))
            current += 1
        return

    ipaddress.ip_address(spec)  # raises ValueError if not a plain IP
    yield spec


def save_json(data, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


def banner() -> str:
    return r"""
  ____             __                 __  ___
 / __/_ ____ _____/ /__ _______ __  /  |/  /__ ____
_\ \/ // / __/ _ / _ / __/ -_) //  / /|_/ / _ `/ _ \
/___/\_,_/_/  \_,_/_//_/\__/\_,_/ /_/  /_/\_,_/ .__/
                                             /_/
        Attack Surface Mapping for Pentesting
"""


LEGAL_WARNING = """
AVISO LEGAL / LEGAL WARNING
----------------------------------------------------------------------
Esta ferramenta realiza varredura ativa de rede (portas, subdominios,
diretorios web). Utilize-a APENAS contra alvos para os quais voce
possui autorizacao explicita e por escrito (contrato de pentest,
bug bounty com escopo definido, ou ativos proprios).

O uso nao autorizado de ferramentas de varredura contra sistemas de
terceiros pode configurar crime (ex.: Lei 12.737/2012 no Brasil,
Computer Fraud and Abuse Act nos EUA, entre outras legislacoes) e
violar termos de servico.

Ao continuar, voce declara que possui autorizacao para testar o alvo
informado e assume total responsabilidade pelo uso desta ferramenta.
----------------------------------------------------------------------
"""
