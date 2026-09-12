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
