"""Optional port scanning backend that shells out to nmap for service/version
detection. Falls back are the caller's responsibility (see cli.py) when nmap
is not installed or the scan fails.
"""
import os
import shlex
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET

DEFAULT_EXTRA_ARGS = "-sV"
DEFAULT_TOP_PORTS = 100


def is_available() -> bool:
    return shutil.which("nmap") is not None


def build_command(ip: str, port_spec: str = None, extra_args: str = None, output_path: str = None):
    cmd = ["nmap", "-Pn", "--open"]
    if extra_args:
        cmd += shlex.split(extra_args)
    if port_spec:
        cmd += ["-p", port_spec]
    else:
        cmd += ["--top-ports", str(DEFAULT_TOP_PORTS)]
    cmd += ["-oX", output_path, ip]
    return cmd


def parse_nmap_xml(xml_path: str) -> dict:
    open_ports = {}
    tree = ET.parse(xml_path)
    root = tree.getroot()

    host = root.find("host")
    if host is None:
        return open_ports

    ports_el = host.find("ports")
    if ports_el is None:
        return open_ports

    for port_el in ports_el.findall("port"):
        state_el = port_el.find("state")
        if state_el is None or state_el.get("state") != "open":
            continue

        portid = int(port_el.get("portid"))
        service_el = port_el.find("service")
        if service_el is not None:
            service = service_el.get("name") or "unknown"
            product = service_el.get("product")
            version = service_el.get("version")
            extrainfo = service_el.get("extrainfo")
        else:
            service, product, version, extrainfo = "unknown", None, None, None

        open_ports[portid] = {
            "service": service,
            "product": product,
            "version": version,
            "extrainfo": extrainfo,
        }

    return dict(sorted(open_ports.items()))


def scan_ports(ip: str, port_spec: str = None, extra_args: str = DEFAULT_EXTRA_ARGS, timeout: float = 300) -> dict:
    """Run nmap against `ip` and return the same {port: {...}} shape as
    modules.ports.scan_ports. Raises RuntimeError if nmap is missing, times
    out, or fails to produce output.
    """
    if not is_available():
        raise RuntimeError("nmap nao encontrado no PATH")

    fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="surfacemap-nmap-")
    os.close(fd)

    try:
        cmd = build_command(ip, port_spec=port_spec, extra_args=extra_args, output_path=xml_path)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"nmap excedeu o timeout de {timeout}s") from exc
        except FileNotFoundError as exc:
            raise RuntimeError("nmap nao encontrado no PATH") from exc

        if not os.path.exists(xml_path) or os.path.getsize(xml_path) == 0:
            stderr = proc.stderr.strip() if proc.stderr else f"codigo de saida {proc.returncode}"
            raise RuntimeError(f"nmap nao produziu saida: {stderr}")

        try:
            return parse_nmap_xml(xml_path)
        except ET.ParseError as exc:
            raise RuntimeError(f"falha ao interpretar saida XML do nmap: {exc}") from exc
    finally:
        if os.path.exists(xml_path):
            os.unlink(xml_path)
