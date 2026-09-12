"""WHOIS lookup: prefers the system `whois` binary, falls back to a raw socket query."""
import shutil
import socket
import subprocess


def whois_via_socket(domain: str, server: str = "whois.iana.org", timeout: float = 10.0) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((server, 43))
            sock.send((domain + "\r\n").encode())
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        return response.decode("utf-8", errors="ignore")
    except Exception as exc:
        return f"error querying {server}: {exc}"


def get_whois(domain: str, timeout: float = 10.0) -> str:
    if shutil.which("whois"):
        try:
            proc = subprocess.run(
                ["whois", domain], capture_output=True, timeout=timeout, text=True
            )
            return proc.stdout or proc.stderr
        except Exception as exc:
            return f"error running whois command: {exc}"

    # Fallback: ask IANA which registry is authoritative, then query it.
    iana_resp = whois_via_socket(domain, timeout=timeout)
    referred_server = None
    for line in iana_resp.splitlines():
        if line.lower().startswith("refer:"):
            referred_server = line.split(":", 1)[1].strip()
            break

    if referred_server:
        return whois_via_socket(domain, server=referred_server, timeout=timeout)
    return iana_resp
