"""Subdomain enumeration: passive (certificate transparency) and active (DNS brute force)."""
import concurrent.futures
import json
import socket
import urllib.error
import urllib.request

USER_AGENT = "Mozilla/5.0 (compatible; surfacemap-recon-tool)"


def passive_crtsh(domain: str, timeout: float = 15.0):
    """Query crt.sh certificate transparency logs for known subdomains."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
        data = json.loads(raw)
        for entry in data:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name.endswith(domain.lower()):
                    subdomains.add(name)
        return sorted(subdomains), None
    except Exception as exc:
        return sorted(subdomains), str(exc)


def _resolve(host: str):
    try:
        ip = socket.gethostbyname(host)
        return host, ip
    except socket.gaierror:
        return host, None


def brute_force(domain: str, wordlist_path: str, threads: int = 20) -> dict:
    """Resolve candidate subdomains built from a wordlist against the domain."""
    found = {}
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        words = [w.strip() for w in f if w.strip() and not w.startswith("#")]

    candidates = [f"{w}.{domain}" for w in words]
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        for host, ip in executor.map(_resolve, candidates):
            if ip:
                found[host] = ip
    return found


def enumerate_subdomains(
    domain: str,
    wordlist_path: str = None,
    threads: int = 20,
    passive: bool = True,
    active: bool = True,
) -> dict:
    result = {"passive": [], "active": {}, "errors": []}

    if passive:
        subs, err = passive_crtsh(domain)
        result["passive"] = subs
        if err:
            result["errors"].append(f"crt.sh: {err}")

    if active and wordlist_path:
        result["active"] = brute_force(domain, wordlist_path, threads=threads)

    return result
