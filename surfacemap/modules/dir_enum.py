"""Lightweight content discovery: probes a wordlist of common paths against a base URL."""
import concurrent.futures
import ssl
import urllib.error
import urllib.request

USER_AGENT = "Mozilla/5.0 (compatible; surfacemap-recon-tool)"


def _build_ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def check_path(base_url: str, path: str, timeout: float = 6.0):
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout, context=_build_ssl_context()) as resp:
            return {"path": path, "status": resp.status, "url": url}
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            return {"path": path, "status": exc.code, "url": url}
    except Exception:
        pass
    return None


def enumerate_paths(base_url: str, wordlist_path: str, threads: int = 20, timeout: float = 6.0):
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        paths = [p.strip() for p in f if p.strip() and not p.startswith("#")]

    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(check_path, base_url, p, timeout) for p in paths]
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                found.append(res)

    return sorted(found, key=lambda x: x["path"])
