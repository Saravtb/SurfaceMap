"""HTTP/HTTPS probing: status, headers, title and lightweight tech fingerprinting."""
import re
import ssl
import urllib.error
import urllib.request

USER_AGENT = "Mozilla/5.0 (compatible; surfacemap-recon-tool)"

FINGERPRINTS = {
    "WordPress": [r"wp-content", r"wp-includes"],
    "Drupal": [r"Drupal\.settings", r"/sites/default/"],
    "Joomla": [r"/media/jui/", r"Joomla!"],
    "Nginx": [r"nginx"],
    "Apache": [r"Apache"],
    "IIS": [r"Microsoft-IIS"],
    "React": [r"__NEXT_DATA__|react-dom|data-reactroot"],
    "Angular": [r"ng-version"],
    "Vue.js": [r"data-v-app|__vue__"],
    "Laravel": [r"laravel_session|XSRF-TOKEN"],
    "Express": [r"Express"],
    "PHP": [r"X-Powered-By:\s*PHP"],
    "ASP.NET": [r"X-AspNet-Version|ASP\.NET"],
}

SENSITIVE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "Via", "X-Generator"]


def _build_ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def probe_url(url: str, timeout: float = 8.0) -> dict:
    info = {
        "url": url,
        "status": None,
        "headers": {},
        "interesting_headers": {},
        "title": None,
        "server": None,
        "technologies": [],
        "error": None,
    }
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout, context=_build_ssl_context()) as resp:
            info["status"] = resp.status
            info["headers"] = dict(resp.getheaders())
            body = resp.read(200_000).decode("utf-8", errors="ignore")
            _fill_from_response(info, body)
    except urllib.error.HTTPError as exc:
        info["status"] = exc.code
        info["headers"] = dict(exc.headers) if exc.headers else {}
        try:
            body = exc.read(200_000).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        _fill_from_response(info, body)
        info["error"] = f"HTTP {exc.code}"
    except Exception as exc:
        info["error"] = str(exc)

    return info


def _fill_from_response(info: dict, body: str):
    info["server"] = info["headers"].get("Server")
    info["interesting_headers"] = {
        h: info["headers"][h] for h in SENSITIVE_HEADERS if h in info["headers"]
    }

    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if title_match:
        info["title"] = re.sub(r"\s+", " ", title_match.group(1)).strip()[:200]

    haystack = body + " ".join(f"{k}: {v}" for k, v in info["headers"].items())
    techs = []
    for tech, patterns in FINGERPRINTS.items():
        if any(re.search(p, haystack, re.IGNORECASE) for p in patterns):
            techs.append(tech)
    info["technologies"] = techs


def probe_host(host: str, timeout: float = 8.0) -> dict:
    return {
        "https": probe_url(f"https://{host}", timeout=timeout),
        "http": probe_url(f"http://{host}", timeout=timeout),
    }
