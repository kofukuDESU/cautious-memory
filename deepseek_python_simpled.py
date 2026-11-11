#!/usr/bin/env python3
"""
Proxy config pipeline.

Steps:
  1 = Fetch / custom file (source)
  2 = Endpoint Test
  3 = Enrich (Gemini + Geo + Reddit, no filtering)

Outputs (Plain text in ./ALIVE/):
  ALIVE/all.txt       → deduplicated source configs
  ALIVE/working.txt   → configs that passed the endpoint test
  ALIVE/enriched.txt  → every working config annotated with
                        {flag}-{CC}-{GEMINI|NOGEMINI}-{REDDIT|NOREDDIT}
"""

import argparse
import base64
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from datetime import datetime
from html import unescape
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse

import requests

# ---------------------------------------------------------------- config
SCRIPT_DIR = Path(__file__).resolve().parent
LINKS_FILE = SCRIPT_DIR / "sub_links.txt"
ALIVE_DIR = Path("ALIVE")
LOG_DIR = Path("logs")

FETCH_TIMEOUT_SECONDS = 5
RETRY_COUNT = 5

PROXIES = None
HEADERS = {"User-Agent": "Mozilla/5.0"}

XRAY_BINARY = "xray"
TEST_ENDPOINTS = [
    "https://cp.cloudflare.com",
    "https://www.gstatic.com",
    "https://captive.apple.com",
]
TEST_TIMEOUT = 1
TEST_WORKERS = 50

# ---- Gemini check ----
GEMINI_TEST_URL = "https://gemini.google.com/"
GEMINI_TIMEOUT = 5
GEMINI_BLOCKED_MARKER = "Gemini isn't currently supported in your country. Stay tuned!"

# ---- Reddit check ----
REDDIT_TEST_URL = "https://www.reddit.com/"
REDDIT_TIMEOUT = (5, 8)
REDDIT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}
REDDIT_MAX_CONCURRENT = 3
REDDIT_MIN_INTERVAL_SECONDS = 0.5
REDDIT_BODY_PREVIEW_CHARS = 350
REDDIT_BLOCKED_MARKERS = (
    "you've been blocked by network security",
    "you have been blocked by network security",
    "blocked by network security",
    "if you think you've been blocked by mistake",
)

# ---- Geo check ----
GEO_ENRICH_URL = "http://ip-api.com/line/?fields=status,countryCode"
GEO_TIMEOUT = 5

CONFIG_RE = re.compile(
    r"(?:vmess|vless|trojan|ssr|ss|hysteria2|hysteria|hy2|tuic|wireguard|wg)://[^\s\"'<>`]+",
    re.IGNORECASE,
)

STEP_SOURCE   = 1
STEP_ENDPOINT = 2
STEP_ENRICH   = 3

IS_TTY = sys.stdout.isatty()

# Reddit rate-limiting primitives
_REDDIT_SEMAPHORE = threading.BoundedSemaphore(REDDIT_MAX_CONCURRENT)
_REDDIT_RATE_LOCK = threading.Lock()
_REDDIT_LAST_REQUEST_START = 0.0


# ---------------------------------------------------------------- helpers
def ensure_dirs() -> None:
    ALIVE_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def load_urls() -> list[str]:
    if not LINKS_FILE.exists():
        raise FileNotFoundError(f"Links file not found: {LINKS_FILE}")
    urls: list[str] = []
    seen: set[str] = set()
    for raw in LINKS_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line not in seen:
            seen.add(line)
            urls.append(line)
    return urls


def b64decode_lenient(data: str) -> bytes:
    data = "".join(data.split())
    data += "=" * (-len(data) % 4)
    return base64.b64decode(data, validate=False)


def normalize_to_text(raw: str) -> str:
    if "://" in raw:
        return raw
    try:
        decoded = b64decode_lenient(raw).decode("utf-8", errors="replace")
        if "://" in decoded:
            return decoded
    except Exception:
        pass
    out = []
    for line in raw.splitlines():
        s = line.strip()
        if not s or "://" in s:
            out.append(line)
            continue
        try:
            decoded = b64decode_lenient(s).decode("utf-8", errors="replace")
            if "://" in decoded:
                out.append(decoded)
                continue
        except Exception:
            pass
        out.append(line)
    return "\n".join(out)


def extract_configs(text: str) -> list[str]:
    return [m.group(0).rstrip(".,;)]}'\"><") for m in CONFIG_RE.finditer(text)]


def fetch_with_retries(url: str, timeout: int, retry_count: int) -> tuple[bool, str]:
    last_error = ""
    for attempt in range(1, retry_count + 1):
        try:
            r = requests.get(url, headers=HEADERS, proxies=PROXIES, timeout=timeout)
            r.raise_for_status()
            text = r.text.strip()
            if text:
                return True, text
            last_error = "Empty response"
        except Exception as e:
            last_error = str(e)
        if attempt < retry_count:
            time.sleep(1)
    return False, last_error


# ---------------------------------------------------------------- remark handling
def country_flag(code: str) -> str:
    code = (code or "").upper()
    if len(code) != 2 or not code.isalpha():
        return "🏳"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code)


def set_remark(uri: str, new_remark: str, protocol: str) -> str:
    if protocol == "vmess":
        try:
            raw = uri[len("vmess://"):].split("#", 1)[0]
            data = json.loads(b64decode_lenient(raw).decode("utf-8", errors="replace"))
            data["ps"] = new_remark
            encoded = base64.b64encode(
                json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            ).decode("ascii")
            return f"vmess://{encoded}"
        except Exception:
            return uri
    base, _, _ = uri.partition("#")
    return f"{base}#{quote(new_remark, safe='')}"


def build_enriched_remark(gemini_ok: bool, reddit_ok: bool, country: str | None) -> str:
    """Compose the final remark from the three test results, discarding the original."""
    parts: list[str] = []
    if country:
        parts.append(f"{country_flag(country)}-{country}")
    
    parts.append("GEMINI" if gemini_ok else "NOGEMINI")
    parts.append("REDDIT" if reddit_ok else "NOREDDIT")
    
    return "-".join(parts)


# ---------------------------------------------------------------- parsing
def _q(params: dict, key: str, default: str = "") -> str:
    v = params.get(key)
    return v[0] if v else default


def parse_vmess(uri: str) -> dict | None:
    try:
        raw = uri[len("vmess://"):].split("#", 1)[0]
        data = json.loads(b64decode_lenient(raw).decode("utf-8", errors="replace"))
    except Exception:
        return None
    try:
        port = int(data.get("port", 0) or 0)
    except (TypeError, ValueError):
        port = 0
    try:
        aid = int(data.get("aid", 0) or 0)
    except (TypeError, ValueError):
        aid = 0
    return {
        "protocol": "vmess", "address": data.get("add", ""), "port": port,
        "uuid": data.get("id", ""), "alterId": aid,
        "security": data.get("scy", "auto") or "auto",
        "network": data.get("net", "tcp") or "tcp",
        "headerType": data.get("type", ""), "host": data.get("host", ""),
        "path": data.get("path", "") or "/", "tls": data.get("tls", ""),
        "sni": data.get("sni", ""), "alpn": data.get("alpn", ""),
        "fp": data.get("fp", ""), "remark": data.get("ps", ""),
    }


def parse_url_style(uri: str, protocol: str) -> dict | None:
    try:
        p = urlparse(uri)
        params = parse_qs(p.query)
        return {
            "protocol": protocol, "uuid": unquote(p.username or ""),
            "address": p.hostname or "", "port": p.port or 0,
            "remark": unquote(p.fragment or ""),
            "network": _q(params, "type", "tcp") or "tcp",
            "tls": _q(params, "security", ""), "sni": _q(params, "sni", ""),
            "host": _q(params, "host", ""), "path": _q(params, "path", "") or "/",
            "fp": _q(params, "fp", ""), "alpn": _q(params, "alpn", ""),
            "flow": _q(params, "flow", ""),
            "serviceName": _q(params, "serviceName", ""),
            "pbk": _q(params, "pbk", ""), "sid": _q(params, "sid", ""),
            "headerType": _q(params, "headerType", ""), "mode": _q(params, "mode", ""),
        }
    except Exception:
        return None


def parse_ss(uri: str) -> dict | None:
    try:
        p = urlparse(uri)
        remark = unquote(p.fragment or "")
        if p.username and p.hostname and p.port:
            try:
                method_pass = b64decode_lenient(unquote(p.username)).decode("utf-8", errors="replace")
                if ":" in method_pass:
                    method, password = method_pass.split(":", 1)
                    return {
                        "protocol": "ss", "address": p.hostname, "port": p.port,
                        "method": method, "password": password, "remark": remark,
                    }
            except Exception:
                pass
        decoded = b64decode_lenient(uri[len("ss://"):].split("#", 1)[0]).decode(
            "utf-8", errors="replace"
        )
        method_pass, host_port = decoded.rsplit("@", 1)
        method, password = method_pass.split(":", 1)
        host, port = host_port.rsplit(":", 1)
        return {
            "protocol": "ss", "address": host, "port": int(port),
            "method": method, "password": password, "remark": remark,
        }
    except Exception:
        return None


def parse_config(uri: str) -> dict | None:
    uri = uri.strip()
    try:
        if uri.startswith("vmess://"):   return parse_vmess(uri)
        if uri.startswith("vless://"):   return parse_url_style(uri, "vless")
        if uri.startswith("trojan://"):  return parse_url_style(uri, "trojan")
        if uri.startswith("ss://"):      return parse_ss(uri)
    except Exception:
        return None
    return None


def fingerprint(p: dict) -> tuple:
    return (
        p.get("protocol"), (p.get("address") or "").lower(), p.get("port"),
        p.get("uuid") or "", p.get("method") or "", p.get("password") or "",
        p.get("network") or "", p.get("tls") or "", p.get("sni") or "",
        p.get("host") or "", p.get("path") or "", p.get("serviceName") or "",
        p.get("flow") or "", p.get("pbk") or "", p.get("sid") or "",
        p.get("headerType") or "", p.get("alterId") or 0,
    )


def parse_and_dedupe(raw_uris: list[str]) -> list[tuple[str, dict]]:
    unique: list[tuple[str, dict]] = []
    seen = set()
    for uri in raw_uris:
        p = parse_config(uri)
        if not p:
            continue
        fp = fingerprint(p)
        if fp in seen:
            continue
        seen.add(fp)
        unique.append((uri, p))
    return unique


def load_configs_from_file(path: Path) -> list[tuple[str, dict]]:
    uris = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return parse_and_dedupe(uris)


# ---------------------------------------------------------------- xray
def build_stream(p: dict) -> dict:
    network = p.get("network") or "tcp"
    tls = p.get("tls") or ""
    host = p.get("host") or ""
    path = p.get("path") or "/"
    stream: dict = {"network": network}

    if network == "ws":
        ws = {"path": path}
        if host:
            ws["headers"] = {"Host": host}
        stream["wsSettings"] = ws
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": p.get("serviceName") or ""}
    elif network in ("h2", "http"):
        stream["network"] = "h2"
        h2 = {"path": path}
        if host:
            h2["host"] = [h for h in host.split(",") if h]
        stream["httpSettings"] = h2
    elif network == "tcp" and p.get("headerType") == "http":
        stream["tcpSettings"] = {
            "header": {
                "type": "http",
                "request": {"path": [path], "headers": {"Host": [host] if host else []}},
            }
        }
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": path, "host": host}
    elif network == "xhttp":
        stream["xhttpSettings"] = {"path": path, "host": host, "mode": p.get("mode") or ""}

    if tls == "tls":
        ts = {}
        sni = p.get("sni") or host or p.get("address") or ""
        if sni:
            ts["serverName"] = sni
        if p.get("fp"):
            ts["fingerprint"] = p["fp"]
        if p.get("alpn"):
            ts["alpn"] = [a.strip() for a in p["alpn"].split(",") if a.strip()]
        stream["security"] = "tls"
        stream["tlsSettings"] = ts
    elif tls == "reality":
        rs = {}
        if p.get("sni"):
            rs["serverName"] = p["sni"]
        if p.get("fp"):
            rs["fingerprint"] = p["fp"]
        if p.get("pbk"):
            rs["publicKey"] = p["pbk"]
        if p.get("sid"):
            rs["shortId"] = p["sid"]
        stream["security"] = "reality"
        stream["realitySettings"] = rs
    else:
        stream["security"] = "none"

    return stream


def build_outbound(p: dict) -> dict | None:
    proto = p["protocol"]
    if not p.get("address") or not p.get("port"):
        return None
    try:
        port = int(p["port"])
    except (TypeError, ValueError):
        return None

    if proto in ("vmess", "vless"):
        user: dict = {"id": p["uuid"]}
        if proto == "vmess":
            user["alterId"] = int(p.get("alterId") or 0)
            user["security"] = p.get("security") or "auto"
        else:
            user["encryption"] = "none"
            if p.get("flow"):
                user["flow"] = p["flow"]
        return {
            "protocol": proto,
            "settings": {"vnext": [{"address": p["address"], "port": port, "users": [user]}]},
            "streamSettings": build_stream(p),
        }
    if proto == "trojan":
        return {
            "protocol": "trojan",
            "settings": {"servers": [{"address": p["address"], "port": port, "password": p["uuid"]}]},
            "streamSettings": build_stream(p),
        }
    if proto == "ss":
        return {
            "protocol": "shadowsocks",
            "settings": {"servers": [{
                "address": p["address"], "port": port,
                "method": p["method"], "password": p["password"],
            }]},
        }
    return None


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_port(port: int, timeout: float = 5.0) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.4):
                return True
        except OSError:
            time.sleep(0.1)
    return False


@contextmanager
def xray_proxy(p: dict):
    outbound = build_outbound(p)
    if not outbound:
        yield None
        return

    port = free_port()
    cfg = {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "port": port, "listen": "127.0.0.1",
            "protocol": "socks", "settings": {"udp": False},
        }],
        "outbounds": [outbound],
    }

    with tempfile.TemporaryDirectory() as tmp:
        cfg_path = Path(tmp) / "c.json"
        cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
        proc = subprocess.Popen(
            [XRAY_BINARY, "run", "-c", str(cfg_path)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            if not wait_port(port, 5.0):
                yield None
                return
            proxy_url = f"socks5h://127.0.0.1:{port}"
            yield {"http": proxy_url, "https": proxy_url}
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()


def xray_available() -> bool:
    try:
        r = subprocess.run([XRAY_BINARY, "version"], capture_output=True, timeout=5)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.SubprocessError):
        return False


def socks_support_available() -> bool:
    try:
        import socks  # noqa: F401
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------- tests
def test_endpoints(p: dict) -> bool:
    with xray_proxy(p) as proxies:
        if proxies is None:
            return False
        for url in TEST_ENDPOINTS:
            try:
                r = requests.get(url, proxies=proxies, timeout=TEST_TIMEOUT, allow_redirects=True)
                if r.status_code >= 500:
                    return False
            except requests.RequestException:
                return False
        return True


def _normalize_for_match(s: str) -> str:
    return (
        s.replace("\u2018", "'").replace("\u2019", "'")
         .replace("\u02BC", "'").lower()
    )


def is_gemini_blocked(body: str) -> bool:
    return _normalize_for_match(GEMINI_BLOCKED_MARKER) in _normalize_for_match(body)


# --- Reddit Specific Helpers ---
def find_reddit_block_marker(body: str) -> str | None:
    normalized = _normalize_for_match(unescape(body or ""))
    for marker in REDDIT_BLOCKED_MARKERS:
        normalized_marker = _normalize_for_match(marker)
        if normalized_marker in normalized:
            return marker
    return None


def _reddit_rate_limit() -> None:
    global _REDDIT_LAST_REQUEST_START
    with _REDDIT_RATE_LOCK:
        now = time.monotonic()
        delay = REDDIT_MIN_INTERVAL_SECONDS - (now - _REDDIT_LAST_REQUEST_START)
        if delay > 0:
            time.sleep(delay)
        _REDDIT_LAST_REQUEST_START = time.monotonic()


def _response_excerpt(body: str, marker: str | None = None) -> str:
    text = re.sub(r"\s+", " ", unescape(body or "")).strip()
    if not text:
        return "<empty response body>"
    if marker:
        lower_text = _normalize_for_match(text)
        lower_marker = _normalize_for_match(marker)
        pos = lower_text.find(lower_marker)
        if pos >= 0:
            start = max(0, pos - 100)
            end = min(len(text), pos + len(marker) + 180)
            return text[start:end][:REDDIT_BODY_PREVIEW_CHARS]
    return text[:REDDIT_BODY_PREVIEW_CHARS]


def classify_reddit_response(response: requests.Response) -> tuple[bool, str, str, str]:
    body = response.text or ""
    marker = find_reddit_block_marker(body)
    status_code = response.status_code
    content_type = response.headers.get("Content-Type", "unknown")
    final_url = response.url
    elapsed = getattr(getattr(response, "elapsed", None), "total_seconds", lambda: 0.0)()
    body_bytes = len(response.content or b"")

    history = getattr(response, "history", []) or []
    redirect_chain = " -> ".join([item.url for item in history] + [final_url])
    detail_parts = [
        f"HTTP {status_code}", f"redirect_chain={redirect_chain}",
        f"final_url={final_url}", f"content_type={content_type}",
        f"elapsed={elapsed:.2f}s", f"body_bytes={body_bytes}",
    ]
    for header in ("Server", "Retry-After", "X-Ratelimit-Used", "X-Ratelimit-Remaining", "X-Ratelimit-Reset", "X-Reddit-Request-Id"):
        value = response.headers.get(header)
        if value:
            detail_parts.append(f"{header}={value}")
    if marker:
        detail_parts.append(f"matched_marker={marker!r}")
    detail_parts.append(f"body_excerpt={_response_excerpt(body, marker)!r}")
    details = " | ".join(detail_parts)

    if marker:
        return False, f"Confirmed network-security block (HTTP {status_code})", details, "security_block"
    if status_code == 429:
        return False, "Rate limited (HTTP 429)", details, "rate_limited"
    if status_code == 403:
        return False, "HTTP 403 (no recognized security marker)", details, "unclassified_403"
    if status_code == 401:
        return False, "Authentication required (HTTP 401)", details, "login_required"
    if status_code >= 500:
        return False, f"Reddit server error (HTTP {status_code})", details, "http_error"
    if status_code >= 400:
        return False, f"HTTP error {status_code}", details, "http_error"
    if 200 <= status_code < 300:
        if not body.strip():
            return False, f"Empty response body (HTTP {status_code})", details, "other"
        final_path = urlparse(final_url).path.lower().rstrip("/")
        if final_path.startswith(("/login", "/account/login", "/register")):
            return False, f"Login page returned (HTTP {status_code})", details, "login_required"
        normalized_content_type = content_type.lower()
        if normalized_content_type != "unknown" and not any(
            kind in normalized_content_type for kind in ("text/html", "application/xhtml+xml")
        ):
            return False, f"Unexpected content type ({content_type})", details, "other"
        return True, f"Allowed (HTTP {status_code})", details, "allowed"
    if 300 <= status_code < 400:
        return False, f"Unresolved redirect (HTTP {status_code})", details, "other"
    return False, f"Unexpected HTTP status {status_code}", details, "other"


def reddit_request(proxies: dict | None = None) -> tuple[bool, str, str, str]:
    with _REDDIT_SEMAPHORE:
        _reddit_rate_limit()
        response = requests.get(
            REDDIT_TEST_URL,
            headers=REDDIT_HEADERS,
            proxies=proxies,
            timeout=REDDIT_TIMEOUT,
            allow_redirects=True,
        )
    return classify_reddit_response(response)


def reddit_direct_control() -> tuple[str, str]:
    try:
        with requests.Session() as session:
            session.trust_env = False
            response = session.get(
                REDDIT_TEST_URL, headers=REDDIT_HEADERS,
                timeout=REDDIT_TIMEOUT, allow_redirects=True,
            )
        _, status, details, _ = classify_reddit_response(response)
        return status, details
    except requests.RequestException as exc:
        return f"Unreachable: {type(exc).__name__}: {exc}", f"direct_runner_exception={exc!r}"


# ---------------------------------------------------------------- enrich test
def test_enrich(p: dict) -> tuple[bool, bool, str | None, str, str, str, str]:
    """Combined Gemini + Reddit + Geo check within a single xray session.
    
    Returns (gemini_ok, reddit_ok, country, gemini_status, reddit_status, reddit_details, reddit_category).
    """
    with xray_proxy(p) as proxies:
        if proxies is None:
            return (False, False, None, "Proxy failed", "Proxy failed", "", "unreachable")

        # --- 1. Gemini ---
        gemini_ok = False
        gemini_status = "Unknown error"
        try:
            g = requests.get(
                GEMINI_TEST_URL, proxies=proxies,
                timeout=GEMINI_TIMEOUT, allow_redirects=True,
            )
            if g.status_code >= 400:
                gemini_status = f"HTTP {g.status_code}"
            elif is_gemini_blocked(g.text or ""):
                gemini_status = "Geo-blocked"
            else:
                gemini_ok = True
                gemini_status = "Allowed"
        except requests.RequestException as e:
            gemini_status = f"Unreachable: {e}"

        # --- 2. Reddit ---
        reddit_ok = False
        reddit_details = ""
        reddit_category = "other"
        try:
            reddit_ok, reddit_status, reddit_details, reddit_category = reddit_request(proxies)
        except requests.RequestException as e:
            reddit_status = f"Unreachable: {type(e).__name__}: {e}"
            reddit_details = f"request_exception={e!r}"
            reddit_category = "unreachable"

        # --- 3. Geo ---
        country = None
        try:
            r = requests.get(GEO_ENRICH_URL, proxies=proxies, timeout=GEO_TIMEOUT)
            if r.status_code == 200:
                lines = [ln.strip() for ln in r.text.strip().splitlines()]
                if len(lines) >= 2 and lines[0].lower() == "success":
                    cc = lines[1].upper()
                    if len(cc) == 2 and cc.isalpha():
                        country = cc
        except requests.RequestException:
            pass

        return (gemini_ok, reddit_ok, country, gemini_status, reddit_status, reddit_details, reddit_category)


# ---------------------------------------------------------------- progress
def _render_bar(prefix: str, done: int, total: int, start: float, extra: str) -> None:
    pct = done / total if total else 1.0
    filled = int(30 * pct)
    bar = "█" * filled + "░" * (30 - filled)
    elapsed = time.time() - start
    eta = (elapsed / done) * (total - done) if done else 0.0
    if not IS_TTY:
        if done % 50 == 0 or done == total:
            print(f"  {prefix} {done}/{total}  {extra}")
        return
    sys.stdout.write(
        f"\r  {prefix} [{bar}] {done}/{total} ({pct * 100:5.1f}%)  {extra}  ETA {eta:4.0f}s\x1b[K"
    )
    sys.stdout.flush()


def _endline() -> None:
    if IS_TTY:
        sys.stdout.write("\n")
        sys.stdout.flush()


# ---------------------------------------------------------------- persistence
def _write(path: Path, uris: list[str]) -> None:
    path.write_text("\n".join(uris) + ("\n" if uris else ""), encoding="utf-8")


def _append_line(path: Path, line: str) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as f:
        f.write(line + "\n")
        f.flush()
        os.fsync(f.fileno())


# ---------------------------------------------------------------- interactive prompts
def prompt_steps() -> set[int] | None:
    print()
    print("Select steps (combine with '+'):")
    print("  1 = Fetch / custom file (source)")
    print("  2 = Endpoint Test")
    print("  3 = Enrich (Gemini + Geo + Reddit)")
    print()
    print("Examples: 1  |  1+2  |  1+2+3")
    while True:
        try:
            ans = input("Steps to run: ").strip()
        except EOFError:
            print()
            return None
        if not ans:
            continue
        try:
            steps = _parse_steps(ans)
        except ValueError as e:
            print(f"  {e}")
            continue
        if steps & {STEP_ENDPOINT, STEP_ENRICH} and STEP_SOURCE not in steps:
            print("  A source step (1) is required when running tests.")
            continue
        return steps


def _parse_steps(s: str) -> set[int]:
    tokens = re.split(r"[+,\s]+", s.strip())
    steps: set[int] = set()
    for t in tokens:
        if not t:
            continue
        if t in ("1", "2", "3"):
            steps.add(int(t))
        else:
            raise ValueError(f"Unknown step '{t}' — valid: 1,2,3")
    if not steps:
        raise ValueError("No steps given.")
    return steps


def prompt_source() -> tuple[str, Path | None] | None:
    print()
    print("Source:")
    print("  [1] Fetch subscription URLs (sub_links.txt)  (default)")
    print("  [2] Custom config file (.txt)")
    while True:
        try:
            ans = input("Choice [1-2, default 1]: ").strip()
        except EOFError:
            print()
            return ("fetch", None)
        if ans in ("", "1"):
            return ("fetch", None)
        if ans == "2":
            path = prompt_custom_file()
            if path is None:
                return None
            return ("custom", path)
        print("  Invalid. Enter 1 or 2.")


def prompt_custom_file() -> Path | None:
    print()
    print(f"Custom config file (.txt). Looked up in:")
    print(f"  {SCRIPT_DIR}")
    while True:
        try:
            name = input("Filename: ").strip()
        except EOFError:
            print()
            return None
        if not name:
            return None
        if not name.lower().endswith(".txt"):
            name += ".txt"
        for candidate in (SCRIPT_DIR / name, Path(name)):
            if candidate.exists():
                return candidate
        print(f"  Not found: {name}")


# ---------------------------------------------------------------- step runs
def run_source_fetch() -> list[tuple[str, dict]] | None:
    log("[Step 1] Fetch")
    try:
        urls = load_urls()
    except FileNotFoundError as e:
        log(f"[Step 1] ERROR: {e}")
        return None
    if not urls:
        log(f"[Step 1] ERROR: {LINKS_FILE} contains no URLs.")
        return None

    raw_uris: list[str] = []
    failures: list[tuple[str, str]] = []
    for url in urls:
        log(f"[Step 1] Fetching: {url}")
        ok, content = fetch_with_retries(url, FETCH_TIMEOUT_SECONDS, RETRY_COUNT)
        if not ok:
            failures.append((url, content))
            log(f"[Step 1]   FAILED: {content}")
            continue
        extracted = extract_configs(normalize_to_text(content))
        log(f"[Step 1]   {len(extracted)} configs")
        raw_uris.extend(extracted)

    unique = parse_and_dedupe(raw_uris)
    log(f"[Step 1] Total: {len(raw_uris)}  Unique: {len(unique)}")

    _write(ALIVE_DIR / "all.txt", [u for u, _ in unique])
    log(f"[Step 1] Saved: {ALIVE_DIR / 'all.txt'}")

    if failures:
        fail_log = LOG_DIR / "failed.txt"
        with fail_log.open("w", encoding="utf-8", newline="\n") as f:
            for i, (url, err) in enumerate(failures, 1):
                f.write(f"[{i}] {url}\nERROR: {err}\n{'-' * 80}\n")
        log(f"[Step 1] Saved failure log: {fail_log}")

    return unique


def run_source_custom(path: Path) -> list[tuple[str, dict]] | None:
    log(f"[Step 1] Custom config file: {path.name}")
    configs = load_configs_from_file(path)
    log(f"[Step 1] Loaded {len(configs)} unique configs")
    _write(ALIVE_DIR / "all.txt", [u for u, _ in configs])
    log(f"[Step 1] Saved: {ALIVE_DIR / 'all.txt'}")
    return configs


def run_endpoint_test(configs: list[tuple[str, dict]]) -> list[tuple[str, dict]] | None:
    log("[Step 2] Endpoint Test")
    testable, skipped = [], 0
    for uri, p in configs:
        if build_outbound(p) is None:
            skipped += 1
        else:
            testable.append((uri, p))
    if skipped:
        log(f"[Step 2]   {skipped} configs skipped (unsupported protocol)")

    if not xray_available():
        log("[Step 2] WARNING: xray binary not available.")
        return None

    out_path = ALIVE_DIR / "working.txt"
    out_path.write_text("", encoding="utf-8")

    log(f"[Step 2] Testing {len(testable)} configs (workers={TEST_WORKERS})...")
    passed_pairs: list[tuple[str, dict]] = []
    passed_uris: list[str] = []
    passed = failed = 0
    start = time.time()

    def record(uri: str, p: dict) -> None:
        passed_uris.append(uri)
        passed_pairs.append((uri, p))
        _append_line(out_path, uri)

    with ThreadPoolExecutor(max_workers=TEST_WORKERS) as ex:
        futures = {ex.submit(test_endpoints, p): (uri, p) for uri, p in testable}
        done = 0
        for fut in as_completed(futures):
            done += 1
            uri, p = futures[fut]
            try:
                if fut.result():
                    record(uri, p); passed += 1
                else:
                    failed += 1
            except Exception as e:
                failed += 1
                _endline()
                log(f"[Step 2]   ERR {uri[:70]}: {e}")
            _render_bar("Step 2", done, len(testable), start,
                        f"PASS {passed}  FAIL {failed}  SKIP {skipped}")
    _endline()

    elapsed = time.time() - start
    log(f"[Step 2] Done in {elapsed:.0f}s — PASS {passed}  FAIL {failed}  SKIP {skipped}")
    log(f"[Step 2] Saved: {out_path}  ({len(passed_pairs)} configs)")
    return passed_pairs


def run_enrich(configs: list[tuple[str, dict]]) -> list[tuple[str, dict]] | None:
    """Step 3 — annotate every config with geo + Gemini + Reddit."""
    log("[Step 3] Enrich (geo + Gemini + Reddit)")
    if not configs:
        log("[Step 3] No configs to enrich.")
        return []
    if not xray_available():
        log("[Step 3] WARNING: xray binary not available.")
        return None

    out_path = ALIVE_DIR / "enriched.txt"
    out_path.write_text("", encoding="utf-8")
    reddit_log_path = LOG_DIR / "reddit_checks.txt"

    log(f"[Step 3] Enriching {len(configs)} configs (workers={TEST_WORKERS})...")
    
    # Direct runner control for Reddit
    direct_reddit_status, direct_reddit_details = reddit_direct_control()
    log(f"Direct runner Reddit control (NOT through Xray): {direct_reddit_status}")

    enriched: list[tuple[str, dict]] = []
    site_check_results = []
    
    counts = {
        "GEMINI": 0, "NOGEMINI": 0,
        "REDDIT": 0, "NOREDDIT": 0,
    }
    reddit_stats = {
        "security_block": 0, "rate_limited": 0, "unclassified_403": 0,
        "login_required": 0, "http_error": 0, "unreachable": 0, "other": 0,
    }
    
    start = time.time()

    def record(uri: str, p: dict, gemini_ok: bool, reddit_ok: bool, country: str | None) -> None:
        new_remark = build_enriched_remark(gemini_ok, reddit_ok, country)
        new_uri = set_remark(uri, new_remark, p["protocol"])
        new_p = dict(p)
        new_p["remark"] = new_remark
        enriched.append((new_uri, new_p))
        _append_line(out_path, new_uri)

    with ThreadPoolExecutor(max_workers=TEST_WORKERS) as ex:
        futures = {ex.submit(test_enrich, p): (uri, p) for uri, p in configs}
        done = 0
        for fut in as_completed(futures):
            done += 1
            uri, p = futures[fut]
            try:
                (gemini_ok, reddit_ok, country, gemini_status, reddit_status, 
                 reddit_details, reddit_category) = fut.result()
            except Exception as e:
                _endline()
                log(f"[Step 3]   ERR {uri[:70]}: {e}")
                gemini_ok, reddit_ok, country = False, False, None
                gemini_status = f"Test Exception: {e}"
                reddit_status = f"Test Exception: {e}"
                reddit_details = ""
                reddit_category = "other"

            record(uri, p, gemini_ok, reddit_ok, country)
            site_check_results.append((uri, gemini_status, reddit_status, reddit_details))
            
            counts["GEMINI" if gemini_ok else "NOGEMINI"] += 1
            counts["REDDIT" if reddit_ok else "NOREDDIT"] += 1
            if not reddit_ok:
                reddit_stats[reddit_category] = reddit_stats.get(reddit_category, 0) + 1

            _render_bar(
                "Step 3", done, len(configs), start,
                f"Gem:{counts['GEMINI']} Red:{counts['REDDIT']}"
            )
    _endline()

    elapsed = time.time() - start
    
    # Save detailed Reddit diagnostics
    with reddit_log_path.open("w", encoding="utf-8", newline="\n") as f:
        f.write("DIRECT RUNNER CONTROL (not through Xray)\n")
        f.write(f"Reddit: {direct_reddit_status}\n")
        f.write(f"Details: {direct_reddit_details}\n")
        f.write("=" * 80 + "\n")
        for i, (uri, gemini_status, reddit_status, reddit_details) in enumerate(site_check_results, 1):
            f.write(f"[{i}] URI: {uri}\n")
            f.write(f"Gemini: {gemini_status}\n")
            f.write(f"Reddit: {reddit_status}\n")
            f.write(f"Reddit details: {reddit_details}\n")
            f.write("-" * 80 + "\n")
    log(f"[Step 3] Saved Reddit diagnostics: {reddit_log_path}")

    log(
        f"[Step 3] Done in {elapsed:.0f}s — "
        f"GEMINI {counts['GEMINI']}  NOGEMINI {counts['NOGEMINI']}  |  "
        f"REDDIT {counts['REDDIT']}  NOREDDIT {counts['NOREDDIT']}"
    )
    log(
        f"[Step 3] Reddit Failures — "
        f"Security Block: {reddit_stats['security_block']}  "
        f"Rate Limited: {reddit_stats['rate_limited']}  "
        f"Unclassified 403: {reddit_stats['unclassified_403']}  "
        f"Login Req: {reddit_stats['login_required']}  "
        f"HTTP Err: {reddit_stats['http_error']}  "
        f"Unreachable: {reddit_stats['unreachable']}"
    )
    log(f"[Step 3] Saved: {out_path}  ({len(enriched)} configs)")
    return enriched


# ---------------------------------------------------------------- pipeline
def run_pipeline(steps: set[int], custom_file_arg: str | None) -> None:
    ensure_dirs()

    if not steps:
        log("No steps selected — nothing to do.")
        return
    if steps & {STEP_ENDPOINT, STEP_ENRICH} and STEP_SOURCE not in steps:
        log("ERROR: a source step (1) is required when running tests.")
        return
        
    if not socks_support_available():
        log("ERROR: SOCKS proxy support is missing.")
        log("       Install it with: python -m pip install 'requests[socks]'")
        return

    # ---- Step 1: resolve source ----
    current: list[tuple[str, dict]] = []
    if STEP_SOURCE in steps:
        if custom_file_arg:
            path = Path(custom_file_arg)
            if not path.exists():
                path = SCRIPT_DIR / custom_file_arg
            if not path.exists():
                log(f"ERROR: custom file not found: {custom_file_arg}")
                return
            loaded = run_source_custom(path)
        elif IS_TTY:
            choice = prompt_source()
            if choice is None:
                log("Source cancelled — aborting.")
                return
            kind, path = choice
            loaded = run_source_fetch() if kind == "fetch" else run_source_custom(path)  # type: ignore[arg-type]
        else:
            loaded = run_source_fetch()
        if loaded is None:
            return
        current = loaded

    if not current:
        log("No configs available — aborting.")
        return

    # ---- Step 2: endpoint test ----
    if STEP_ENDPOINT in steps:
        result = run_endpoint_test(current)
        if result is None:
            return
        current = result

    # ---- Step 3: enrich ----
    if STEP_ENRICH in steps:
        result = run_enrich(current)
        if result is None:
            return
        current = result

    log(f"Pipeline complete. Final configs: {len(current)}")


# ---------------------------------------------------------------- main
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Proxy config pipeline: source → endpoint test → enrich."
    )
    parser.add_argument(
        "--steps", default=None,
        help="Non-interactive step combo (e.g. '1+2+3'). "
             "If omitted and stdin is a TTY, you'll be prompted.",
    )
    parser.add_argument(
        "--custom-file", default=None,
        help="With --steps containing '1', load this file instead of fetching.",
    )
    args = parser.parse_args()

    if args.steps:
        try:
            steps = _parse_steps(args.steps)
        except ValueError as e:
            log(f"ERROR: {e}")
            return
        if steps & {STEP_ENDPOINT, STEP_ENRICH} and STEP_SOURCE not in steps:
            log("ERROR: a source step (1) is required when running tests.")
            return
    elif IS_TTY:
        steps = prompt_steps()
        if steps is None:
            log("No steps given — exiting.")
            return
    else:
        log("Non-interactive and no --steps given.")
        log("Example:  python script.py --steps '1+2+3'")
        return

    log(f"Selected steps: {sorted(steps)}")
    try:
        run_pipeline(steps, args.custom_file)
    except KeyboardInterrupt:
        log("Stopped by user.")
    except Exception as e:
        ensure_dirs()
        log_file = LOG_DIR / "failed.txt"
        log_file.write_text(f"Fatal error: {e}\n", encoding="utf-8")
        log(f"Fatal error: {e}")
        log(f"Logged to: {log_file}")


if __name__ == "__main__":
    main()
