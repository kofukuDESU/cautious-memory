#!/usr/bin/env python3
"""
Proxy config pipeline — GitHub Actions friendly edition.

Steps:
  1 = Fetch subscriptions / custom file (source)
  2 = Endpoint test (xray + real HTTPS probes, then a 100 KB / 3 s speed
      download on the SAME session and worker pool — not a separate step)
  3 = Enrich (Gemini + Geo, no filtering)
When 2 and 3 are both selected, they share ONE xray session per config.

Outputs (./ALIVE/):
  all.txt      deduplicated source configs
  working.txt  configs that passed the endpoint test
  enriched.txt annotated configs:
               {flag}-{CC}-{GEMINI|NOGEMINI|GEMERR}-{idx}-{speed}KB
               e.g. 🇩🇪-DE-GEMINI-007-850KB  (speed suffix = KB/s from the
               100 KB probe; present only when step 2 ran)
               dead proxies (enrich-only mode) get {flag}-{CC}-DEAD-{idx}

Label semantics:
  GEMINI      tested, allowed
  NOGEMINI    tested, geo-blocked
  GEMERR      inconclusive (timeout, challenge, HTTP error, ...)
  DEAD        proxy itself did not work

CI behavior:
  - Non-interactive: never prompts. On GitHub Actions, --steps defaults to 1+2+3
    (override with --steps or env PROXY_STEPS).
  - Auto-installs xray into ./bin/ if missing (disable: --no-install-xray,
    pin with env XRAY_VERSION=v26.11.9, or point XRAY_BINARY at your own).
  - Writes logs/summary.json and appends a report to $GITHUB_STEP_SUMMARY.
  - Speed results: logs/speed_test.txt (fastest first) + avg/median/max stats.
  - Samples of unparseable links are saved to logs/parse_failed.txt.
  - --time-budget MINUTES stops testing gracefully so results still get saved.

Requires: Python 3.10+, requests[socks]  (pip install "requests[socks]")
"""

from __future__ import annotations

import argparse
import base64
import io
import json
import os
import platform
import random
import re
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import zipfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from html import unescape
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse

import requests

# ---------------------------------------------------------------- config
SCRIPT_DIR = Path(__file__).resolve().parent
LINKS_FILE = SCRIPT_DIR / "sub_links.txt"
ALIVE_DIR = Path("ALIVE")
LOG_DIR = Path("logs")
BIN_DIR = SCRIPT_DIR / "bin"

FETCH_TIMEOUT = (5, 20)          # connect, read
FETCH_RETRIES = 3
FETCH_WORKERS = 8
MAX_SUB_BYTES = 10_000_000       # 10 MB safety cap per subscription
FETCH_PROXIES: dict | None = None

BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"
)
HEADERS = {"User-Agent": BROWSER_UA}

XRAY_BIN = "xray"                # resolved / replaced at runtime
XRAY_VERSION_STR = "unknown"
XRAY_START_TIMEOUT = 5.0
XRAY_START_ATTEMPTS = 3          # fresh port per attempt (port-race mitigation)

# (url, expected status, required body marker or None)
TEST_ENDPOINTS = [
    ("https://cp.cloudflare.com/generate_204", 204, None),
    ("https://www.gstatic.com/generate_204", 204, None),
    ("https://captive.apple.com/hotspot-detect.html", 200, "success"),
]
TEST_TIMEOUT = (3, 5)            # connect, read — through a proxy chain
ENDPOINT_ROUNDS = 2              # one full retry round
TEST_WORKERS = 40                # concurrent test workers (steps 2 and 3)

# ---- Download speed probe (part of step 2, NOT a separate step) ----
# Runs on the SAME xray session and SAME worker pool as the endpoint test,
# immediately after a config passes its endpoint probe.
SPEED_TEST_BYTES = 100_000        # 100 KB payload
SPEED_TEST_URL = f"https://speed.cloudflare.com/__down?bytes={SPEED_TEST_BYTES}"
SPEED_TIMEOUT = 3.0               # seconds: connect/read timeout + total transfer cap
SPEED_CHUNK = 4096                # small chunks so the 3 s wall-clock cap stays tight

# ---- Gemini check ----
GEMINI_TEST_URL = "https://gemini.google.com/?hl=en"
GEMINI_HEADERS = {"User-Agent": BROWSER_UA, "Accept-Language": "en-US,en;q=0.9"}
GEMINI_TIMEOUT = (5, 10)
GEMINI_BLOCK_MARKERS = ("currently supported in your country",)
BODY_PREVIEW_CHARS = 350

# ---- Geo check ----
GEO_TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"      # https, loc=CC
GEO_FALLBACK_URL = "http://ip-api.com/line/?fields=status,countryCode"  # 45 req/min/IP
GEO_TIMEOUT = 5

CONFIG_RE = re.compile(
    r"(?:vmess|vless|trojan|ssr|ss|hysteria2|hysteria|hy2|tuic|wireguard|wg)://[^\s\"'<>`]+",
    re.IGNORECASE,
)
SUPPORTED_SCHEMES = {"vmess", "vless", "trojan", "ss"}

STEP_SOURCE = 1
STEP_ENDPOINT = 2
STEP_ENRICH = 3

IS_TTY = sys.stdout.isatty()
IN_CI = bool(os.environ.get("GITHUB_ACTIONS") or os.environ.get("CI"))

STOP = threading.Event()
DEADLINE: float | None = None    # monotonic deadline when --time-budget is used
ALLOW_INSECURE = False           # honor allowInsecure=1 only with --allow-insecure

SUMMARY: dict = {}


# ---------------------------------------------------------------- helpers
def ensure_dirs() -> None:
    ALIVE_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def deadline_exceeded() -> bool:
    return DEADLINE is not None and time.monotonic() >= DEADLINE


class TaskSkipped(Exception):
    """Raised by workers when STOP is set or the time budget ran out."""


def _check_stop() -> None:
    if STOP.is_set() or deadline_exceeded():
        raise TaskSkipped()


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
    # Accept BOTH standard and URL-safe base64. b64decode(validate=False)
    # silently DROPS '-' and '_' instead of translating them -> corruption.
    data = "".join(data.split()).replace("-", "+").replace("_", "/")
    data += "=" * (-len(data) % 4)
    return base64.b64decode(data, validate=False)


def normalize_to_text(raw: str) -> str:
    # Whole-body decode (up to 3 layers) only when no plaintext links exist.
    text = raw
    for _ in range(3):
        if "://" in text:
            break
        try:
            decoded = b64decode_lenient(text).decode("utf-8", errors="replace")
        except Exception:
            break
        if "://" not in decoded:
            break
        text = decoded
    # ALWAYS run the per-line pass: subscriptions can mix plain + b64 lines.
    out = []
    for line in text.splitlines():
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
    # Keep )]} — they are common inside remarks; strip only clear delimiters.
    return [m.group(0).rstrip(".,;'\"<>`") for m in CONFIG_RE.finditer(text)]


def fetch_with_retries(url: str) -> tuple[bool, str]:
    last_error = ""
    for attempt in range(1, FETCH_RETRIES + 1):
        try:
            with requests.get(url, headers=HEADERS, proxies=FETCH_PROXIES,
                              timeout=FETCH_TIMEOUT, stream=True) as r:
                r.raise_for_status()
                chunks, size = [], 0
                for chunk in r.iter_content(65536):
                    size += len(chunk)
                    if size > MAX_SUB_BYTES:
                        raise ValueError("subscription exceeds size cap")
                    chunks.append(chunk)
                # Force UTF-8: requests defaults to ISO-8859-1 without charset,
                # which mangles Persian/emoji remarks.
                text = b"".join(chunks).decode("utf-8", errors="replace").strip()
                if text:
                    return True, text
                last_error = "Empty response"
        except Exception as e:
            last_error = f"{type(e).__name__}: {e}"
        if attempt < FETCH_RETRIES:
            time.sleep(min(2 ** (attempt - 1), 8) + random.uniform(0, 0.5))
    return False, last_error


# ---------------------------------------------------------------- remarks
def country_flag(code: str) -> str:
    code = (code or "").upper()
    if len(code) != 2 or not code.isalpha():
        return "🏳"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code)


def set_remark(uri: str, new_remark: str, protocol: str) -> str:
    if protocol == "vmess":
        raw = uri[len("vmess://"):].split("#", 1)[0].split("?", 1)[0]
        data = _vmess_json(raw)
        if data is None:
            # Shadowrocket-style vmess: normalize to standard JSON so the
            # remark survives and every client understands the output.
            p = parse_vmess(uri)
            if not p:
                return uri
            data = {"v": "2", "add": p["address"], "port": p["port"], "id": p["uuid"],
                    "aid": p.get("alterId", 0), "scy": p.get("security") or "auto",
                    "net": p.get("network") or "tcp", "type": p.get("headerType") or "",
                    "host": p.get("host") or "", "path": p.get("path") or "",
                    "tls": p.get("tls") or "", "sni": p.get("sni") or "",
                    "alpn": p.get("alpn") or "", "fp": p.get("fp") or ""}
        data["ps"] = new_remark
        encoded = base64.b64encode(
            json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ).decode("ascii")
        return f"vmess://{encoded}"
    base, _, _ = uri.partition("#")
    return f"{base}#{quote(new_remark, safe='')}"


def gemini_tag(res: SiteResult) -> str:
    if res.ok:
        return "GEMINI"
    return "NOGEMINI" if res.category == "blocked" else "GEMERR"


def build_enriched_remark(res: EnrichResult, idx: int,
                          speed: SpeedResult | None = None) -> str:
    parts: list[str] = []
    if res.country:
        parts.append(f"{country_flag(res.country)}-{res.country}")
    if res.dead:
        parts.append("DEAD")
    else:
        parts.append(gemini_tag(res.gemini))
    parts.append(f"{idx:03d}")   # unique per run -> no identical remarks
    if speed is not None:
        parts.append(f"{speed.kbps:.0f}KB")   # measured KB/s, e.g. 850KB
    return "-".join(parts)


# ---------------------------------------------------------------- parsing
def _q(params: dict, key: str, default: str = "") -> str:
    v = params.get(key)
    return v[0] if v else default


def _safe_int(value, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        try:
            return int(float(str(value).strip()))
        except (TypeError, ValueError):
            return default


def _vmess_json(payload: str) -> dict | None:
    """JSON payload hunt: std/urlsafe b64, percent-encoding, double-b64, BOM/NUL."""
    seen: set[str] = set()
    for cand in (payload, unquote(payload)):
        text = cand
        for _ in range(2):                      # some panels double-encode
            if text in seen:
                break
            seen.add(text)
            try:
                decoded = b64decode_lenient(text).decode("utf-8", errors="replace")
            except Exception:
                break
            cleaned = decoded.lstrip("\ufeff").strip().strip("\x00").strip()
            try:
                data = json.loads(cleaned)
                if isinstance(data, dict):
                    return data
            except Exception:
                pass
            text = cleaned
    return None


def parse_vmess(uri: str) -> dict | None:
    payload = uri[len("vmess://"):].split("#", 1)[0]
    payload, _, query = payload.partition("?")   # strip ?query BEFORE b64 decode
    data = _vmess_json(payload)
    if data is not None:
        alpn = data.get("alpn", "")
        if isinstance(alpn, list):              # some JSON variants use lists
            alpn = ",".join(str(a) for a in alpn)
        return {
            "protocol": "vmess",
            "address": data.get("add") or data.get("address") or "",
            "port": _safe_int(data.get("port")), "uuid": data.get("id") or "",
            "alterId": _safe_int(data.get("aid")),
            "security": data.get("scy", "auto") or "auto",
            "network": data.get("net", "tcp") or "tcp",
            "headerType": data.get("type", ""), "host": data.get("host", ""),
            "path": data.get("path", "") or "/", "tls": data.get("tls", ""),
            "sni": data.get("sni", ""), "alpn": alpn or "",
            "fp": data.get("fp", ""), "remark": data.get("ps", ""),
        }
    # Shadowrocket style: vmess://b64(cipher:uuid@host:port)?obfs=websocket&...
    try:
        decoded = b64decode_lenient(unquote(payload)).decode("utf-8", errors="replace").strip()
        if "@" not in decoded or ":" not in decoded:
            return None
        method, rest = decoded.split(":", 1)
        uuid, hostport = rest.rsplit("@", 1)
        address, port = _split_host_port(hostport.split("/", 1)[0])
    except Exception:
        return None
    if not address or not uuid or not (0 < port < 65536):
        return None
    params = parse_qs(query)
    obfs = _q(params, "obfs", "none").lower()
    network = {"websocket": "ws", "ws": "ws", "http": "h2", "h2": "h2",
               "grpc": "grpc"}.get(obfs, "tcp")
    tls = "tls" if _q(params, "tls", "0").lower() in ("1", "true") else ""
    return {
        "protocol": "vmess", "address": address, "port": port, "uuid": uuid,
        "alterId": _safe_int(_q(params, "alterId", "0")),
        "security": method or "auto", "network": network,
        "headerType": "", "host": _q(params, "obfsParam", ""),
        "path": _q(params, "path", "") or "/", "tls": tls,
        "sni": _q(params, "sni", "") or _q(params, "peer", ""),
        "alpn": "", "fp": "", "remark": _q(params, "remarks", ""),
    }


def parse_url_style(uri: str, protocol: str) -> dict | None:
    try:
        p = urlparse(uri)
    except ValueError:
        return None                              # truly malformed authority
    try:
        port = p.port or 0                       # .port RAISES on garbage ports
    except ValueError:
        port = 0                                 # -> "unsupported" later, not parse-failed
    params = parse_qs(p.query)
    # TLS is IMPLICIT for trojan; links often omit security=tls.
    default_tls = "tls" if protocol == "trojan" else ""
    insecure = _q(params, "allowInsecure", _q(params, "insecure", "")).lower() in ("1", "true")
    return {
        "protocol": protocol, "uuid": unquote(p.username or ""),
        "address": p.hostname or "", "port": port,
        "remark": unquote(p.fragment or ""),
        "network": _q(params, "type", "tcp") or "tcp",
        "tls": _q(params, "security", default_tls),
        "sni": _q(params, "sni", ""), "host": _q(params, "host", ""),
        "path": _q(params, "path", "") or "/",
        "fp": _q(params, "fp", ""), "alpn": _q(params, "alpn", ""),
        "flow": _q(params, "flow", ""),
        "serviceName": _q(params, "serviceName", ""),
        "pbk": _q(params, "pbk", ""), "sid": _q(params, "sid", ""),
        "spx": _q(params, "spx", ""),
        "headerType": _q(params, "headerType", ""),
        "mode": _q(params, "mode", ""),
        "allowInsecure": insecure,
    }


def _split_host_port(s: str) -> tuple[str, int]:
    s = s.strip()
    if s.startswith("["):                           # [ipv6]:port
        host, _, rest = s[1:].partition("]")
        return host, int(rest.lstrip(":"))
    host, port = s.rsplit(":", 1)
    return host.strip("[]"), int(port)


def parse_ss(uri: str) -> dict | None:
    """Manual split (not urlparse) so base64 userinfo containing '/' or '+'
    survives, and plaintext method:password userinfo is accepted too."""
    try:
        body = uri[len("ss://"):].split("#", 1)[0]
        remark = unquote(uri.partition("#")[2])
        params: dict = {}
        if "?" in body:
            body, query = body.split("?", 1)
            params = parse_qs(query)
        base = {
            "protocol": "ss", "remark": remark,
            "plugin": _q(params, "plugin", ""),
            "network": _q(params, "type", "tcp") or "tcp",
            "tls": _q(params, "security", ""),
            "sni": _q(params, "sni", ""), "host": _q(params, "host", ""),
            "path": _q(params, "path", "") or "/",
            "fp": _q(params, "fp", ""), "alpn": _q(params, "alpn", ""),
        }
        if "@" in body:                             # SIP002
            userinfo, hostport = body.rsplit("@", 1)
            hostport = hostport.split("/", 1)[0]    # strip trailing /path
            userinfo = unquote(userinfo)
            if ":" in userinfo:                     # plaintext method:password
                method, password = userinfo.split(":", 1)
            else:                                   # base64(method:password)
                decoded = b64decode_lenient(userinfo).decode("utf-8", errors="replace")
                if ":" not in decoded:
                    return None
                method, password = decoded.split(":", 1)
        else:                                       # legacy full-base64
            decoded = b64decode_lenient(body).decode("utf-8", errors="replace")
            method_pass, hostport = decoded.rsplit("@", 1)
            hostport = hostport.split("/", 1)[0]    # same, inside the b64 body
            method, password = method_pass.split(":", 1)
        address, port = _split_host_port(hostport)
        if not address or not method or not (0 < port < 65536):
            return None
        return {**base, "address": address, "port": port,
                "method": method, "password": password}
    except Exception:
        return None


def parse_config(uri: str) -> dict | None:
    uri = uri.strip()
    scheme = uri.split("://", 1)[0].lower()         # regex is case-insensitive
    if scheme == "vmess":
        return parse_vmess(uri)
    if scheme == "vless":
        return parse_url_style(uri, "vless")
    if scheme == "trojan":
        return parse_url_style(uri, "trojan")
    if scheme == "ss":
        return parse_ss(uri)
    return None


def fingerprint(p: dict) -> tuple:
    return (
        p.get("protocol"), (p.get("address") or "").lower(), p.get("port"),
        p.get("uuid") or "", p.get("method") or "", p.get("password") or "",
        p.get("network") or "", p.get("tls") or "", (p.get("sni") or "").lower(),
        (p.get("host") or "").lower(), p.get("path") or "", p.get("serviceName") or "",
        p.get("flow") or "", p.get("pbk") or "", p.get("sid") or "",
        p.get("headerType") or "", p.get("alterId") or 0,
        p.get("security") or "", p.get("fp") or "", p.get("alpn") or "",
        p.get("mode") or "", p.get("plugin") or "",
    )


def parse_and_dedupe(raw_uris: list[str]) -> tuple[list[tuple[str, dict]], Counter]:
    unique: list[tuple[str, dict]] = []
    seen: set[tuple] = set()
    skipped: Counter = Counter()
    failures: list[str] = []
    for uri in raw_uris:
        scheme = uri.split("://", 1)[0].lower()
        if scheme not in SUPPORTED_SCHEMES:
            skipped[scheme] += 1                    # hy2/tuic need sing-box, not xray
            continue
        p = parse_config(uri)
        if not p:
            skipped[f"{scheme} (parse failed)"] += 1
            if len(failures) < 100:                 # keep samples for auditing
                failures.append(uri)
            continue
        fp = fingerprint(p)
        if fp in seen:
            continue
        seen.add(fp)
        unique.append((uri, p))
    if failures:
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            (LOG_DIR / "parse_failed.txt").write_text(
                "\n".join(failures) + "\n", encoding="utf-8")
        except OSError:
            pass
    return unique, skipped


def load_configs_from_file(path: Path) -> tuple[list[tuple[str, dict]], Counter]:
    # Same normalization as the fetch path (b64 dumps, mixed lines, etc.)
    text = path.read_text(encoding="utf-8", errors="replace")
    return parse_and_dedupe(extract_configs(normalize_to_text(text)))


# ---------------------------------------------------------------- xray config
def build_stream(p: dict) -> dict:
    network = (p.get("network") or "tcp").lower()
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
        gs = {"serviceName": p.get("serviceName") or ""}
        if p.get("mode") == "multi":
            gs["multiMode"] = True
        stream["grpcSettings"] = gs
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
        hu = {"path": path}
        if host:
            hu["host"] = host
        stream["httpupgradeSettings"] = hu
    elif network == "xhttp":
        xs = {"path": path}
        if host:
            xs["host"] = host
        if p.get("mode"):
            xs["mode"] = p["mode"]
        stream["xhttpSettings"] = xs

    if tls == "tls":
        ts = {}
        sni = p.get("sni") or host or p.get("address") or ""
        if sni:
            ts["serverName"] = sni
        if p.get("fp"):
            ts["fingerprint"] = p["fp"]
        if p.get("alpn"):
            ts["alpn"] = [a.strip() for a in str(p["alpn"]).split(",") if a.strip()]
        if ALLOW_INSECURE and p.get("allowInsecure"):
            ts["allowInsecure"] = True
        stream["security"] = "tls"
        stream["tlsSettings"] = ts
    elif tls == "reality":
        # REALITY needs a uTLS fingerprint; default to chrome when absent.
        rs = {"fingerprint": p.get("fp") or "chrome", "publicKey": p.get("pbk") or ""}
        if p.get("sni"):
            rs["serverName"] = p["sni"]
        if p.get("sid"):
            rs["shortId"] = p["sid"]
        if p.get("spx"):
            rs["spiderX"] = p["spx"]
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
    if not (0 < port < 65536):
        return None
    network = (p.get("network") or "tcp").lower()
    if network in ("kcp", "mkcp", "quic"):
        return None                                 # settings not recoverable from links
    if p.get("tls") == "reality" and not p.get("pbk"):
        return None                                 # REALITY without key cannot work

    if proto in ("vmess", "vless"):
        if not p.get("uuid"):
            return None
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
        if not p.get("uuid"):
            return None
        return {
            "protocol": "trojan",
            "settings": {"servers": [{"address": p["address"], "port": port,
                                      "password": p["uuid"]}]},
            "streamSettings": build_stream(p),
        }
    if proto == "ss":
        if p.get("plugin"):
            return None                             # SIP003 plugins unsupported by xray
        if not p.get("method") or not p.get("password"):
            return None
        return {
            "protocol": "shadowsocks",
            "settings": {"servers": [{
                "address": p["address"], "port": port,
                "method": p["method"], "password": p["password"],
            }]},
            "streamSettings": build_stream(p),
        }
    return None


# ---------------------------------------------------------------- xray process
def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_port(proc: subprocess.Popen, port: int, timeout: float = 5.0) -> bool:
    """Wait until OUR xray answers a SOCKS5 greeting on the port.
    Bails out immediately if the process died (bad config)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.4) as s:
                s.settimeout(0.4)
                s.sendall(b"\x05\x01\x00")          # SOCKS5 hello, no-auth
                if s.recv(2) == b"\x05\x00":
                    return True
        except OSError:
            pass
        time.sleep(0.05)
    return False


def _terminate(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass


@contextmanager
def xray_proxy(p: dict):
    outbound = build_outbound(p)
    if outbound is None:
        yield None
        return
    with tempfile.TemporaryDirectory(prefix="xray_") as tmp:
        cfg_path = Path(tmp) / "c.json"
        for _attempt in range(XRAY_START_ATTEMPTS):
            if STOP.is_set():
                break
            port = free_port()                      # fresh port each attempt
            cfg = {
                "log": {"loglevel": "none"},
                "inbounds": [{
                    "port": port, "listen": "127.0.0.1",
                    "protocol": "socks", "settings": {"udp": False},
                }],
                "outbounds": [outbound],
            }
            cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
            proc = subprocess.Popen(
                [XRAY_BIN, "run", "-c", str(cfg_path)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            if wait_port(proc, port, XRAY_START_TIMEOUT):
                proxy_url = f"socks5h://127.0.0.1:{port}"
                try:
                    yield {"http": proxy_url, "https": proxy_url}
                finally:
                    _terminate(proc)
                return
            _terminate(proc)                        # died or port stolen -> retry
        yield None


def _xray_asset_name() -> str | None:
    system = platform.system()
    machine = platform.machine().lower()
    arm = machine in ("arm64", "aarch64")
    if system == "Linux":
        return "Xray-linux-arm64-v8a.zip" if arm else "Xray-linux-64.zip"
    if system == "Darwin":
        return "Xray-macos-arm64-v8a.zip" if arm else "Xray-macos-64.zip"
    if system == "Windows":
        return "Xray-windows-arm64-v8a.zip" if arm else "Xray-windows-64.zip"
    return None


def install_xray() -> str | None:
    asset = _xray_asset_name()
    if asset is None:
        log("ERROR: no known xray release asset for this platform.")
        return None
    version = os.environ.get("XRAY_VERSION", "").strip()
    if version and version.lower() != "latest":
        url = f"https://github.com/XTLS/Xray-core/releases/download/{version}/{asset}"
    else:
        url = f"https://github.com/XTLS/Xray-core/releases/latest/download/{asset}"
    log(f"Installing xray: {url}")
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    data = None
    for attempt in range(1, 4):
        try:
            r = requests.get(url, headers=HEADERS, proxies=FETCH_PROXIES, timeout=(10, 120))
            r.raise_for_status()
            data = r.content
            break
        except Exception as e:
            log(f"  xray download attempt {attempt} failed: {e}")
            if attempt < 3:
                time.sleep(2 * attempt)
    if not data:
        return None
    exe = "xray.exe" if os.name == "nt" else "xray"
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            member = next(n for n in zf.namelist() if Path(n).name == exe)
            target = BIN_DIR / exe
            target.write_bytes(zf.read(member))
        target.chmod(0o755)
    except Exception as e:
        log(f"ERROR: failed to extract xray: {e}")
        return None
    return str(target)


def ensure_xray_ready(auto_install: bool) -> bool:
    global XRAY_BIN, XRAY_VERSION_STR
    cand = os.environ.get("XRAY_BINARY") or XRAY_BIN
    path = shutil.which(cand)
    if path is None and Path(cand).is_file():
        path = str(Path(cand).resolve())
    if path is None:
        local = BIN_DIR / ("xray.exe" if os.name == "nt" else "xray")
        if local.is_file():
            path = str(local)
    if path is None and auto_install:
        path = install_xray()
    if path is None:
        log("ERROR: xray binary not found. Install it, set XRAY_BINARY, or allow auto-install.")
        return False
    try:
        r = subprocess.run([path, "version"], capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            raise RuntimeError((r.stderr or "").strip() or "xray version failed")
        XRAY_VERSION_STR = (r.stdout.splitlines() or ["unknown"])[0]
    except Exception as e:
        log(f"ERROR: xray not usable: {e}")
        return False
    XRAY_BIN = path
    SUMMARY["xray"] = XRAY_VERSION_STR
    log(f"Using {XRAY_VERSION_STR} ({path})")
    return True


def socks_support_available() -> bool:
    try:
        import socks  # noqa: F401
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------- results
@dataclass
class SiteResult:
    ok: bool
    status: str
    category: str        # allowed / blocked / challenge / http_error / unreachable ...
    details: str = ""


@dataclass
class EnrichResult:
    gemini: SiteResult
    country: str | None = None
    dead: bool = False

    @classmethod
    def make_dead(cls, reason: str) -> EnrichResult:
        return cls(SiteResult(False, reason, "proxy_dead"), None, True)


@dataclass
class SpeedResult:
    kbps: float              # KB/s (bytes/1000 per second); 0.0 if nothing arrived
    received: int            # bytes actually downloaded (<= SPEED_TEST_BYTES)
    seconds: float           # wall-clock seconds (incl. connect/TLS setup)
    complete: bool           # full 100 KB arrived within the 3 s cap


@dataclass
class Outcome:
    alive: bool
    enrich: EnrichResult | None = None
    speed: SpeedResult | None = None


# ---------------------------------------------------------------- tests
def endpoint_check(proxies: dict) -> bool:
    """Any expected-status probe passing = alive. One full retry round."""
    for _round in range(ENDPOINT_ROUNDS):
        for url, expected, marker in TEST_ENDPOINTS:
            if STOP.is_set() or deadline_exceeded():
                return False
            try:
                r = requests.get(url, proxies=proxies, timeout=TEST_TIMEOUT,
                                 allow_redirects=False)
            except requests.RequestException:
                continue
            if r.status_code != expected:
                continue
            if marker and marker not in (r.text or "").lower():
                continue
            return True
    return False


def speed_check(proxies: dict) -> SpeedResult:
    """Download 100 KB through the SAME xray session, capped at 3 seconds.

    Called right after the endpoint probe passes (same worker, same session —
    no extra step, no extra concurrency). Partial downloads still count:
    speed = bytes received / elapsed wall-clock time.
    """
    start = time.monotonic()
    received = 0
    try:
        with requests.get(SPEED_TEST_URL, headers=HEADERS, proxies=proxies,
                          timeout=(SPEED_TIMEOUT, SPEED_TIMEOUT), stream=True) as r:
            r.raise_for_status()
            for chunk in r.iter_content(SPEED_CHUNK):
                received += len(chunk)
                if (received >= SPEED_TEST_BYTES
                        or time.monotonic() - start >= SPEED_TIMEOUT
                        or STOP.is_set() or deadline_exceeded()):
                    break
    except requests.RequestException:
        pass                                  # keep whatever bytes arrived
    elapsed = max(time.monotonic() - start, 1e-6)
    received = min(received, SPEED_TEST_BYTES)
    return SpeedResult(
        kbps=(received / 1000.0) / elapsed,
        received=received,
        seconds=elapsed,
        complete=received >= SPEED_TEST_BYTES,
    )


def _normalize_for_match(s: str) -> str:
    return (
        s.replace("\u2018", "'").replace("\u2019", "'")
         .replace("\u02BC", "'").lower()
    )


def _gemini_normalize(body: str) -> str:
    body = unescape(body or "")
    body = body.replace("\\u0027", "'").replace("\\x27", "'").replace("\\u2019", "'")
    return _normalize_for_match(body)


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
            return text[start:end][:BODY_PREVIEW_CHARS]
    return text[:BODY_PREVIEW_CHARS]


def gemini_request(proxies: dict) -> SiteResult:
    try:
        r = requests.get(GEMINI_TEST_URL, headers=GEMINI_HEADERS, proxies=proxies,
                         timeout=GEMINI_TIMEOUT, allow_redirects=True)
    except requests.RequestException as e:
        return SiteResult(False, f"Unreachable: {type(e).__name__}: {e}",
                          "unreachable", f"request_exception={e!r}")
    body = r.text or ""
    norm = _gemini_normalize(body)
    final = urlparse(r.url)
    host = (final.hostname or "").lower()
    fpath = final.path.lower()
    marker = next((m for m in GEMINI_BLOCK_MARKERS
                   if _normalize_for_match(m) in norm), None)
    details = (
        f"HTTP {r.status_code} | final_url={r.url} | "
        f"content_type={r.headers.get('Content-Type', 'unknown')} | "
        f"body_excerpt={_response_excerpt(body, marker)!r}"
    )
    if (host.startswith(("consent.google.", "sorry.google."))
            or fpath.startswith("/sorry") or "unusual traffic" in norm):
        return SiteResult(False, f"Challenge/consent page ({host})", "challenge", details)
    if marker:
        return SiteResult(False, "Geo-blocked", "blocked",
                          details + f" | matched_marker={marker!r}")
    if r.status_code >= 400:
        return SiteResult(False, f"HTTP {r.status_code}", "http_error", details)
    if 200 <= r.status_code < 300:
        return SiteResult(True, f"Allowed (HTTP {r.status_code})", "allowed", details)
    return SiteResult(False, f"Unexpected HTTP {r.status_code}", "other", details)


def geo_lookup(proxies: dict) -> str | None:
    # Primary: Cloudflare trace over HTTPS (no third-party rate limit,
    # and a malicious exit cannot fake it like plaintext ip-api).
    try:
        r = requests.get(GEO_TRACE_URL, proxies=proxies, timeout=GEO_TIMEOUT)
        if r.status_code == 200:
            fields = dict(ln.split("=", 1) for ln in r.text.splitlines() if "=" in ln)
            cc = (fields.get("loc") or "").strip().upper()
            if len(cc) == 2 and cc.isalpha():
                return cc
    except requests.RequestException:
        pass
    try:
        r = requests.get(GEO_FALLBACK_URL, proxies=proxies, timeout=GEO_TIMEOUT)
        if r.status_code == 200:
            lines = [ln.strip() for ln in r.text.strip().splitlines()]
            if len(lines) >= 2 and lines[0].lower() == "success":
                cc = lines[1].upper()
                if len(cc) == 2 and cc.isalpha():
                    return cc
    except requests.RequestException:
        pass
    return None


def enrich_with_proxies(proxies: dict) -> EnrichResult:
    gemini = gemini_request(proxies)
    country = geo_lookup(proxies)
    return EnrichResult(gemini, country)


def test_worker(p: dict, do_endpoint: bool, do_enrich: bool) -> Outcome:
    _check_stop()
    with xray_proxy(p) as proxies:
        if proxies is None:
            _check_stop()
            return Outcome(False, EnrichResult.make_dead("Proxy startup failed")
                           if do_enrich else None)
        speed: SpeedResult | None = None
        if do_endpoint:
            if not endpoint_check(proxies):
                return Outcome(False)
            # 100 KB / 3 s speed probe: SAME xray session, SAME worker.
            # Part of step 2 — not an extra step, no extra concurrency.
            speed = speed_check(proxies)
        elif do_enrich:
            # Enrich-only mode: cheap liveness probe so dead nodes get DEAD,
            # not a misleading NOGEMINI.
            if not endpoint_check(proxies):
                return Outcome(False, EnrichResult.make_dead("Endpoint probe failed"))
        if not do_enrich:
            return Outcome(True, speed=speed)
        try:
            res = enrich_with_proxies(proxies)      # same session as step 2
        except Exception as e:
            res = EnrichResult(SiteResult(False, f"Test exception: {type(e).__name__}: {e}",
                                          "other"))
        return Outcome(True, res, speed)


# ---------------------------------------------------------------- progress / io
def _render_bar(prefix: str, done: int, total: int, start: float, extra: str) -> None:
    pct = done / total if total else 1.0
    filled = int(30 * pct)
    bar = "█" * filled + "░" * (30 - filled)
    elapsed = time.time() - start
    eta = (elapsed / done) * (total - done) if done else 0.0
    if not IS_TTY:
        if done % 50 == 0 or done == total:
            print(f"  {prefix} {done}/{total}  {extra}", flush=True)
        return
    sys.stdout.write(
        f"\r  {prefix} [{bar}] {done}/{total} ({pct * 100:5.1f}%)  {extra}  ETA {eta:4.0f}s\x1b[K"
    )
    sys.stdout.flush()


def _endline() -> None:
    if IS_TTY:
        sys.stdout.write("\n")
        sys.stdout.flush()


def _write(path: Path, uris: list[str]) -> None:
    path.write_text("\n".join(uris) + ("\n" if uris else ""), encoding="utf-8")


class LineWriter:
    """Incremental, crash-safe output. Flush per line, fsync once on close."""

    def __init__(self, path: Path):
        self._f = path.open("w", encoding="utf-8", newline="\n")

    def write(self, line: str) -> None:
        self._f.write(line + "\n")
        self._f.flush()

    def __enter__(self) -> LineWriter:
        return self

    def __exit__(self, *exc) -> bool:
        try:
            self._f.flush()
            os.fsync(self._f.fileno())
        finally:
            self._f.close()
        return False


def _write_speed_log(path: Path, entries: list[tuple[str, SpeedResult]]) -> None:
    ordered = sorted(entries, key=lambda t: t[1].kbps, reverse=True)   # fastest first
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for i, (uri, s) in enumerate(ordered, 1):
            state = "full" if s.complete else ("partial, 3s cap" if s.received else "no data")
            f.write(f"[{i}] {s.kbps:9.1f} KB/s  {s.received:6d}/{SPEED_TEST_BYTES} B  "
                    f"{s.seconds:4.2f}s  {state}\n")
            f.write(f"URI: {uri}\n")
            f.write("-" * 80 + "\n")


def _write_enrich_diagnostics(path: Path,
                              entries: list[tuple[str, EnrichResult, SpeedResult | None]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for i, (uri, res, speed) in enumerate(entries, 1):
            f.write(f"[{i}] URI: {uri}\n")
            f.write(f"Country: {res.country or 'unknown'}\n")
            if speed is not None:
                state = "full" if speed.complete else ("partial, 3s cap" if speed.received else "no data")
                f.write(f"Speed: {speed.kbps:.1f} KB/s "
                        f"({speed.received}/{SPEED_TEST_BYTES} B in {speed.seconds:.2f}s, {state})\n")
            if res.dead:
                f.write(f"DEAD: {res.gemini.status}\n")
            else:
                f.write(f"Gemini: {res.gemini.status} [{res.gemini.category}]\n")
                f.write(f"Gemini details: {res.gemini.details}\n")
            f.write("-" * 80 + "\n")


def write_summary_files(duration_s: float) -> None:
    SUMMARY["duration_s"] = round(duration_s, 1)
    SUMMARY["timestamp_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        (LOG_DIR / "summary.json").write_text(
            json.dumps(SUMMARY, indent=2, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass
    gh = os.environ.get("GITHUB_STEP_SUMMARY")
    if not gh:
        return
    lines = ["## Proxy pipeline", "",
             f"- Steps: `{SUMMARY.get('steps')}`",
             f"- Xray: `{SUMMARY.get('xray', 'n/a')}`",
             f"- Duration: {SUMMARY['duration_s']}s", ""]
    src = SUMMARY.get("source")
    if src:
        lines += [f"**Source:** {src['unique']} unique / {src['raw']} raw configs"
                  f" ({src['failed_urls']} URLs failed)", ""]
    ep = SUMMARY.get("endpoint")
    if ep:
        lines += ["### Endpoint test", "",
                  "| PASS | FAIL | Unsupported | Skipped |", "|---|---|---|---|",
                  f"| {ep['pass']} | {ep['fail']} | {ep['unsupported']} | {ep['skipped']} |", ""]
    sp = SUMMARY.get("speed")
    if sp:
        lines += ["### Download speed (100 KB, 3 s cap)", "",
                  f"- Tested: {sp['tested']} | Full: {sp['complete']} | No data: {sp['no_data']}",
                  f"- Avg: {sp['avg_kbps']} KB/s | Median: {sp['median_kbps']} KB/s "
                  f"| Max: {sp['max_kbps']} KB/s", ""]
    en = SUMMARY.get("enrich")
    if en:
        g = en["gemini"]
        lines += ["### Enrich", "",
                  "| GEMINI | NOGEMINI | GEMERR | DEAD |", "|---|---|---|---|",
                  f"| {g['GEMINI']} | {g['NOGEMINI']} | {g['GEMERR']} | {en['dead']} |", ""]
    try:
        with open(gh, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except OSError:
        pass


# ---------------------------------------------------------------- interactive (local only)
def prompt_steps() -> set[int] | None:
    print("\nSelect steps (combine with '+'):")
    print("  1 = Fetch / custom file (source)")
    print("  2 = Endpoint Test")
    print("  3 = Enrich (Gemini + Geo)")
    print("\nExamples: 1  |  1+2  |  1+2+3")
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
    print("\nSource:")
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
    print(f"\nCustom config file (.txt). Looked up in:\n  {SCRIPT_DIR}")
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

    results: dict[str, tuple[bool, str]] = {}
    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as ex:
        futs = {ex.submit(fetch_with_retries, u): u for u in urls}
        for f in as_completed(futs):
            results[futs[f]] = f.result()

    raw_uris: list[str] = []
    failures: list[tuple[str, str]] = []
    for url in urls:
        ok, content = results[url]
        if not ok:
            failures.append((url, content))
            log(f"[Step 1]   FAILED {url}: {content}")
            continue
        extracted = extract_configs(normalize_to_text(content))
        log(f"[Step 1]   {len(extracted):5d} configs  {url}")
        raw_uris.extend(extracted)

    unique, skipped = parse_and_dedupe(raw_uris)
    log(f"[Step 1] Total: {len(raw_uris)}  Unique: {len(unique)}")
    if skipped:
        log("[Step 1]   Skipped: " + ", ".join(f"{k}={v}" for k, v in skipped.most_common()))
    if any("(parse failed)" in k for k in skipped):
        log(f"[Step 1]   Parse-failure samples: {LOG_DIR / 'parse_failed.txt'}")
    _write(ALIVE_DIR / "all.txt", [u for u, _ in unique])
    log(f"[Step 1] Saved: {ALIVE_DIR / 'all.txt'}")

    if failures:
        fail_log = LOG_DIR / "failed.txt"
        with fail_log.open("w", encoding="utf-8", newline="\n") as f:
            for i, (url, err) in enumerate(failures, 1):
                f.write(f"[{i}] {url}\nERROR: {err}\n{'-' * 80}\n")
        log(f"[Step 1] Saved failure log: {fail_log}")

    SUMMARY["source"] = {"urls": len(urls), "failed_urls": len(failures),
                         "raw": len(raw_uris), "unique": len(unique),
                         "skipped": dict(skipped)}
    return unique


def run_source_custom(path: Path) -> list[tuple[str, dict]] | None:
    log(f"[Step 1] Custom config file: {path}")
    configs, skipped = load_configs_from_file(path)
    log(f"[Step 1] Loaded {len(configs)} unique configs")
    if skipped:
        log(f"[Step 1]   Skipped: " + ", ".join(f"{k}={v}" for k, v in skipped.most_common()))
    if any("(parse failed)" in k for k in skipped):
        log(f"[Step 1]   Parse-failure samples: {LOG_DIR / 'parse_failed.txt'}")
    _write(ALIVE_DIR / "all.txt", [u for u, _ in configs])
    log(f"[Step 1] Saved: {ALIVE_DIR / 'all.txt'}")
    SUMMARY["source"] = {"custom_file": str(path), "raw": len(configs),
                         "unique": len(configs), "failed_urls": 0,
                         "skipped": dict(skipped)}
    return configs


def run_tests(configs: list[tuple[str, dict]], do_endpoint: bool, do_enrich: bool,
              args: argparse.Namespace) -> list[tuple[str, dict]] | None:
    label = ("Step 2+3" if do_endpoint and do_enrich
             else "Step 2" if do_endpoint else "Step 3")
    log(f"[{label}] " + ("Endpoint test + speed probe + Enrich (shared xray sessions)"
                         if do_endpoint and do_enrich
                         else "Endpoint Test + speed probe" if do_endpoint
                         else "Enrich (Gemini + Geo)"))
    testable = [(u, p) for u, p in configs if build_outbound(p) is not None]
    unsupported = len(configs) - len(testable)
    if unsupported:
        log(f"[{label}]   {unsupported} configs skipped (unsupported protocol/network/plugin)")
    if not testable:
        log(f"[{label}] Nothing testable.")
        return []

    log(f"[{label}] Testing {len(testable)} configs (workers={args.workers})...")

    passed_pairs: list[tuple[str, dict]] = []
    enriched_pairs: list[tuple[str, dict]] = []
    diag_entries: list[tuple[str, EnrichResult, SpeedResult | None]] = []
    speed_entries: list[tuple[str, SpeedResult]] = []
    passed = failed = skipped_budget = dead = idx = 0
    speed_sum = 0.0
    speed_n = 0
    gtags: Counter = Counter()
    start = time.time()

    with ExitStack() as stack:
        ww = stack.enter_context(LineWriter(ALIVE_DIR / "working.txt")) if do_endpoint else None
        ew = stack.enter_context(LineWriter(ALIVE_DIR / "enriched.txt")) if do_enrich else None
        ex = stack.enter_context(ThreadPoolExecutor(max_workers=args.workers))
        futures = {ex.submit(test_worker, p, do_endpoint, do_enrich): (uri, p)
                   for uri, p in testable}
        done = 0
        try:
            for fut in as_completed(futures):
                done += 1
                uri, p = futures[fut]
                try:
                    outcome = fut.result()
                except TaskSkipped:
                    if skipped_budget == 0:
                        _endline()
                        log(f"[{label}] Stop/time-budget reached — skipping remaining configs.")
                    skipped_budget += 1
                except Exception as e:
                    failed += 1
                    _endline()
                    log(f"[{label}]   ERR {uri[:70]}: {e}")
                else:
                    if outcome.speed is not None:
                        speed_entries.append((uri, outcome.speed))
                        if outcome.speed.received > 0:
                            speed_sum += outcome.speed.kbps
                            speed_n += 1
                    if do_endpoint:
                        if outcome.alive:
                            passed += 1
                            passed_pairs.append((uri, p))
                            ww.write(uri)
                        else:
                            failed += 1
                    if (do_enrich and outcome.enrich is not None
                            and (outcome.alive or not do_endpoint)):
                        res = outcome.enrich
                        idx += 1
                        remark = build_enriched_remark(res, idx, outcome.speed)
                        new_uri = set_remark(uri, remark, p["protocol"])
                        new_p = dict(p)
                        new_p["remark"] = remark
                        enriched_pairs.append((new_uri, new_p))
                        ew.write(new_uri)
                        diag_entries.append((uri, res, outcome.speed))
                        if res.dead:
                            dead += 1
                        else:
                            gtags[gemini_tag(res.gemini)] += 1
                extra_parts = []
                if do_endpoint:
                    extra_parts.append(f"PASS {passed} FAIL {failed}")
                if do_enrich:
                    extra_parts.append(f"Gem:{gtags['GEMINI']} Dead:{dead}")
                if speed_n:
                    extra_parts.append(f"Avg {speed_sum / speed_n:.0f}KB/s")
                if skipped_budget:
                    extra_parts.append(f"SKIP {skipped_budget}")
                _render_bar(label, done, len(testable), start, "  ".join(extra_parts))
        except KeyboardInterrupt:
            STOP.set()
            _endline()
            log(f"[{label}] Interrupted — cancelling queued tasks; "
                "running ones finish within their timeouts.")
            ex.shutdown(wait=False, cancel_futures=True)
    _endline()

    elapsed = time.time() - start
    if do_endpoint:
        log(f"[{label}] Endpoint: PASS {passed}  FAIL {failed}  "
            f"UNSUPPORTED {unsupported}  SKIPPED {skipped_budget}  ({elapsed:.0f}s)")
        log(f"[{label}] Saved: {ALIVE_DIR / 'working.txt'}")
        SUMMARY["endpoint"] = {"pass": passed, "fail": failed,
                               "unsupported": unsupported, "skipped": skipped_budget}
    if speed_entries:
        speed_path = LOG_DIR / "speed_test.txt"
        _write_speed_log(speed_path, speed_entries)
        oks = [s.kbps for _, s in speed_entries if s.received > 0]
        full = sum(1 for _, s in speed_entries if s.complete)
        no_data = sum(1 for _, s in speed_entries if s.received == 0)
        SUMMARY["speed"] = {
            "tested": len(speed_entries), "complete": full, "no_data": no_data,
            "avg_kbps": round(statistics.mean(oks), 1) if oks else 0.0,
            "median_kbps": round(statistics.median(oks), 1) if oks else 0.0,
            "max_kbps": round(max(oks), 1) if oks else 0.0,
        }
        sp = SUMMARY["speed"]
        log(f"[{label}] Speed (100KB/3s): avg {sp['avg_kbps']}  median {sp['median_kbps']}  "
            f"max {sp['max_kbps']} KB/s  |  full {full}/{len(speed_entries)}  no-data {no_data}")
        log(f"[{label}] Speed log: {speed_path}")
    if do_enrich:
        diag_path = LOG_DIR / "enrich_checks.txt"
        _write_enrich_diagnostics(diag_path, diag_entries)
        log(f"[{label}] Gemini: GEMINI {gtags['GEMINI']}  NOGEMINI {gtags['NOGEMINI']}  "
            f"GEMERR {gtags['GEMERR']}  |  DEAD {dead}  ({elapsed:.0f}s)")
        log(f"[{label}] Saved: {ALIVE_DIR / 'enriched.txt'}  ({len(enriched_pairs)} configs)")
        log(f"[{label}] Diagnostics: {diag_path}")
        SUMMARY["enrich"] = {
            "gemini": {k: gtags[k] for k in ("GEMINI", "NOGEMINI", "GEMERR")},
            "dead": dead, "skipped": skipped_budget,
        }
    return enriched_pairs if do_enrich else passed_pairs


# ---------------------------------------------------------------- pipeline
def resolve_steps(args: argparse.Namespace) -> set[int] | None:
    raw = args.steps or os.environ.get("PROXY_STEPS")
    if raw:
        try:
            steps = _parse_steps(raw)
        except ValueError as e:
            log(f"ERROR: {e}")
            return None
    elif IS_TTY and not IN_CI:
        steps = prompt_steps()
        if steps is None:
            log("No steps given — exiting.")
            return None
    elif IN_CI:
        steps = {STEP_SOURCE, STEP_ENDPOINT, STEP_ENRICH}
        log("CI detected, no --steps given — defaulting to 1+2+3.")
    else:
        log("Non-interactive and no --steps given.")
        log("Example:  python proxy_pipeline.py --steps '1+2+3'")
        return None
    if steps & {STEP_ENDPOINT, STEP_ENRICH} and STEP_SOURCE not in steps:
        log("ERROR: a source step (1) is required when running tests.")
        return None
    return steps


def run_pipeline(args: argparse.Namespace, steps: set[int]) -> int:
    global FETCH_PROXIES, ALLOW_INSECURE, DEADLINE
    ensure_dirs()
    pipeline_start = time.time()
    SUMMARY["steps"] = sorted(steps)

    fetch_proxy = args.fetch_proxy or os.environ.get("FETCH_PROXY") or ""
    if fetch_proxy:
        FETCH_PROXIES = {"http": fetch_proxy, "https": fetch_proxy}
        log(f"Fetch proxy: {fetch_proxy}")
    ALLOW_INSECURE = args.allow_insecure
    if args.time_budget and args.time_budget > 0:
        DEADLINE = time.monotonic() + args.time_budget * 60
        log(f"Time budget: {args.time_budget:g} minutes")

    # ---- Step 1: source ----
    if args.custom_file:
        path = Path(args.custom_file)
        if not path.exists():
            path = SCRIPT_DIR / args.custom_file
        if not path.exists():
            log(f"ERROR: custom file not found: {args.custom_file}")
            return 1
        loaded = run_source_custom(path)
    elif IS_TTY and not IN_CI and not args.steps:
        choice = prompt_source()
        if choice is None:
            log("Source cancelled — aborting.")
            return 1
        kind, path = choice
        loaded = run_source_fetch() if kind == "fetch" else run_source_custom(path)
    else:
        loaded = run_source_fetch()
    if loaded is None:
        return 1
    if not loaded:
        log("No configs available — aborting (previous outputs left untouched).")
        return 1
    current = loaded

    # ---- Steps 2/3 ----
    if steps & {STEP_ENDPOINT, STEP_ENRICH}:
        if not socks_support_available():
            log("ERROR: SOCKS proxy support is missing.")
            log("       Install it with: python -m pip install 'requests[socks]'")
            return 1
        if not ensure_xray_ready(auto_install=not args.no_install_xray):
            return 1
        result = run_tests(current, STEP_ENDPOINT in steps, STEP_ENRICH in steps, args)
        if result is None:
            return 1
        current = result

    write_summary_files(time.time() - pipeline_start)
    log(f"Pipeline complete. Final configs: {len(current)}")
    return 130 if STOP.is_set() else 0


# ---------------------------------------------------------------- main
def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Proxy config pipeline: source -> endpoint test -> enrich (CI-friendly)."
    )
    parser.add_argument("--steps", default=None,
                        help="Step combo, e.g. '1+2+3'. CI default: 1+2+3. Env: PROXY_STEPS.")
    parser.add_argument("--custom-file", default=None,
                        help="Load this file as the source instead of fetching sub_links.txt.")
    parser.add_argument("--workers", type=int, default=TEST_WORKERS,
                        help=f"Concurrent test workers for steps 2/3 (default {TEST_WORKERS}).")
    parser.add_argument("--time-budget", type=float, default=0,
                        help="Minutes; stop testing gracefully after this (0 = unlimited). "
                             "Set below the job's timeout-minutes so results still get saved.")
    parser.add_argument("--fetch-proxy", default=None,
                        help="Proxy for fetching subscriptions/installing xray, "
                             "e.g. socks5h://127.0.0.1:1080. Env: FETCH_PROXY.")
    parser.add_argument("--allow-insecure", action="store_true",
                        help="Honor allowInsecure=1 links (self-signed certs). "
                             "Off by default; enables MITM-able tests for those nodes.")
    parser.add_argument("--no-install-xray", action="store_true",
                        help="Do not auto-download xray when it is missing.")
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    steps = resolve_steps(args)
    if steps is None:
        return 1
    log(f"Selected steps: {sorted(steps)}")
    try:
        return run_pipeline(args, steps)
    except KeyboardInterrupt:
        STOP.set()
        log("Stopped by user.")
        return 130
    except Exception as e:
        ensure_dirs()
        fatal_log = LOG_DIR / "fatal.txt"          # separate from fetch failed.txt
        fatal_log.write_text(traceback.format_exc(), encoding="utf-8")
        log(f"Fatal error: {e}")
        log(f"Traceback logged to: {fatal_log}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
