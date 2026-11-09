"""
SSRF-safe fetching for the standalone link investigator.

Rules enforced here:
- only http/https
- host must resolve to a public IP (no loopback / private / link-local /
  CGNAT / reserved / multicast ranges, including the 169.254.169.254 cloud
  metadata endpoint)
- every redirect target is validated again before it is fetched
- 5s timeout per request, at most 5 redirect hops
- response bodies are capped at 1 MiB and non-text/attachment responses are
  never downloaded (we only read status/headers for those)
- nothing is ever executed or written to disk
"""

import asyncio
import ipaddress
import re
import socket
import time
from urllib.parse import urljoin, urlparse

import httpx

MAX_REDIRECTS = 5
REQUEST_TIMEOUT = 5.0
MAX_RESPONSE_BYTES = 1024 * 1024  # 1 MiB
USER_AGENT = "GuardianAI-LinkInspector/1.0 (+https://github.com/sarveshdabke/PhishGuard-AI)"

REDIRECT_STATUSES = {301, 302, 303, 307, 308}

# The only paths the passive endpoint-exposure check is allowed to request.
# Nothing else is ever probed: no payloads, no forms, no credentials.
SENSITIVE_PROBE_PATHS = (".env", ".git/HEAD")

# Kept per hop so the website-security checks can report on them without
# issuing any extra request.
SECURITY_RESPONSE_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)

BLOCKED_NETWORKS = [
    ipaddress.ip_network(net)
    for net in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",      # CGNAT
        "127.0.0.0/8",
        "169.254.0.0/16",     # link-local — includes 169.254.169.254 metadata
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",        # multicast
        "240.0.0.0/4",        # reserved
        "::/128",
        "::1/128",
        "100::/64",
        "2001:db8::/32",
        "fc00::/7",           # unique local
        "fe80::/10",          # link-local
        "ff00::/8",           # multicast
    )
]

BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "metadata",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "kubernetes.default",
    "kubernetes.default.svc",
}

BLOCKED_HOST_SUFFIXES = (".localhost", ".local", ".internal", ".localdomain", ".home.arpa")


class SSRFBlockedError(Exception):
    """Raised when a URL points at a non-public destination."""


def _is_blocked_ip(ip) -> tuple[bool, str]:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return _is_blocked_ip(ip.ipv4_mapped)

    for network in BLOCKED_NETWORKS:
        if ip.version == network.version and ip in network:
            return True, f"{ip} is in the blocked range {network}"

    if ip.is_private:
        return True, f"{ip} is a private address"
    if ip.is_loopback:
        return True, f"{ip} is a loopback address"
    if ip.is_link_local:
        return True, f"{ip} is a link-local address"
    if ip.is_multicast:
        return True, f"{ip} is a multicast address"
    if ip.is_reserved:
        return True, f"{ip} is a reserved address"
    if ip.is_unspecified:
        return True, f"{ip} is an unspecified address"

    return False, ""


def _resolve_sync(host: str, timeout: float) -> list[str]:
    """Blocking getaddrinfo; called through asyncio.to_thread."""
    socket.setdefaulttimeout(timeout)
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    addresses = []
    for info in infos:
        address = info[4][0]
        if address not in addresses:
            addresses.append(address)
    return addresses


async def resolve_host(host: str, timeout: float = REQUEST_TIMEOUT) -> list[str]:
    """Resolve a hostname to every address it maps to (bounded by timeout)."""
    try:
        return await asyncio.wait_for(asyncio.to_thread(_resolve_sync, host, timeout), timeout=timeout)
    except (asyncio.TimeoutError, socket.gaierror, OSError, UnicodeError):
        return []


async def validate_target(url: str, timeout: float = REQUEST_TIMEOUT) -> dict:
    """
    Validates a URL before it is fetched.

    Returns {"allowed": bool, "reason": str, "host": str, "ips": [..], "resolved": bool}.
    Raises nothing — callers decide whether a failure is a hard rejection
    (initial URL) or recorded hop evidence (redirect target).
    """
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").strip().rstrip(".").lower()

    if scheme not in {"http", "https"}:
        return {
            "allowed": False, "blocked": True, "resolved": False,
            "reason": f"unsupported scheme '{scheme}'", "host": host, "ips": [],
        }
    if not host:
        return {
            "allowed": False, "blocked": True, "resolved": False,
            "reason": "URL has no hostname", "host": host, "ips": [],
        }

    if host in BLOCKED_HOSTNAMES or host.endswith(BLOCKED_HOST_SUFFIXES):
        return {
            "allowed": False,
            "blocked": True,
            "reason": f"'{host}' is a local/internal hostname",
            "host": host,
            "ips": [],
            "resolved": False,
        }

    literal = host.strip("[]")
    try:
        ip = ipaddress.ip_address(literal)
    except ValueError:
        ip = None

    if ip is not None:
        blocked, reason = _is_blocked_ip(ip)
        if blocked:
            return {
                "allowed": False, "blocked": True, "resolved": True,
                "reason": reason, "host": host, "ips": [str(ip)],
            }
        return {"allowed": True, "blocked": False, "reason": "", "host": host, "ips": [str(ip)], "resolved": True}

    addresses = await resolve_host(host, timeout=timeout)
    if not addresses:
        return {
            "allowed": False,
            "blocked": False,  # DNS failure is evidence, not an SSRF rejection
            "reason": f"'{host}' did not resolve",
            "host": host,
            "ips": [],
            "resolved": False,
        }

    for address in addresses:
        blocked, reason = _is_blocked_ip(ipaddress.ip_address(address))
        if blocked:
            return {
                "allowed": False,
                "blocked": True,
                "reason": f"'{host}' resolves to a non-public address — {reason}",
                "host": host,
                "ips": addresses,
                "resolved": True,
            }

    return {"allowed": True, "blocked": False, "reason": "", "host": host, "ips": addresses, "resolved": True}


def _extract_title(body: bytes, content_type: str) -> str | None:
    if "html" not in (content_type or "").lower():
        return None
    match = re.search(rb"<title[^>]*>(.*?)</title>", body[:200_000], re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    title = match.group(1).decode("utf-8", errors="ignore")
    title = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", title)).strip()
    return title[:200] or None


async def _safe_get(
    url: str,
    timeout: float,
    max_bytes: int,
    capture_prefix: bool = False,
) -> dict:
    """One redirect-free GET with a hard body-size cap. Never raises.

    ``capture_prefix`` keeps the first 512 bytes of the body so a caller can
    tell a real sensitive file apart from a catch-all HTML page.
    """
    hop = {
        "url": url,
        "status": None,
        "content_type": None,
        "location": None,
        "bytes_read": 0,
        "truncated": False,
        "title": None,
        "server": None,
        "headers": {},
        "body_prefix": "",
        "error": None,
    }
    started = time.monotonic()

    try:
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=httpx.Timeout(timeout, connect=timeout, read=timeout),
            verify=True,
            headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"},
        ) as client:
            async with client.stream("GET", url) as response:
                hop["status"] = response.status_code
                hop["content_type"] = response.headers.get("content-type")
                hop["location"] = response.headers.get("location")
                hop["server"] = response.headers.get("server")
                hop["headers"] = {
                    name: response.headers[name]
                    for name in SECURITY_RESPONSE_HEADERS
                    if name in response.headers
                }

                disposition = (response.headers.get("content-disposition") or "").lower()
                content_type = (hop["content_type"] or "").lower()
                is_download = "attachment" in disposition or not (
                    content_type.startswith("text/")
                    or "html" in content_type
                    or "json" in content_type
                    or "xml" in content_type
                    or content_type == ""
                )

                if response.status_code in REDIRECT_STATUSES or is_download:
                    # Redirect bodies and file downloads are never read.
                    hop["skipped_body_reason"] = (
                        "redirect" if response.status_code in REDIRECT_STATUSES else "non-text/attachment content"
                    )
                else:
                    chunks = []
                    total = 0
                    async for chunk in response.aiter_bytes():
                        remaining = max_bytes - total
                        if remaining <= 0:
                            hop["truncated"] = True
                            break
                        if len(chunk) > remaining:
                            chunks.append(chunk[:remaining])
                            total += remaining
                            hop["truncated"] = True
                            break
                        chunks.append(chunk)
                        total += len(chunk)
                    hop["bytes_read"] = total
                    body = b"".join(chunks)
                    hop["title"] = _extract_title(body, content_type)
                    if capture_prefix:
                        hop["body_prefix"] = body[:512].decode("utf-8", errors="ignore")

    except httpx.TimeoutException:
        hop["error"] = f"timed out after {timeout:g}s"
    except httpx.TooManyRedirects:
        hop["error"] = "too many redirects"
    except httpx.HTTPError as exc:
        hop["error"] = f"request failed ({type(exc).__name__}): {str(exc)[:160]}"
    except Exception as exc:  # never let a fetch crash the investigation
        hop["error"] = f"unexpected error ({type(exc).__name__}): {str(exc)[:160]}"
    finally:
        hop["elapsed_ms"] = int((time.monotonic() - started) * 1000)

    return hop


def _decode_prefix(prefix: str) -> str:
    return (prefix or "").lstrip("\ufeff \t\r\n")


def _looks_like_sensitive_file(path: str, prefix: str) -> bool:
    """Does this body actually look like the file we asked for?"""
    text = _decode_prefix(prefix)
    if not text:
        return False

    if path == ".git/HEAD":
        return bool(re.match(r"^(ref:\s*refs/|[0-9a-f]{40}\b)", text, re.IGNORECASE))

    # A .env is KEY=VALUE text. Anything that starts like markup is a catch-all page.
    lines = [line.strip() for line in text.splitlines()[:5] if line.strip()]
    if not lines or lines[0].startswith("<"):
        return False
    return any("=" in line and not line.startswith("<") for line in lines)


async def probe_sensitive_paths(
    base_url: str,
    timeout: float = REQUEST_TIMEOUT,
    max_bytes: int = 64 * 1024,
) -> list[dict]:
    """
    Passive existence check for at most two well-known paths on the target host.

    Only a plain GET is issued, redirects are never followed, and every URL is
    validated by the SSRF guard first. A 200 counts as exposed only when the
    body actually looks like the requested file: many sites (and WAFs) answer
    unknown paths with a 200 HTML page, which is a cover page, not a leak.
    """
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    results: list[dict] = []

    for path in SENSITIVE_PROBE_PATHS:
        url = f"{origin}/{path}"
        validation = await validate_target(url, timeout=timeout)
        if not validation["allowed"]:
            results.append(
                {
                    "path": f"/{path}",
                    "url": url,
                    "status": None,
                    "exposed": False,
                    "bytes_read": 0,
                    "content_type": None,
                    "error": validation["reason"],
                }
            )
            continue

        hop = await _safe_get(
            url, timeout=timeout, max_bytes=max_bytes, capture_prefix=True
        )
        status = hop.get("status")
        bytes_read = hop.get("bytes_read") or 0
        prefix = hop.get("body_prefix") or ""
        content_type = (hop.get("content_type") or "").lower()

        head = _decode_prefix(prefix)[:200].lower()
        looks_html = "html" in content_type or head.startswith("<!") or head.startswith("<html") or "<html" in head
        matches_file = _looks_like_sensitive_file(path, prefix)

        note = None
        if status is not None and status != 200:
            note = f"HTTP {status} - not exposed"
        elif looks_html:
            note = "HTTP 200 but an HTML page was returned (catch-all or WAF rejection) - not exposed"
        elif not matches_file:
            note = "HTTP 200 but the body does not look like the expected file - not exposed"

        results.append(
            {
                "path": f"/{path}",
                "url": url,
                "status": status,
                "exposed": status == 200 and bytes_read > 0 and not looks_html and matches_file,
                "bytes_read": bytes_read,
                "content_type": hop.get("content_type"),
                "error": hop.get("error"),
                "note": note,
            }
        )

    return results


async def fetch_redirect_chain(
    url: str,
    max_hops: int = MAX_REDIRECTS,
    timeout: float = REQUEST_TIMEOUT,
    max_bytes: int = MAX_RESPONSE_BYTES,
) -> dict:
    """
    Follows redirects manually so every hop can be validated (SSRF) and
    recorded. Returns the hop list plus a derived summary.
    """
    hops: list[dict] = []
    visited: list[str] = []
    current = url
    redirects_followed = 0
    limit_exceeded = False
    loop_detected = False
    error = None
    page_title = None

    while True:
        if current in visited:
            loop_detected = True
            error = "redirect loop detected"
            break
        visited.append(current)

        validation = await validate_target(current, timeout=timeout)
        if not validation["allowed"]:
            # A blocked destination is a security finding; a DNS failure is not.
            if validation.get("blocked"):
                hop_error = f"blocked by SSRF guard: {validation['reason']}"
                error = f"redirect target blocked by SSRF guard: {validation['reason']}"
            else:
                hop_error = "hostname did not resolve — fetch skipped"
                error = f"'{validation['host']}' did not resolve"
            hops.append(
                {
                    "hop": len(hops) + 1,
                    "url": current,
                    "status": None,
                    "content_type": None,
                    "location": None,
                    "bytes_read": 0,
                    "truncated": False,
                    "title": None,
                    "server": None,
                    "headers": {},
                    "elapsed_ms": 0,
                    "error": hop_error,
                }
            )
            break

        hop = await _safe_get(current, timeout=timeout, max_bytes=max_bytes)
        hop["hop"] = len(hops) + 1
        hop["resolved_ips"] = validation["ips"]
        hops.append(hop)

        if hop["title"] and not page_title:
            page_title = hop["title"]

        if hop.get("error"):
            error = hop["error"]
            break

        location = hop.get("location")
        if hop["status"] in REDIRECT_STATUSES and location:
            if redirects_followed >= max_hops:
                limit_exceeded = True
                error = f"redirect limit of {max_hops} hops exceeded"
                break
            next_url = urljoin(current, location)
            redirects_followed += 1
            current = next_url
            continue

        break

    final_url = hops[-1]["url"] if hops else url
    final_parsed = urlparse(final_url)
    submitted_parsed = urlparse(url)

    submitted_host = (submitted_parsed.hostname or "").lower()
    final_host = (final_parsed.hostname or "").lower()
    domain_changed = _registered_domain(submitted_host) != _registered_domain(final_host)

    return {
        "hops": hops,
        "hop_count": len(hops),
        "redirect_count": redirects_followed,
        "final_url": final_url,
        "final_host": final_host,
        "submitted_host": submitted_host,
        "domain_changed": domain_changed,
        "scheme_downgrade": submitted_parsed.scheme == "https" and final_parsed.scheme == "http",
        "limit_exceeded": limit_exceeded,
        "loop_detected": loop_detected,
        "page_title": page_title,
        "error": error,
    }


def _registered_domain(host: str) -> str:
    if not host:
        return ""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    from app.services.url_normalizer import split_domain

    return split_domain(host)["registered_domain"].lower()
