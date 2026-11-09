"""
TLS certificate analysis for the standalone link investigator (Module 2).

Everything here is read-only and best-effort:

- the certificate is fetched with a plain ``ssl`` handshake (verification
  disabled only so that *invalid* certificates can still be inspected), then
  parsed with ``cryptography``;
- a second, verifying handshake reports whether the chain is trusted by the
  local trust store (Python's ``ssl`` module only exposes the leaf cert, so
  chain trust is reported from that verification attempt);
- Certificate Transparency is queried from crt.sh, response size capped;
- a match against backend/compromised_cas.json is a critical finding.

No exception ever escapes :func:`analyze_tls` — a failure becomes a recorded
``status`` plus evidence, never a crash and never a fabricated result.
"""

import asyncio
import ipaddress
import json
import socket
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from app.config import settings
from app.services.ssrf_guard import _is_blocked_ip, resolve_host

COMPROMISED_CA_PATH = Path(__file__).resolve().parents[2] / "compromised_cas.json"

# --- scoring (0-100, same scale the rest of the app uses) -------------------
# 60-79 => HIGH ("High Risk"), >= 80 => CRITICAL ("Confirmed Malicious").
TLS_EXPIRED_SCORE = 75
TLS_NOT_YET_VALID_SCORE = 75
TLS_HOSTNAME_MISMATCH_SCORE = 75
TLS_SELF_SIGNED_SCORE = 75
TLS_UNTRUSTED_CHAIN_SCORE = 65
TLS_COMPROMISED_CA_SCORE = 100

#: Mandatory disclaimer shown in the TLS section of every report.
VALID_CERT_NOTE = "A valid certificate does not mean the website is safe"

CT_RECENT_WINDOW_DAYS = 7

STATUS_LABELS = {
    "valid": "valid",
    "expired": "expired",
    "not_yet_valid": "not yet valid",
    "hostname_mismatch": "hostname mismatch",
    "self_signed": "self-signed",
    "untrusted_chain": "untrusted chain",
    "compromised_ca": "compromised CA",
    "no_tls": "no TLS (plain HTTP)",
    "unreachable": "unreachable",
    "blocked": "blocked target",
    "error": "analysis error",
}


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def load_compromised_cas() -> list[dict]:
    try:
        with open(COMPROMISED_CA_PATH, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return [entry for entry in data.get("distrusted_cas", []) if entry.get("name")]
    except (OSError, ValueError):
        return []


# ---------------------------------------------------------------------------
# Certificate parsing
# ---------------------------------------------------------------------------

def _public_key_info(cert: x509.Certificate) -> tuple[str, int | None]:
    try:
        key = cert.public_key()
    except Exception:  # unsupported key type — report, don't crash
        return "unknown", None

    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC ({key.curve.name})", key.key_size
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", 456
    return type(key).__name__, None


def _signature_algorithm(cert: x509.Certificate) -> str:
    try:
        oid = cert.signature_algorithm_oid
        name = getattr(oid, "_name", None) or getattr(oid, "dotted_string", "unknown")
    except Exception:
        return "unknown"
    try:
        hash_alg = cert.signature_hash_algorithm
        if hash_alg is not None:
            return f"{name} ({hash_alg.name})"
    except Exception:
        pass
    return name


def _san_entries(cert: x509.Certificate) -> tuple[list[str], list[str]]:
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
    except x509.ExtensionNotFound:
        return [], []
    dns_names = [str(name) for name in san.get_values_for_type(x509.DNSName)]
    ip_addresses = [str(address) for address in san.get_values_for_type(x509.IPAddress)]
    return dns_names, ip_addresses


def _matches_name(pattern: str, host: str) -> bool:
    pattern = pattern.strip().lower().rstrip(".")
    host = host.strip().lower().rstrip(".")
    if not pattern or not host:
        return False
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        # RFC 6125: a wildcard covers exactly one label
        return host.count(".") == suffix.count(".") + 1 and host.endswith("." + suffix)
    return False


def hostname_matches(host: str, cert: x509.Certificate) -> tuple[bool, str | None]:
    """Returns (matches, the SAN/CN value that matched)."""
    dns_names, ip_addresses = _san_entries(cert)

    try:
        literal = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        literal = None

    if literal is not None:
        for address in ip_addresses:
            try:
                if ipaddress.ip_address(address) == literal:
                    return True, address
            except ValueError:
                continue
        return False, None

    for name in dns_names:
        if _matches_name(name, host):
            return True, name

    if not dns_names:
        for attribute in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            if _matches_name(str(attribute.value), host):
                return True, str(attribute.value)

    return False, None


def _issuer_identifiers(cert: x509.Certificate) -> list[str]:
    values = {cert.issuer.rfc4514_string()}
    for attribute in cert.issuer:
        if attribute.value:
            values.add(str(attribute.value))
    return [value for value in values if value]


def match_compromised_ca(cert: x509.Certificate) -> dict | None:
    identifiers = [value.lower() for value in _issuer_identifiers(cert)]
    for entry in load_compromised_cas():
        needle = entry["name"].lower()
        if any(needle in identifier for identifier in identifiers):
            return entry
    return None


def certificate_summary(cert: x509.Certificate) -> dict:
    not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(
        tzinfo=timezone.utc
    )
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(
        tzinfo=timezone.utc
    )
    key_type, key_bits = _public_key_info(cert)
    dns_names, ip_addresses = _san_entries(cert)

    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "issuer_common_name": next(
            (str(a.value) for a in cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)),
            None,
        ),
        "issuer_organization": next(
            (str(a.value) for a in cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)),
            None,
        ),
        "serial_number": format(cert.serial_number, "x"),
        "not_before": _iso(not_before),
        "not_after": _iso(not_after),
        "signature_algorithm": _signature_algorithm(cert),
        "public_key_type": key_type,
        "public_key_bits": key_bits,
        "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
        "san": dns_names[:24],
        "san_ip": ip_addresses[:8],
        "san_count": len(dns_names) + len(ip_addresses),
    }


def summarize_certificate(
    host: str,
    der: bytes,
    *,
    chain_trusted: bool | None,
    verify_error: str | None,
    protocol: str | None = None,
    cipher: str | None = None,
    now: datetime | None = None,
) -> dict:
    """
    Builds the TLS section from raw certificate bytes.

    Pure function (no network) so the scoring rules are testable offline.
    """
    now = now or datetime.now(timezone.utc)
    cert = x509.load_der_x509_certificate(der)
    certificate = certificate_summary(cert)

    not_before = datetime.fromisoformat(certificate["not_before"].replace("Z", "+00:00"))
    not_after = datetime.fromisoformat(certificate["not_after"].replace("Z", "+00:00"))

    expired = now > not_after
    not_yet_valid = now < not_before
    self_signed = cert.issuer == cert.subject
    matched, matched_value = hostname_matches(host, cert)
    compromised = match_compromised_ca(cert)

    days_remaining = None
    if not expired:
        days_remaining = max(0, (not_after - now).days)

    findings: list[dict] = []

    def finding(kind: str, severity: str, evidence: str, detail: str = "") -> None:
        findings.append(
            {"type": kind, "severity": severity, "evidence": evidence, "detail": detail}
        )

    if compromised:
        finding(
            "compromised_ca",
            "critical",
            "issued by a known compromised or distrusted CA",
            f"Issuer matches '{compromised['name']}' — {compromised.get('reason', '')}".strip(),
        )

    if expired:
        finding(
            "expired",
            "high",
            f"Certificate expired on {_iso(not_after)} ({abs((now - not_after).days)} day(s) ago)",
            "An expired certificate means the HTTPS session cannot be authenticated.",
        )
    elif not_yet_valid:
        finding(
            "not_yet_valid",
            "high",
            f"Certificate is not valid before {_iso(not_before)}",
            "A certificate that is not yet valid cannot be trusted.",
        )

    if not matched:
        san_preview = ", ".join(certificate["san"][:4]) or "none"
        finding(
            "hostname_mismatch",
            "high",
            f"Certificate is not valid for '{host}' (SAN: {san_preview})",
            "The name you are visiting is not covered by the certificate — typical of "
            "shared hosting or an interception proxy.",
        )

    if self_signed:
        finding(
            "self_signed",
            "high",
            "Self-signed certificate (issuer equals subject; no trusted CA vouches for it)",
            "Self-signed certificates are used by interception proxies and throwaway "
            "phishing infrastructure.",
        )
    elif chain_trusted is False:
        finding(
            "untrusted_chain",
            "high" if verify_error and "expired" in verify_error.lower() else "medium",
            f"Certificate chain is not trusted by the local trust store ({verify_error or 'verification failed'})",
            "The leaf certificate may be genuine but the chain cannot be validated.",
        )

    # Status precedence: the most severe finding names the section status.
    severity_order = ["critical", "high", "medium", "low", "info"]
    status = "valid"
    score = 0
    primary = None
    if findings:
        primary = sorted(
            findings, key=lambda item: severity_order.index(item["severity"])
        )[0]
        status = primary["type"]
        if status == "expired":
            score = TLS_EXPIRED_SCORE
        elif status == "not_yet_valid":
            score = TLS_NOT_YET_VALID_SCORE
        elif status == "hostname_mismatch":
            score = TLS_HOSTNAME_MISMATCH_SCORE
        elif status == "self_signed":
            score = TLS_SELF_SIGNED_SCORE
        elif status == "compromised_ca":
            score = TLS_COMPROMISED_CA_SCORE
        elif status == "untrusted_chain":
            score = TLS_UNTRUSTED_CHAIN_SCORE

    if status != "valid" and compromised:
        # compromised CA always outranks every other TLS defect
        status = "compromised_ca"
        score = TLS_COMPROMISED_CA_SCORE

    return {
        "status": status,
        "status_label": STATUS_LABELS.get(status, status),
        "certificate": {
            **certificate,
            "expired": expired,
            "not_yet_valid": not_yet_valid,
            "self_signed": self_signed,
            "days_remaining": days_remaining,
        },
        "hostname": {
            "matches": matched,
            "matched_value": matched_value,
            "checked_host": host,
        },
        "chain": {
            "trusted": chain_trusted,
            "verification_error": verify_error,
            "protocol": protocol,
            "cipher": cipher,
            "note": (
                "Python's ssl module exposes only the leaf certificate; chain trust is "
                "reported from a verification handshake against the local trust store."
            ),
        },
        "compromised_ca": (
            {"matched": True, "name": compromised["name"], "reason": compromised.get("reason", "")}
            if compromised
            else {"matched": False, "name": None, "reason": None}
        ),
        "findings": findings,
        "score": score,
        "note": VALID_CERT_NOTE,
    }


# ---------------------------------------------------------------------------
# Network: certificate fetch + chain verification
# ---------------------------------------------------------------------------

def _fetch_leaf_blocking(
    host: str, address: str, port: int, timeout: float
) -> tuple[bytes, str | None, str | None]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((address, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls_socket:
            der = tls_socket.getpeercert(binary_form=True)
            protocol = tls_socket.version()
            cipher = tls_socket.cipher()
            cipher_name = f"{cipher[0]} ({cipher[2]} bits)" if cipher else None
            return der, protocol, cipher_name


def _verify_blocking(host: str, address: str, port: int, timeout: float) -> tuple[bool | None, str | None]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((address, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host):
                return True, None
    except ssl.SSLCertVerificationError as exc:
        message = getattr(exc, "verify_message", None) or str(exc)
        return False, str(message)[:240]
    except ssl.SSLError as exc:
        return None, f"TLS error: {str(exc)[:200]}"
    except (socket.timeout, TimeoutError):
        return None, f"verification handshake timed out after {timeout:g}s"
    except OSError as exc:
        return None, f"verification handshake failed: {str(exc)[:200]}"


def _pick_address(host: str, addresses: list[str]) -> str | None:
    """First public address, IPv4 preferred (IPv6-only stacks are not universal)."""
    public_v4: list[str] = []
    public_v6: list[str] = []
    for address in addresses:
        try:
            literal = ipaddress.ip_address(address)
        except ValueError:
            continue
        blocked, _ = _is_blocked_ip(literal)
        if blocked:
            continue
        (public_v4 if literal.version == 4 else public_v6).append(address)
    if public_v4:
        return public_v4[0]
    if public_v6:
        return public_v6[0]
    return None


# ---------------------------------------------------------------------------
# Certificate Transparency (crt.sh)
# ---------------------------------------------------------------------------

def summarize_ct_rows(rows: list[dict], domain: str, *, truncated: bool = False) -> dict:
    """Pure CT summary — kept separate so it is testable without network."""
    seen: dict[str, dict] = {}
    for row in rows:
        key = str(row.get("id") or row.get("serial_number") or id(row))
        seen.setdefault(key, row)

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(days=CT_RECENT_WINDOW_DAYS)

    def parse(value):
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    recently_issued = []
    newest = None
    oldest = None
    for row in seen.values():
        not_before = parse(row.get("not_before"))
        if not_before is None:
            continue
        if newest is None or not_before > newest:
            newest = not_before
        if oldest is None or not_before < oldest:
            oldest = not_before
        if not_before >= window_start:
            recently_issued.append(
                {
                    "common_name": row.get("common_name") or row.get("name_value"),
                    "not_before": _iso(not_before),
                    "issuer": (row.get("issuer_name") or "")[:160],
                }
            )

    recently_issued.sort(key=lambda item: item["not_before"] or "", reverse=True)

    return {
        "available": True,
        "query": f"%.{domain}",
        "source": "https://crt.sh/",
        "certificate_count": len(seen),
        "truncated": truncated,
        "count_note": (
            f"at least {len(seen)} (crt.sh response truncated while streaming — the real "
            "count is higher)"
            if truncated
            else f"{len(seen)} certificate(s) found in Certificate Transparency logs"
        ),
        "window_days": CT_RECENT_WINDOW_DAYS,
        "recently_issued_count": len(recently_issued),
        "recently_issued": recently_issued[:5],
        "oldest_not_before": _iso(oldest),
        "newest_not_before": _iso(newest),
        "error": None,
    }


def _parse_ct_payload(text: str) -> tuple[list[dict], bool]:
    text = text.strip()
    if not text:
        return [], False
    if text.endswith("]"):
        try:
            data = json.loads(text)
            return (data if isinstance(data, list) else []), False
        except ValueError:
            pass
    # Response was cut mid-array: keep every complete object we received.
    cut = text.rfind("},")
    if cut != -1:
        try:
            data = json.loads(text[: cut + 1] + "]")
            if isinstance(data, list):
                return data, True
        except ValueError:
            pass
    cut = text.rfind("}")
    if cut != -1:
        try:
            data = json.loads(text[: cut + 1] + "]")
            if isinstance(data, list):
                return data, True
        except ValueError:
            pass
    return [], True


async def check_ct_log(
    domain: str,
    *,
    timeout: float | None = None,
    max_bytes: int | None = None,
    endpoint: str | None = None,
) -> dict:
    """Queries crt.sh for the domain; never raises."""
    timeout = timeout if timeout is not None else settings.LINK_CT_TIMEOUT
    max_bytes = max_bytes if max_bytes is not None else settings.LINK_CT_MAX_BYTES
    endpoint = (endpoint or settings.CT_LOG_URL).rstrip("/")
    query = f"%.{domain}"
    url = f"{endpoint}/?q={quote(query, safe='')}&output=json"

    base = {
        "available": False,
        "query": query,
        "source": "https://crt.sh/",
        "certificate_count": 0,
        "truncated": False,
        "count_note": "Certificate Transparency log not queried",
        "window_days": CT_RECENT_WINDOW_DAYS,
        "recently_issued_count": 0,
        "recently_issued": [],
        "oldest_not_before": None,
        "newest_not_before": None,
        "error": None,
    }

    try:
        chunks: list[bytes] = []
        total = 0
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, connect=min(5.0, timeout)),
            follow_redirects=True,
            headers={"User-Agent": "GuardianAI-LinkInspector/1.0"},
        ) as client:
            async with client.stream("GET", url) as response:
                response.raise_for_status()
                async for chunk in response.aiter_bytes():
                    remaining = max_bytes - total
                    if remaining <= 0:
                        break
                    chunks.append(chunk[:remaining])
                    total += min(len(chunk), remaining)

        rows, truncated = _parse_ct_payload(b"".join(chunks).decode("utf-8", "ignore"))
        if not rows and truncated:
            return {**base, "error": "CT log unavailable: response could not be parsed"}
        return summarize_ct_rows(rows, domain, truncated=truncated)

    except httpx.HTTPStatusError as exc:
        return {**base, "error": f"CT log unavailable: crt.sh returned HTTP {exc.response.status_code}"}
    except httpx.TimeoutException:
        return {**base, "error": f"CT log unavailable: crt.sh timed out after {timeout:g}s"}
    except httpx.RequestError as exc:
        return {**base, "error": f"CT log unavailable: {type(exc).__name__}"}
    except Exception as exc:  # never let a CT lookup break the investigation
        return {**base, "error": f"CT log unavailable: {type(exc).__name__}: {str(exc)[:120]}"}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _section(host: str, url: str, status: str, *, error: str | None = None) -> dict:
    return {
        "analyzed": False,
        "url": url,
        "host": host,
        "port": None,
        "https": status != "no_tls",
        "status": status,
        "status_label": STATUS_LABELS.get(status, status),
        "certificate": None,
        "hostname": {"matches": None, "matched_value": None, "checked_host": host},
        "chain": {
            "trusted": None,
            "verification_error": None,
            "protocol": None,
            "cipher": None,
            "note": None,
        },
        "compromised_ca": {"matched": False, "name": None, "reason": None},
        "ct": {
            "available": False,
            "query": None,
            "source": "https://crt.sh/",
            "certificate_count": 0,
            "truncated": False,
            "count_note": "Certificate Transparency log not queried",
            "window_days": CT_RECENT_WINDOW_DAYS,
            "recently_issued_count": 0,
            "recently_issued": [],
            "oldest_not_before": None,
            "newest_not_before": None,
            "error": None,
        },
        "findings": [],
        "score": 0,
        "note": VALID_CERT_NOTE,
        "error": error,
    }


async def analyze_tls(
    url: str,
    host: str,
    *,
    scheme: str = "https",
    port: int | None = None,
    timeout: float | None = None,
    ct_timeout: float | None = None,
    ct_max_bytes: int | None = None,
    ct_endpoint: str | None = None,
    registered_domain: str | None = None,
) -> dict:
    """Analyses the TLS setup for one submitted URL. Never raises."""
    timeout = timeout if timeout is not None else settings.LINK_TLS_TIMEOUT
    port = port or (443 if scheme == "https" else 80)

    if scheme.lower() != "https":
        section = _section(host, url, "no_tls")
        section["port"] = port
        section["findings"] = [
            {
                "type": "no_tls",
                "severity": "medium",
                "evidence": "no TLS (plain HTTP) — the page is served over unencrypted HTTP",
                "detail": "Traffic can be read and modified in transit; there is no certificate to validate.",
            }
        ]
        return section

    section = _section(host, url, "unreachable")
    section["port"] = port
    section["https"] = True
    ct_task: asyncio.Task | None = None

    try:
        is_ip = False
        try:
            ipaddress.ip_address(host.strip("[]"))
            is_ip = True
        except ValueError:
            pass

        addresses = [host.strip("[]")] if is_ip else await resolve_host(host, timeout=timeout)
        if not addresses:
            section["error"] = f"'{host}' did not resolve — no TLS handshake was attempted"
            section["status"] = "unreachable"
            section["findings"] = [
                {
                    "type": "unreachable",
                    "severity": "medium",
                    "evidence": f"TLS not checked: '{host}' did not resolve",
                    "detail": "Recorded as evidence; no certificate could be retrieved.",
                }
            ]
            return section

        address = _pick_address(host, addresses)
        if address is None:
            section["status"] = "blocked"
            section["error"] = "host resolves only to non-public addresses (blocked by SSRF guard)"
            section["findings"] = [
                {
                    "type": "blocked",
                    "severity": "high",
                    "evidence": "TLS handshake refused: target resolves to a non-public address",
                    "detail": "The SSRF guard blocks loopback, private and link-local destinations.",
                }
            ]
            return section

        domain = registered_domain or host
        if not is_ip:
            # CT is independent of the handshake — run it while the TLS
            # connections are being made so it does not serialise latency.
            ct_task = asyncio.create_task(
                check_ct_log(
                    domain, timeout=ct_timeout, max_bytes=ct_max_bytes, endpoint=ct_endpoint
                )
            )

        der, protocol, cipher = await asyncio.wait_for(
            asyncio.to_thread(_fetch_leaf_blocking, host, address, port, timeout),
            timeout=timeout + 1,
        )
        chain_trusted, verify_error = await asyncio.wait_for(
            asyncio.to_thread(_verify_blocking, host, address, port, timeout),
            timeout=timeout + 1,
        )

        parsed = summarize_certificate(
            host,
            der,
            chain_trusted=chain_trusted,
            verify_error=verify_error,
            protocol=protocol,
            cipher=cipher,
        )

        ct: dict = section["ct"]
        if ct_task is not None:
            ct = await ct_task
            if (ct.get("recently_issued_count") or 0) > 0:
                parsed["findings"].append(
                    {
                        "type": "ct_recent_issue",
                        "severity": "low",
                        "evidence": (
                            f"{ct['recently_issued_count']} certificate(s) for {domain} were issued "
                            f"in the last {CT_RECENT_WINDOW_DAYS} days — recently issued, verify"
                        ),
                        "detail": "Frequent or brand-new issuance is common for freshly created "
                        "phishing domains; it is not proof of malice.",
                    }
                )

        return {
            **section,
            "analyzed": True,
            "status": parsed["status"],
            "status_label": parsed["status_label"],
            "certificate": parsed["certificate"],
            "hostname": parsed["hostname"],
            "chain": parsed["chain"],
            "compromised_ca": parsed["compromised_ca"],
            "ct": ct,
            "findings": parsed["findings"],
            "score": parsed["score"],
            "note": VALID_CERT_NOTE,
            "error": None,
        }

    except (asyncio.TimeoutError, socket.timeout, TimeoutError):
        section["error"] = f"TLS handshake timed out after {timeout:g}s"
    except ssl.SSLError as exc:
        section["error"] = f"TLS handshake failed: {str(exc)[:200]}"
    except (socket.gaierror, OSError) as exc:
        section["error"] = f"TLS connection failed: {str(exc)[:200]}"
    except Exception as exc:  # certificate parsing or anything unexpected
        section["error"] = f"TLS analysis failed: {type(exc).__name__}: {str(exc)[:160]}"
    finally:
        if ct_task is not None and not ct_task.done():
            ct_task.cancel()

    if section["status"] == "unreachable":
        section["findings"] = [
            {
                "type": "unreachable",
                "severity": "medium",
                "evidence": f"TLS not checked: {section['error']}",
                "detail": "Recorded as evidence — the rest of the investigation still runs.",
            }
        ]
    return section
