"""
DNS lookups for the standalone link investigator (dnspython).

A non-resolving domain is *evidence*, never a crash: every failure mode
(NXDOMAIN, no A record, SERVFAIL, timeout) is reported as structured data.

The queries run concurrently with a hard 5s budget and fall back to the
system resolver (socket.getaddrinfo) when dnspython cannot get an address —
some networks point the first configured nameserver at an unreachable host,
and the OS stack fails over to the next one correctly.
"""

import asyncio
import ipaddress
import socket

import dns.asyncresolver
import dns.exception
import dns.resolver

DNS_TIMEOUT = 5.0
RECORD_TYPES = ("A", "AAAA", "MX")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _system_resolve(host: str, timeout: float) -> list[str]:
    socket.setdefaulttimeout(timeout)
    addresses: list[str] = []
    try:
        for info in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP):
            address = info[4][0]
            if address not in addresses:
                addresses.append(address)
    except (socket.gaierror, OSError, UnicodeError):
        return []
    return addresses


async def _query(resolver, host: str, record_type: str, timeout: float) -> dict:
    try:
        answer = await resolver.resolve(host, record_type, lifetime=timeout)
        return {"type": record_type, "values": [r.to_text().strip('"') for r in answer], "error": None}
    except dns.resolver.NXDOMAIN:
        return {"type": record_type, "values": [], "error": "nxdomain"}
    except dns.resolver.NoAnswer:
        return {"type": record_type, "values": [], "error": "no_answer"}
    except dns.resolver.NoNameservers:
        return {"type": record_type, "values": [], "error": "servfail"}
    except dns.exception.Timeout:
        return {"type": record_type, "values": [], "error": "timeout"}
    except (dns.exception.DNSException, ValueError, UnicodeError) as exc:
        return {"type": record_type, "values": [], "error": f"{type(exc).__name__}"}


async def resolve_domain(host: str, timeout: float = DNS_TIMEOUT, fallback_host: str | None = None) -> dict:
    """
    Resolves A/AAAA/MX for `host` (concurrently, bounded by `timeout`).
    Falls back to the registered domain when the full host does not resolve.
    """
    if not host:
        return {"host": host, "resolved": False, "records": {}, "addresses": [], "mx": [],
                "error": "no hostname to resolve", "error_kind": "invalid", "resolver": "none"}

    if _is_ip(host):
        record_type = "AAAA" if ":" in host else "A"
        return {
            "host": host,
            "resolved": True,
            "records": {record_type: [host]},
            "addresses": [host],
            "mx": [],
            "error": None,
            "error_kind": None,
            "resolver": "literal",
            "is_ip_literal": True,
        }

    result = {
        "host": host,
        "resolved": False,
        "records": {},
        "addresses": [],
        "mx": [],
        "error": None,
        "error_kind": None,
        "resolver": "dnspython",
    }

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = min(2.0, timeout)
    resolver.lifetime = timeout

    try:
        answers = await asyncio.wait_for(
            asyncio.gather(*(_query(resolver, host, qtype, timeout) for qtype in RECORD_TYPES)),
            timeout=timeout + 1,
        )
    except (asyncio.TimeoutError, dns.exception.DNSException) as exc:
        answers = []
        result["error"] = f"DNS lookup for '{host}' timed out"
        result["error_kind"] = "timeout"
        if not isinstance(exc, asyncio.TimeoutError):
            result["error_kind"] = "error"

    errors = {a["error"] for a in answers if a["error"]}

    for answer in answers:
        values = answer["values"]
        if values:
            result["records"][answer["type"]] = values[:10]
            if answer["type"] in ("A", "AAAA"):
                result["addresses"].extend(values)
            if answer["type"] == "MX":
                result["mx"] = values[:10]

    result["addresses"] = sorted(set(result["addresses"]))
    result["resolved"] = bool(result["addresses"])

    # --- fallback: the OS resolver handles dead first nameservers correctly ---
    if not result["resolved"] and errors - {"nxdomain"}:
        system_addresses = await asyncio.wait_for(
            asyncio.to_thread(_system_resolve, host, timeout), timeout=timeout + 1
        )
        if system_addresses:
            result["addresses"] = system_addresses
            result["resolved"] = True
            result["resolver"] = "system (dnspython unavailable)"
            result["records"]["A" if ":" not in system_addresses[0] else "AAAA"] = system_addresses[:10]

    if result["resolved"]:
        result["error"] = None
        result["error_kind"] = None
    else:
        if "nxdomain" in errors:
            result["error"] = f"NXDOMAIN — '{host}' does not exist in DNS"
            result["error_kind"] = "nxdomain"
        elif not result.get("error"):
            if "timeout" in errors:
                result["error"] = f"DNS query for '{host}' timed out after {timeout:g}s"
                result["error_kind"] = "timeout"
            elif "servfail" in errors:
                result["error"] = f"DNS SERVFAIL — no nameserver answered for '{host}'"
                result["error_kind"] = "servfail"
            else:
                result["error"] = f"'{host}' has no A/AAAA records"
                result["error_kind"] = "no_answer"

    if not result["resolved"] and fallback_host and fallback_host.lower() != host.lower():
        fallback = await resolve_domain(fallback_host, timeout=timeout)
        result["fallback"] = {
            "host": fallback_host,
            "resolved": fallback["resolved"],
            "addresses": fallback["addresses"],
        }
        if fallback["resolved"]:
            result["addresses"] = fallback["addresses"]
            result["resolved"] = True
            result["error"] = None
            result["error_kind"] = None

    return result
