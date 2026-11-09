"""
Normalisation for user-submitted links (Module 1 — standalone URL investigation).

Everything here is offline and side-effect free: it only parses and rewrites
the string the user pasted so the rest of the pipeline (DNS, SSRF guard,
redirects, reputation) works on one canonical form.
"""

import ipaddress
import re
import unicodedata
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import tldextract

# Bundled PSL snapshot only — never fetch the suffix list over the network
# while handling a user request.
_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

TRACKING_PARAM_PREFIXES = ("utm_",)
TRACKING_PARAMS = {
    "fbclid", "gclid", "gclsrc", "dclid", "msclkid", "wbraid", "gbraid",
    "mc_cid", "mc_eid", "mkt_tok", "igshid", "yclid", "twclid", "ttclid",
    "_ga", "_gl", "_hsenc", "_hsmi", "oly_anon_id", "oly_enc_id",
    "vero_id", "vero_conv", "wickedid", "rb_clickid", "s_cid", "ref_src",
    "ref_url", "trk", "trk_contact",
}

ALLOWED_SCHEMES = {"http", "https"}
DEFAULT_PORTS = {"http": 80, "https": 443}

# Cyrillic / Greek / other look-alikes frequently used in IDN homograph attacks.
# Mapped to the Latin character they imitate so we can build an ASCII "skeleton".
CONFUSABLES = {
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h",
    "о": "o", "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "ѕ": "s",
    "і": "i", "ї": "i", "ј": "j", "ԁ": "d", "ɡ": "g", "ԛ": "q", "ԝ": "w",
    "һ": "h", "ӏ": "l", "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k",
    "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "γ": "y",
    "ι": "i", "η": "n", "ω": "w", "ı": "i", "ℓ": "l", "ⅼ": "l", "ⲟ": "o",
    "ſ": "s", "ɑ": "a", "ɡ": "g",
}

# Digit/homoglyph substitutions used inside domain labels (paypa1, g00gle, ...).
DIGIT_SKELETON = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "9": "g", "2": "z", "$": "s", "@": "a",
}

SCRIPT_RANGES = (
    (0x0400, 0x04FF, "Cyrillic"),
    (0x0370, 0x03FF, "Greek"),
    (0x0530, 0x058F, "Armenian"),
    (0x0590, 0x05FF, "Hebrew"),
    (0x0600, 0x06FF, "Arabic"),
    (0x0E00, 0x0E7F, "Thai"),
    (0x0E80, 0x0EFF, "Lao"),
    (0x4E00, 0x9FFF, "CJK"),
)


class InvalidURLError(ValueError):
    """Raised when the submitted string cannot be interpreted as a http(s) URL."""


def is_ip_address(value: str) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def decode_punycode_label(label: str) -> str:
    """Decode a single 'xn--' label to Unicode; return it unchanged if impossible."""
    if not label.lower().startswith("xn--"):
        return label
    try:
        return label.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        return label


def decode_host(host: str) -> str:
    if not host:
        return host
    return ".".join(decode_punycode_label(label) for label in host.split("."))


def confusable_skeleton(text: str) -> str:
    """Best-effort ASCII skeleton of a label/host (homoglyph + digit folding)."""
    lowered = text.lower()
    folded = "".join(CONFUSABLES.get(ch, ch) for ch in lowered)
    return "".join(DIGIT_SKELETON.get(ch, ch) for ch in folded)


def scripts_used(text: str) -> set:
    found = set()
    for ch in text:
        if ord(ch) < 128:
            continue
        for start, end, name in SCRIPT_RANGES:
            if start <= ord(ch) <= end:
                found.add(name)
                break
        else:
            found.add("Other")
    return found


def is_homograph_risk(host: str) -> dict:
    """
    Flags hosts that mix scripts, contain non-ASCII look-alike characters,
    or decode to a different ASCII skeleton than their punycode form.
    """
    decoded = decode_host(host)
    scripts = scripts_used(decoded)
    reasons = []

    mixed = "Latin" in scripts and len(scripts - {"Latin"}) > 0
    if mixed:
        other = ", ".join(sorted(scripts - {"Latin"}))
        reasons.append(f"Host mixes Latin characters with {other} characters")

    non_ascii = [ch for ch in decoded if ord(ch) > 127]
    if non_ascii:
        lookalikes = sorted({ch for ch in non_ascii if ch in CONFUSABLES})
        if lookalikes:
            reasons.append(
                "Non-ASCII look-alike characters in host: "
                + " ".join(f"'{ch}'" for ch in lookalikes[:6])
            )
        elif not mixed:
            reasons.append("Host contains non-ASCII (IDN) characters")

    if "xn--" in host.lower():
        reasons.append(
            f"Punycode host decodes to '{decoded}'"
            if decoded != host
            else "Punycode-encoded host (xn--)"
        )

    return {
        "decoded_host": decoded,
        "is_punycode": "xn--" in host.lower(),
        "scripts": sorted(scripts),
        "suspicious": bool(reasons),
        "reasons": reasons,
        "skeleton": confusable_skeleton(decoded),
    }


def split_domain(host: str) -> dict:
    """Registered domain parts for a host, using the bundled PSL snapshot."""
    ext = _EXTRACTOR(host)
    registered = ".".join(part for part in (ext.domain, ext.suffix) if part)
    return {
        "registered_domain": registered or host,
        "domain_label": ext.domain,
        "suffix": ext.suffix,
        "subdomain": ext.subdomain,
    }


def normalize_url(raw_url: str) -> dict:
    """
    Canonicalises a user-supplied URL.

    - adds a scheme when the user pasted a bare host ("sbi.co.in/login")
    - lowercases scheme + host, drops default ports and trailing dots
    - strips tracking parameters (utm_*, fbclid, gclid, ...)
    - drops the fragment
    - decodes punycode for display and reports homograph risk

    Raises InvalidURLError for anything that is not a usable http(s) URL.
    """
    if not isinstance(raw_url, str):
        raise InvalidURLError("URL must be a string")

    original = raw_url
    candidate = raw_url.strip()
    if not candidate:
        raise InvalidURLError("URL is empty")
    if len(candidate) > 4096:
        raise InvalidURLError("URL is too long (max 4096 characters)")
    if any(ch in candidate for ch in ("\n", "\r", "\t", " ")):
        raise InvalidURLError("URL contains whitespace or control characters")

    notes = []
    scheme_assumed = False
    if "://" not in candidate:
        candidate = f"https://{candidate}"
        scheme_assumed = True
        notes.append("No scheme supplied — assumed https://")

    parsed = urlparse(candidate)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise InvalidURLError(
            f"Unsupported URL scheme '{scheme or 'none'}' — only http and https are allowed"
        )

    host = (parsed.hostname or "").strip().rstrip(".")
    if not host:
        raise InvalidURLError("URL has no hostname")
    if is_ip_address(host):
        host = host.lower()
    else:
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise InvalidURLError("Hostname is not valid IDNA")
        if not re.fullmatch(r"[a-z0-9.\-]+", host):
            raise InvalidURLError("Hostname contains invalid characters")
        if "." not in host and host != "localhost":
            raise InvalidURLError(
                "Hostname has no public suffix (expected something like example.com)"
            )

    port = parsed.port
    if port is not None and port == DEFAULT_PORTS.get(scheme):
        port = None
        notes.append(f"Removed default port {DEFAULT_PORTS[scheme]}")

    # --- strip tracking parameters, keep the rest in order ---
    removed_params = []
    kept_params = []
    if parsed.query:
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            lowered = key.lower()
            if lowered.startswith(TRACKING_PARAM_PREFIXES) or lowered in TRACKING_PARAMS:
                removed_params.append(key)
            else:
                kept_params.append((key, value))
    query = urlencode(kept_params, doseq=True)

    if parsed.fragment:
        notes.append("URL fragment (#...) removed")

    netloc = host if port is None else f"{host}:{port}"
    normalized = urlunparse((scheme, netloc, parsed.path or "/", "", query, ""))

    ext = split_domain(host) if not is_ip_address(host) else {
        "registered_domain": host, "domain_label": host, "suffix": "", "subdomain": "",
    }
    homograph = is_homograph_risk(host)

    if homograph["is_punycode"] and homograph["decoded_host"] != host:
        notes.append(
            f"Punycode host '{host}' displays as '{homograph['decoded_host']}' "
            f"(Unicode form differs)"
        )
        display_url = normalized.replace(host, homograph["decoded_host"], 1)
    else:
        display_url = normalized

    return {
        "input": original,
        "url": normalized,
        "display_url": display_url,
        "scheme": scheme,
        "scheme_assumed": scheme_assumed,
        "host": host,
        "unicode_host": homograph["decoded_host"],
        "display_host": homograph["decoded_host"] if homograph["is_punycode"] else host,
        "is_ip": is_ip_address(host),
        "port": port,
        "path": parsed.path or "/",
        "query": query,
        "tracking_params_removed": removed_params,
        "homograph": homograph,
        "notes": notes,
        **ext,
    }


def normalize_text(text: str) -> str:
    """NFKC + lowercase helper used for brand comparisons."""
    return unicodedata.normalize("NFKC", text or "").lower()
