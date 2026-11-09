import re
import tldextract
import ipaddress
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "signin", "banking", "password", "suspended", "urgent", "click"
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"
}

BRAND_KEYWORDS = [
    "microsoft", "google", "paypal", "amazon", "apple", "facebook",
    "bankofamerica", "chase", "netflix", "instagram", "linkedin"
]


def analyze_urls(urls: list) -> list:
    """
    Takes list of raw URLs (from email_parser.py) and returns
    risk analysis for each.
    """
    results = []
    for url in urls:
        results.append(_analyze_single_url(url))
    return results


def _analyze_single_url(url: str) -> dict:
    reasons = []
    risk_score = 0

    parsed = urlparse(url)
    extracted = tldextract.extract(url)

    domain = extracted.domain
    suffix = extracted.suffix
    subdomain = extracted.subdomain
    full_domain = f"{domain}.{suffix}" if suffix else domain

    # --- 1. IP-based URL ---
    if _is_ip_address(parsed.hostname):
        risk_score += 30
        reasons.append("URL uses raw IP address instead of domain name")

    # --- 2. URL shortener ---
    if full_domain.lower() in SHORTENER_DOMAINS:
        risk_score += 20
        reasons.append("URL shortener detected — destination hidden")

    # --- 3. Excessive subdomains ---
    if subdomain and subdomain.count(".") >= 2:
        risk_score += 15
        reasons.append("Excessive subdomain levels — possible obfuscation")

    # --- 4. Brand impersonation in subdomain/path (not actual brand domain) ---
    for brand in BRAND_KEYWORDS:
        if brand in (subdomain.lower() + parsed.path.lower()) and brand != domain.lower():
            risk_score += 25
            reasons.append(f"Brand name '{brand}' used outside actual domain — possible impersonation")
            break

    # --- 5. Suspicious keywords in URL ---
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()]
    if found_keywords:
        risk_score += 10 * min(len(found_keywords), 2)
        reasons.append(f"Suspicious keywords found: {', '.join(found_keywords[:3])}")

    # --- 6. Punycode / IDN homograph ---
    if "xn--" in url.lower():
        risk_score += 25
        reasons.append("Punycode/IDN encoding detected — possible homograph attack")

    # --- 7. HTTP instead of HTTPS ---
    if parsed.scheme == "http":
        risk_score += 10
        reasons.append("Insecure HTTP (not HTTPS)")

    # --- 8. No suffix / malformed domain ---
    if not suffix:
        risk_score += 10
        reasons.append("Malformed or unusual domain structure")

    # Cap score at 100
    risk_score = min(risk_score, 100)

    if risk_score >= 50:
        risk = "HIGH"
    elif risk_score >= 20:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "url": url,
        "domain": full_domain or parsed.hostname or url,
        "risk": risk,
        "risk_score": risk_score,
        "reasons": reasons,
    }


# Public alias: the standalone link investigator scores a single URL through the
# same heuristics the email flow uses.
analyze_single_url = _analyze_single_url


def _is_ip_address(hostname: str) -> bool:
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False