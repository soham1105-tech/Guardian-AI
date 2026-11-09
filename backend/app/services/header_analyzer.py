import re
import tldextract
from email.utils import parseaddr


def analyze_headers(parsed_email: dict) -> dict:
    """
    Takes parsed email dict (from email_parser.py) and returns
    header-based spoofing analysis.
    """
    reasons = []

    from_addr = parsed_email.get("from_addr", "")
    return_path = parsed_email.get("return_path", "")
    reply_to = parsed_email.get("reply_to", "")
    auth_results = parsed_email.get("authentication_results", "")

    # --- Extract domains ---
    sender_domain = _get_domain(from_addr)
    return_path_domain = _get_domain(_extract_email_from_header(return_path))
    reply_to_domain = _get_domain(_extract_email_from_header(reply_to))

    # --- SPF / DKIM / DMARC from Authentication-Results header ---
    spf = _extract_auth_result(auth_results, "spf")
    dkim = _extract_auth_result(auth_results, "dkim")
    dmarc = _extract_auth_result(auth_results, "dmarc")

    # --- Domain mismatch check ---
    domain_mismatch = False
    if sender_domain and return_path_domain and sender_domain != return_path_domain:
        domain_mismatch = True
        reasons.append(f"From domain ({sender_domain}) does not match Return-Path domain ({return_path_domain})")

    if sender_domain and reply_to_domain and sender_domain != reply_to_domain:
        reasons.append(f"Reply-To domain ({reply_to_domain}) differs from From domain ({sender_domain}) — replies go elsewhere")

    # --- Auth failures ---
    if spf == "FAIL":
        reasons.append("SPF authentication failed — sender IP not authorized")
    if dkim == "FAIL":
        reasons.append("DKIM signature invalid or missing")
    if dmarc == "FAIL":
        reasons.append("DMARC alignment failed")

    # --- Compute spoofing risk ---
    spoofing_risk = _calculate_spoofing_risk(spf, dkim, dmarc, domain_mismatch)

    return {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "sender_domain": sender_domain,
        "return_path_domain": return_path_domain,
        "domain_mismatch": domain_mismatch,
        "spoofing_risk": spoofing_risk,
        "reasons": reasons,
    }


def _get_domain(email_addr: str) -> str:
    if not email_addr or "@" not in email_addr:
        return ""
    domain = email_addr.split("@")[-1].strip().rstrip(">").lower()
    return domain


def _extract_email_from_header(header_value: str) -> str:
    if not header_value:
        return ""
    _, addr = parseaddr(header_value)
    return addr


def _extract_auth_result(auth_header: str, mechanism: str) -> str:
    """
    Parses Authentication-Results header for spf=/dkim=/dmarc= result.
    Returns PASS / FAIL / NEUTRAL / UNKNOWN
    """
    if not auth_header:
        return "UNKNOWN"

    pattern = rf"{mechanism}=(\w+)"
    match = re.search(pattern, auth_header, re.IGNORECASE)

    if not match:
        return "UNKNOWN"

    result = match.group(1).lower()
    if result == "pass":
        return "PASS"
    elif result == "fail":
        return "FAIL"
    elif result in ("neutral", "softfail", "none"):
        return "NEUTRAL"
    else:
        return "UNKNOWN"


def _calculate_spoofing_risk(spf: str, dkim: str, dmarc: str, domain_mismatch: bool) -> str:
    fail_count = sum(1 for r in [spf, dkim, dmarc] if r == "FAIL")

    if fail_count >= 2 or (fail_count >= 1 and domain_mismatch):
        return "HIGH"
    elif fail_count == 1 or domain_mismatch:
        return "MEDIUM"
    else:
        return "LOW"