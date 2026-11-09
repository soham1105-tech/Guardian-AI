import re
import ipaddress

IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def extract_iocs(parsed_email: dict, url_analysis: list, attachment_analysis: list) -> dict:
    """
    Aggregates all Indicators of Compromise from every analysis stage
    into one deduplicated summary. IP-literal values are always
    classified as IPs, never as domains — even when they appear in
    a URL's "domain" field (e.g. http://185.220.101.45/...).
    """
    domains = set()
    ips = set()
    urls = set()
    emails = set()
    hashes = set()

    # --- From URLs ---
    for item in url_analysis:
        urls.add(item["url"])
        domain_value = item.get("domain")
        if domain_value:
            if _is_ip(domain_value):
                ips.add(domain_value)
            else:
                domains.add(domain_value)

    # --- From body text (raw IPs mentioned) ---
    body_text = parsed_email.get("body_text", "") or ""
    for ip in IP_REGEX.findall(body_text):
        ips.add(ip)

    # --- From email addresses in body/headers ---
    for addr in EMAIL_REGEX.findall(body_text):
        emails.add(addr)

    from_addr = parsed_email.get("from_addr")
    if from_addr:
        emails.add(from_addr)

    # --- From Received headers (originating IPs) ---
    for header in parsed_email.get("received_headers", []):
        for ip in IP_REGEX.findall(header):
            ips.add(ip)

    # --- From attachment hashes ---
    for att in attachment_analysis:
        if att.get("sha256"):
            hashes.add(att["sha256"])

    # --- Sender domain (guard against IP-literal sender domains too) ---
    if from_addr and "@" in from_addr:
        sender_domain = from_addr.split("@")[-1]
        if _is_ip(sender_domain):
            ips.add(sender_domain)
        else:
            domains.add(sender_domain)

    return {
        "ips": sorted(ips),
        "domains": sorted(domains),
        "urls": sorted(urls),
        "emails": sorted(emails),
        "hashes": sorted(hashes),
    }