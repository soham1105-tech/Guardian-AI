import re
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses

# Regex for extracting URLs from plain text body
URL_REGEX = re.compile(r'https?://[^\s<>"\')\]]+')


def parse_email(filepath: str) -> dict:
    """
    Parses a .eml file and returns structured data.
    """
    with open(filepath, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    # --- Basic headers ---
    from_addr = _extract_first_address(msg.get("From"))
    to_addr = _extract_first_address(msg.get("To"))
    subject = msg.get("Subject", "")
    date = msg.get("Date", "")
    return_path = msg.get("Return-Path", "")
    reply_to = msg.get("Reply-To", "")

    # --- All Received headers (used later for spoofing/IP analysis) ---
    received_headers = msg.get_all("Received", [])

    # --- Auth results (some providers add this header) ---
    auth_results = msg.get("Authentication-Results", "")

    # --- Body extraction ---
    body_text = _extract_body(msg)

    # --- URLs from body ---
    urls = list(set(URL_REGEX.findall(body_text or "")))

    # --- Attachments ---
    attachments = _extract_attachments(msg)

    return {
        "from_addr": from_addr,
        "to_addr": to_addr,
        "subject": subject,
        "date": date,
        "return_path": return_path,
        "reply_to": reply_to,
        "received_headers": received_headers,
        "authentication_results": auth_results,
        "body_text": body_text,
        "urls": urls,
        "attachments": attachments,
        "raw_headers": dict(msg.items()),  # useful for debugging / raw view tab
    }


def _extract_first_address(header_value: str) -> str:
    if not header_value:
        return ""
    addresses = getaddresses([header_value])
    if addresses:
        return addresses[0][1]  # returns email part only
    return header_value


def _extract_body(msg) -> str:
    """
    Walks the email and extracts plain text body.
    Falls back to stripped HTML if no plain text part exists.
    """
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            if content_type == "text/plain" and "attachment" not in content_disposition:
                try:
                    return part.get_content()
                except Exception:
                    continue

        # Fallback: try HTML and strip tags crudely
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                try:
                    html = part.get_content()
                    return re.sub(r"<[^>]+>", " ", html)
                except Exception:
                    continue
        return ""
    else:
        try:
            return msg.get_content()
        except Exception:
            return ""


def _extract_attachments(msg) -> list:
    """
    Returns list of dicts: filename, content_type, size, raw_bytes
    (raw_bytes needed later for hashing in attachment_analyzer.py)
    """
    attachments = []

    if not msg.is_multipart():
        return attachments

    for part in msg.walk():
        content_disposition = str(part.get("Content-Disposition", ""))
        filename = part.get_filename()

        if filename and "attachment" in content_disposition.lower() or (filename and part.get_content_maintype() != "multipart"):
            try:
                payload = part.get_payload(decode=True)
            except Exception:
                payload = None

            if payload:
                attachments.append({
                    "filename": filename,
                    "content_type": part.get_content_type(),
                    "size_bytes": len(payload),
                    "raw_bytes": payload,  # consumed by attachment_analyzer.py, never executed
                })

    return attachments