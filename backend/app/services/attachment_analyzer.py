import hashlib
import mimetypes

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js",
    ".jar", ".ps1", ".msi", ".dll", ".lnk"
}

ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz"}

MACRO_ENABLED_EXTENSIONS = {".docm", ".xlsm", ".pptm"}


def analyze_attachments(attachments: list) -> list:
    """
    Takes list of attachment dicts (from email_parser.py, includes raw_bytes)
    and returns risk analysis WITHOUT executing any content.
    """
    results = []
    for att in attachments:
        results.append(_analyze_single_attachment(att))
    return results


def _analyze_single_attachment(att: dict) -> dict:
    reasons = []
    risk_score = 0

    filename = att.get("filename", "unknown")
    raw_bytes = att.get("raw_bytes", b"")
    size_bytes = att.get("size_bytes", len(raw_bytes))
    content_type = att.get("content_type", "")

    # --- Extension extraction ---
    extension = _get_extension(filename)

    # --- Double extension check (e.g. invoice.pdf.exe) ---
    parts = filename.lower().split(".")
    if len(parts) > 2:
        risk_score += 25
        reasons.append("Double extension detected — common malware disguise technique")

    # --- Dangerous extension ---
    if extension in DANGEROUS_EXTENSIONS:
        risk_score += 40
        reasons.append(f"Executable/script extension ({extension}) — high risk file type")

    # --- Archive (could hide malicious content) ---
    if extension in ARCHIVE_EXTENSIONS:
        risk_score += 15
        reasons.append("Archive file — contents not inspected, treat as unverified")

    # --- Macro-enabled Office files ---
    if extension in MACRO_ENABLED_EXTENSIONS:
        risk_score += 30
        reasons.append("Macro-enabled Office document — common malware delivery method")

    # --- MIME type mismatch (declared type vs extension guess) ---
    guessed_type, _ = mimetypes.guess_type(filename)
    if guessed_type and content_type and guessed_type != content_type:
        risk_score += 10
        reasons.append(f"MIME type mismatch: declared '{content_type}', expected '{guessed_type}'")

    # --- Empty/suspicious size ---
    if size_bytes == 0:
        risk_score += 10
        reasons.append("Zero-byte attachment — unusual")

    risk_score = min(risk_score, 100)

    if risk_score >= 50:
        risk = "HIGH"
    elif risk_score >= 20:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "filename": filename,
        "extension": extension,
        "mime_type": content_type,
        "size_bytes": size_bytes,
        "sha256": _compute_sha256(raw_bytes),
        "risk": risk,
        "risk_score": risk_score,
        "reasons": reasons,
    }


def _get_extension(filename: str) -> str:
    if "." not in filename:
        return ""
    return "." + filename.lower().rsplit(".", 1)[-1]


def _compute_sha256(data: bytes) -> str:
    if not data:
        return ""
    return hashlib.sha256(data).hexdigest()