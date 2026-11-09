MITRE_TECHNIQUES = {
    "spearphishing_link": {
        "id": "T1566.002", "name": "Phishing: Spearphishing Link", "tactic": "Initial Access",
    },
    "spearphishing_attachment": {
        "id": "T1566.001", "name": "Phishing: Spearphishing Attachment", "tactic": "Initial Access",
    },
    "spoofing": {
        "id": "T1656", "name": "Impersonation", "tactic": "Defense Evasion / Initial Access",
    },
    "credential_harvesting": {
        "id": "T1598.003", "name": "Phishing for Information: Spearphishing Link", "tactic": "Reconnaissance",
    },
    "malicious_macro": {
        "id": "T1204.002", "name": "User Execution: Malicious File", "tactic": "Execution",
    },
    "masquerading": {
        "id": "T1036.008", "name": "Masquerading: Masquerade File Type", "tactic": "Defense Evasion",
    },
}


def map_techniques(header_analysis: dict, url_analysis: list, attachment_analysis: list) -> list:
    """
    Maps deterministic findings already produced by the pipeline to
    standard MITRE ATT&CK technique IDs. Pure mapping — no new detection
    logic is introduced here.
    """
    seen = set()
    techniques = []

    def add(key):
        if key not in seen:
            seen.add(key)
            techniques.append(MITRE_TECHNIQUES[key])

    if header_analysis.get("spoofing_risk") in ("MEDIUM", "HIGH"):
        add("spoofing")

    risky_urls = [u for u in url_analysis if u["risk"] in ("MEDIUM", "HIGH")]
    if risky_urls:
        add("spearphishing_link")
        if any("login" in r.lower() or "credential" in r.lower() or "keyword" in r.lower()
               for u in risky_urls for r in u.get("reasons", [])):
            add("credential_harvesting")

    risky_attachments = [a for a in attachment_analysis if a["risk"] in ("MEDIUM", "HIGH")]
    if risky_attachments:
        add("spearphishing_attachment")
        if any("macro" in r.lower() for a in risky_attachments for r in a.get("reasons", [])):
            add("malicious_macro")
        if any("double extension" in r.lower() for a in risky_attachments for r in a.get("reasons", [])):
            add("masquerading")

    return techniques