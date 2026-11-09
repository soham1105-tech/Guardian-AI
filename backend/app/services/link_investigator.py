"""
Standalone link investigation (Module 1).

Takes any user-supplied URL/domain and produces the *same report shape* the
email pipeline returns (risk_report / url_analysis / ioc_summary /
threat_intel / mitre_techniques / ai_verdict) so the existing result
components render it unchanged, plus a link-specific `checks` object and the
summary fields (`verdict`, `risk_score` 0-10, `indicators`, `evidence`,
`recommendations`).

Nothing is executed and no files are downloaded: responses are streamed and
capped, redirects are validated hop by hop against the SSRF guard, and every
external lookup is best-effort.
"""

import asyncio
from datetime import datetime

from app.config import settings
from app.services.ai_analyzer import get_ai_verdict
from app.services.dns_resolver import resolve_domain
from app.services.domain_intel import check_domain
from app.services.ioc_extractor import extract_iocs
from app.services.mitre_mapper import map_techniques
from app.services.risk_engine import _categorize
from app.services.ssrf_guard import (
    SECURITY_RESPONSE_HEADERS,
    SENSITIVE_PROBE_PATHS,
    SSRFBlockedError,
    fetch_redirect_chain,
    probe_sensitive_paths,
    validate_target,
)
from app.services.threat_intel.provider_manager import check_iocs_batch, summarize_threat_intel
from app.services.tls_analyzer import VALID_CERT_NOTE, analyze_tls
from app.services.url_analyzer import analyze_single_url
from app.services.url_normalizer import InvalidURLError, normalize_url

# --- scoring constants (0-100, same scale + thresholds as the email flow) ---
PAYLOAD_KEYWORDS = (
    "phishing", "phish", "malware", "ransomware", "keylogger", "stealer",
    "trojan", "scam", "exploit", "payload", "0day", "credential",
)
PAYLOAD_KEYWORD_SCORE = 65          # a path literally advertising a payload is a hard signal
USERINFO_SCORE = 45                 # http://brand.com@evil.tld trick
NONSTANDARD_PORT_SCORE = 10
DNS_FAILURE_SCORE = 40
REDIRECT_UNRELATED_SCORE = 35
REDIRECT_DOWNGRADE_SCORE = 20
REDIRECT_LIMIT_SCORE = 25
REDIRECT_LOOP_SCORE = 30
REDIRECT_BLOCKED_SCORE = 50
REPUTATION_MALICIOUS_FLOOR = 85     # a *scan-based* verdict => CRITICAL
OTX_PULSE_SCORE = 20                # community-pulse mentions alone are weak evidence
EXTRA_SIGNAL_WEIGHT = 0.2           # weaker signals add to, never mask, the strongest one

# Providers that publish an actual scan/blocklist verdict for a URL/domain.
# AlienVault OTX only reports "appears in N community pulses", which is a
# narrative mention — shared-hosting and popular short domains show up there
# constantly, so it corroborates but never confirms on its own.
SCAN_CONFIRMING_PROVIDERS = {"VirusTotal", "URLhaus", "URLScan.io", "AbuseIPDB"}

def risk_class_for(score: float, has_threat_intel: bool = False) -> str:
    """
    Maps the 0-100 score onto the 5-class risk_class (Prompt 3 thresholds,
    unchanged). Shared by the link and message pipelines so both always agree.
    """
    score_10 = round(score / 10, 1)
    if score_10 <= 2:
        return "Low Risk"
    if score_10 <= 5:
        return "Suspicious"
    if score_10 <= 8:
        return "High Risk"
    return "Confirmed Malicious" if has_threat_intel else "High Risk"


VERDICT_BY_CATEGORY = {
    "CRITICAL": "Confirmed Malicious",
    "HIGH": "High Risk",
    "SUSPICIOUS": "Medium Risk",
    "SAFE": "Low Risk",
}


async def _collect_reputation(normalized: dict, resolved_ips: list) -> dict:
    """Reuses the existing provider stack (VirusTotal, URLhaus, URLScan.io, OTX, AbuseIPDB)."""
    urls = [normalized["url"]]
    raw = (normalized.get("input") or "").strip()
    if raw and raw.rstrip("/").lower() != normalized["url"].rstrip("/").lower():
        urls.append(raw)

    domains = [normalized["registered_domain"]]
    if normalized["host"] != normalized["registered_domain"]:
        domains.append(normalized["host"])

    # Resolved IPs are deliberately NOT sent to reputation providers: shared
    # CDN/brand infrastructure (e.g. google.com's edge IPs) is mentioned in so
    # many community OTX pulses that IP lookups would produce false positives.
    ioc_summary = {
        "urls": urls[:2],
        "domains": domains[:2],
        "ips": [],
        "emails": [],
        "hashes": [],
    }

    try:
        results = await check_iocs_batch(ioc_summary, max_per_type=2)
    except Exception as exc:  # reputation must never break the investigation
        results = {}
        ioc_summary["_error"] = f"reputation lookup failed ({type(exc).__name__})"

    summary = summarize_threat_intel(results)
    checked = sorted(
        {v["provider"] for verdicts in results.values() for v in verdicts if v.get("checked")}
        - {v["provider"] for verdicts in results.values() for v in verdicts if v.get("malicious")}
    )
    flagged = sorted(
        {v["provider"] for verdicts in results.values() for v in verdicts if v.get("malicious")}
    )

    return {
        "ioc_summary": {k: v for k, v in ioc_summary.items() if not k.startswith("_")},
        "results": results,
        "summary": summary,
        "providers_with_clean_results": checked,
        "providers_that_flagged": flagged,
        "providers_configured": [
            name
            for name, key in (
                ("VirusTotal", settings.VIRUSTOTAL_API_KEY),
                # abuse.ch now requires a free Auth-Key for URLhaus, so a
                # keyless deployment is reported as unconfigured, not clean.
                ("URLhaus", settings.URLHAUS_API_KEY),
                ("URLScan.io", settings.URLSCAN_API_KEY),
                ("AbuseIPDB", settings.ABUSEIPDB_API_KEY),
                ("OTX", settings.OTX_API_KEY),
            )
            if key
        ],
    }


def _static_checks(normalized: dict) -> tuple[int, list[str], list[dict]]:
    """Reuses the email URL heuristics, then adds link-only static signals."""
    base = analyze_single_url(normalized["url"])
    reasons = list(base.get("reasons", []))
    indicators: list[dict] = []
    score = base.get("risk_score", 0)

    path = (normalized.get("path") or "").lower()
    payload_hits = [kw for kw in PAYLOAD_KEYWORDS if kw in path]
    if payload_hits:
        score = max(score, PAYLOAD_KEYWORD_SCORE)
        reasons.append(
            f"URL path advertises a phishing/malware payload: {', '.join(payload_hits[:3])}"
        )
        indicators.append(
            {
                "type": "payload_keyword",
                "detail": f"Path contains payload keyword(s): {', '.join(payload_hits[:3])}",
                "severity": "high",
            }
        )

    try:
        from urllib.parse import urlparse

        parsed = urlparse(normalized["url"])
        if parsed.username or parsed.password:
            score += USERINFO_SCORE
            reasons.append(
                "URL embeds a fake user/brand block before the real host "
                "(classic 'brand.com@evil.tld' credential-harvesting trick)"
            )
            indicators.append(
                {
                    "type": "userinfo_obfuscation",
                    "detail": f"URL userinfo '{parsed.username or parsed.password}' hides the real host {normalized['host']}",
                    "severity": "high",
                }
            )
        if normalized.get("port") and normalized["port"] not in (80, 443):
            score += NONSTANDARD_PORT_SCORE
            reasons.append(f"Non-standard port {normalized['port']} in URL")
    except ValueError:
        pass

    if normalized["homograph"]["suspicious"]:
        for reason in normalized["homograph"]["reasons"]:
            if reason not in reasons:
                reasons.append(reason)

    return min(score, 100), reasons, indicators


def _dns_result(dns: dict) -> dict:
    return {
        "resolved": dns.get("resolved", False),
        "records": dns.get("records", {}),
        "addresses": dns.get("addresses", []),
        "mx": dns.get("mx", []),
        "error": dns.get("error"),
        "error_kind": dns.get("error_kind"),
        "fallback": dns.get("fallback"),
    }


def _redirect_findings(chain: dict) -> tuple[int, list[dict], list[str]]:
    score = 0
    indicators: list[dict] = []
    evidence: list[str] = []

    if chain["redirect_count"]:
        evidence.append(
            f"Followed {chain['redirect_count']} redirect(s); final URL is {chain['final_url']}"
        )
    if chain["domain_changed"]:
        score += REDIRECT_UNRELATED_SCORE
        indicators.append(
            {
                "type": "redirect",
                "detail": (
                    f"Submitted domain '{chain['submitted_host']}' redirects to unrelated "
                    f"domain '{chain['final_host']}'"
                ),
                "severity": "high",
            }
        )
        evidence.append(
            f"Redirects to unrelated domain: {chain['submitted_host']} -> {chain['final_host']}"
        )
    if chain["scheme_downgrade"]:
        score += REDIRECT_DOWNGRADE_SCORE
        indicators.append(
            {
                "type": "tls_downgrade",
                "detail": "Redirect chain downgrades HTTPS to plaintext HTTP",
                "severity": "medium",
            }
        )
    if chain["limit_exceeded"]:
        score += REDIRECT_LIMIT_SCORE
        indicators.append(
            {
                "type": "redirect",
                "detail": f"Redirect chain longer than {settings.LINK_MAX_REDIRECTS} hops",
                "severity": "medium",
            }
        )
    if chain["loop_detected"]:
        score += REDIRECT_LOOP_SCORE
        indicators.append(
            {"type": "redirect", "detail": "Redirect loop detected", "severity": "medium"}
        )
    blocked = [h for h in chain["hops"] if "SSRF" in (h.get("error") or "")]
    if blocked:
        score += REDIRECT_BLOCKED_SCORE
        for hop in blocked:
            indicators.append(
                {
                    "type": "ssrf",
                    "detail": f"Redirect hop {hop['hop']} pointed at a non-public address: {hop['url']}",
                    "severity": "high",
                }
            )
        evidence.append("A redirect target was rejected by the SSRF guard and not fetched")
    if chain.get("error") and not blocked:
        evidence.append(f"Fetch note: {chain['error']}")
    if chain.get("page_title"):
        evidence.append(f"Final page title: \"{chain['page_title']}\"")

    return score, indicators, evidence


def _reputation_strength(results: dict) -> tuple[bool, int]:
    """
    Splits reputation findings into scan-confirmed vs merely corroborating.

    Returns (scan_confirmed, reputation_score). A scan-based provider verdict
    (VirusTotal / URLhaus / URLScan / AbuseIPDB) is treated as confirmation and
    floors the risk score at CRITICAL; AlienVault OTX only reports community
    pulses, so on its own it contributes OTX_PULSE_SCORE.
    """
    confirming = 0
    corroborating = 0
    for verdicts in results.values():
        for verdict in verdicts:
            if not (verdict.get("checked") and verdict.get("malicious")):
                continue
            if verdict.get("provider") in SCAN_CONFIRMING_PROVIDERS:
                confirming = max(confirming, int(verdict.get("confidence") or 0))
            else:
                corroborating = max(corroborating, int(verdict.get("confidence") or 0))

    if confirming:
        return True, max(REPUTATION_MALICIOUS_FLOOR, confirming)
    if corroborating:
        return False, OTX_PULSE_SCORE
    return False, 0


def _combine(components: dict) -> int:
    """Strongest signal dominates; the rest corroborate with a small weight."""
    if not components:
        return 0
    values = sorted(components.values(), reverse=True)
    strongest, rest = values[0], values[1:]
    return min(100, round(strongest + EXTRA_SIGNAL_WEIGHT * sum(rest)))


def _recommendations(category: str, checks: dict) -> list[str]:
    recommendations: list[str] = []

    if category in ("CRITICAL", "HIGH"):
        recommendations.append("Do not open this link or enter credentials, OTPs or card details on it.")
        recommendations.append("Block the domain at your mail gateway, proxy or DNS filter.")
        recommendations.append("Report the URL to your security team so other recipients can be warned.")
    elif category == "SUSPICIOUS":
        recommendations.append("Treat this link as untrusted and verify the sender through a separate channel.")
        recommendations.append("Do not enter credentials until the domain is confirmed as legitimate.")
    else:
        recommendations.append("No malicious indicators were found in the checks that could be performed.")
        recommendations.append("Still avoid entering credentials on pages reached from unexpected messages.")

    if checks["domain_intel"].get("brand"):
        brand = checks["domain_intel"]["brand"]
        recommendations.append(
            f"Reach {brand} by typing its official address yourself instead of following this link."
        )
    if checks["redirects"].get("domain_changed"):
        recommendations.append(
            "The link does not stay on the domain it starts on — inspect the final destination before trusting it."
        )
    if not checks["dns"].get("resolved"):
        recommendations.append(
            "The domain does not currently resolve — it may be a takedown, a typo, or a not-yet-registered phishing domain."
        )
    if checks["reputation"].get("unavailable_providers"):
        providers = ", ".join(checks["reputation"]["unavailable_providers"])
        recommendations.append(
            f"Reputation feeds unavailable ({providers}) — treat this report as heuristic-only."
        )

    tls = checks.get("tls") or {}
    tls_status = tls.get("status")
    if (tls.get("compromised_ca") or {}).get("matched"):
        recommendations.append(
            "The TLS certificate was issued by a known compromised or distrusted CA — "
            "treat this site as malicious and block it rather than trusting the padlock."
        )
    elif tls_status in ("expired", "not_yet_valid", "hostname_mismatch", "self_signed", "untrusted_chain"):
        recommendations.append(
            f"Do not enter credentials — the HTTPS certificate is invalid ({tls.get('status_label')})."
        )
    elif tls_status == "no_tls":
        recommendations.append(
            "The page is served over plain HTTP — anything typed into it can be read or modified in transit."
        )
    return recommendations


async def investigate_link(raw_url: str) -> dict:
    """
    Full link investigation. Raises InvalidURLError / SSRFBlockedError, which
    the API layer maps to clean 400 responses.
    """
    normalized = normalize_url(raw_url)
    initial = await validate_target(normalized["url"], timeout=settings.LINK_FETCH_TIMEOUT)
    if not initial["allowed"] and initial["blocked"]:
        raise SSRFBlockedError(initial["reason"])

    domain_intel = check_domain(normalized)

    dns_task = resolve_domain(
        normalized["host"],
        timeout=settings.LINK_FETCH_TIMEOUT,
        fallback_host=None if normalized["is_ip"] else normalized["registered_domain"],
    )
    chain_task = fetch_redirect_chain(
        normalized["url"],
        max_hops=settings.LINK_MAX_REDIRECTS,
        timeout=settings.LINK_FETCH_TIMEOUT,
        max_bytes=settings.LINK_MAX_RESPONSE_BYTES,
    )
    tls_task = analyze_tls(
        normalized["url"],
        normalized["host"],
        scheme=normalized["scheme"],
        port=normalized["port"],
        timeout=settings.LINK_TLS_TIMEOUT,
        ct_timeout=settings.LINK_CT_TIMEOUT,
        ct_max_bytes=settings.LINK_CT_MAX_BYTES,
        registered_domain=normalized["registered_domain"],
    )

    dns, chain, tls = await asyncio.gather(dns_task, chain_task, tls_task)
    resolved_ips = dns.get("addresses") or initial.get("ips") or []
    reputation = await _collect_reputation(normalized, resolved_ips)

    # --- gather evidence ---
    evidence: list[dict] = []
    indicators: list[dict] = []

    def evidence_item(source: str, finding: str, severity: str = "info", detail: str | None = None):
        evidence.append(
            {"source": source, "finding": finding, "severity": severity, "detail": detail or ""}
        )

    def indicator(kind: str, detail: str, severity: str):
        indicators.append(
            {"type": kind, "value": normalized["host"], "severity": severity, "detail": detail}
        )

    # 1. normalisation
    evidence_item(
        "URL normalisation",
        f"Analysed URL: {normalized['url']}",
        "info",
        "; ".join(normalized["notes"]) if normalized["notes"] else "No changes were required.",
    )
    if normalized["tracking_params_removed"]:
        evidence_item(
            "URL normalisation",
            f"Stripped {len(normalized['tracking_params_removed'])} tracking parameter(s): "
            + ", ".join(normalized["tracking_params_removed"][:6]),
            "info",
        )
    if normalized["homograph"]["is_punycode"] or normalized["homograph"]["decoded_host"] != normalized["host"]:
        evidence_item(
            "IDN / punycode",
            f"Host '{normalized['host']}' displays as '{normalized['homograph']['decoded_host']}'",
            "medium" if normalized["homograph"]["suspicious"] else "info",
            "; ".join(normalized["homograph"]["reasons"]) or "Punycode host decoded to Unicode.",
        )

    # 2. domain intelligence
    for item in domain_intel["indicators"]:
        indicator(item["type"], item["detail"], item["severity"])
        evidence_item(
            "Domain intelligence",
            item["detail"],
            item["severity"],
            f"Rule: {item['type']}",
        )
    if not domain_intel["indicators"]:
        evidence_item(
            "Domain intelligence",
            f"No typosquatting, brand impersonation or suspicious-TLD indicators for '{normalized['registered_domain']}'",
            "info",
        )

    # 3. static URL heuristics
    static_score, static_reasons, static_indicators = _static_checks(normalized)
    for item in static_indicators:
        indicator(item["type"], item["detail"], item["severity"])
    for reason in static_reasons:
        evidence_item("URL heuristics", reason, "medium")
    if not static_reasons:
        evidence_item("URL heuristics", "No suspicious URL structure, keywords or encoding found", "info")

    # 4. DNS
    dns_checks = _dns_result(dns)
    if dns_checks["resolved"]:
        evidence_item(
            "DNS",
            f"{normalized['host']} resolves to {', '.join(dns_checks['addresses'][:4])}",
            "info",
            f"Records: {', '.join(sorted(dns_checks['records'].keys())) or 'A/AAAA'}"
            if dns_checks["records"]
            else "",
        )
    else:
        indicator(
            "dns",
            dns_checks["error"] or f"{normalized['host']} does not resolve",
            "medium",
        )
        evidence_item(
            "DNS",
            dns_checks["error"] or f"{normalized['host']} has no A/AAAA records",
            "medium",
            "The domain failed to resolve; the remaining checks were still completed.",
        )
    dns_score = 0 if dns_checks["resolved"] else DNS_FAILURE_SCORE

    # 5. redirects
    redirect_score, redirect_indicators, redirect_evidence = _redirect_findings(chain)
    for item in redirect_indicators:
        indicator(item["type"], item["detail"], item["severity"])
    for line in redirect_evidence:
        evidence_item("Redirect chain", line, "high" if redirect_score >= REDIRECT_UNRELATED_SCORE else "info")
    if not redirect_evidence:
        evidence_item(
            "Redirect chain",
            f"No redirects — {chain['final_url']} answered directly",
            "info",
        )

    # 5b. TLS certificate
    tls_checks = tls
    tls_score = tls_checks.get("score", 0)
    for item in tls_checks.get("findings", []):
        indicator(item["type"], item["evidence"], item["severity"])
        evidence_item("TLS certificate", item["evidence"], item["severity"], item.get("detail") or "")

    tls_cert = tls_checks.get("certificate")
    if tls_cert:
        issuer_label = (
            tls_cert.get("issuer_organization")
            or tls_cert.get("issuer_common_name")
            or tls_cert.get("issuer")
        )
        remaining = tls_cert.get("days_remaining")
        evidence_item(
            "TLS certificate",
            f"Certificate issued by '{issuer_label}' to '{tls_cert['subject']}', "
            f"valid {tls_cert['not_before']} → {tls_cert['not_after']}"
            + (f" ({remaining} day(s) remaining)" if remaining is not None else " (expired)"),
            "info",
            f"TLS {tls_checks['chain'].get('protocol') or 'unknown'} · "
            f"{tls_cert['signature_algorithm']} · {tls_cert['public_key_type']} "
            f"{tls_cert['public_key_bits'] or ''} key · "
            f"SAN match: {'yes (' + str(tls_checks['hostname'].get('matched_value')) + ')' if tls_checks['hostname'].get('matches') else 'no'} · "
            f"chain trusted: {tls_checks['chain'].get('trusted')}",
        )
    ct = tls_checks.get("ct") or {}
    if ct.get("error"):
        evidence_item("TLS certificate", ct["error"], "low")
    elif ct.get("available"):
        evidence_item(
            "TLS certificate",
            f"Certificate Transparency: {ct.get('count_note')}",
            "info",
            f"{ct.get('recently_issued_count', 0)} issued in the last {ct.get('window_days', 7)} day(s)"
            + (" — recently issued, verify" if ct.get("recently_issued_count") else ""),
        )
    evidence_item("TLS certificate", VALID_CERT_NOTE, "info", "A certificate only proves the HTTPS transport is encrypted and the name matches — not that the operator is honest.")

    # 6. reputation
    rep_summary = reputation["summary"]
    unavailable: list[str] = []
    for ioc_value, verdicts in reputation["results"].items():
        for verdict in verdicts:
            if not verdict.get("checked"):
                if verdict["provider"] not in unavailable:
                    unavailable.append(verdict["provider"])
                continue
            if verdict.get("malicious"):
                confirmed_here = verdict["provider"] in SCAN_CONFIRMING_PROVIDERS
                indicator(
                    "reputation",
                    f"{verdict['provider']} flagged {ioc_value}: {verdict['detail']}",
                    "critical" if confirmed_here else "medium",
                )
                evidence_item(
                    "Reputation",
                    f"{verdict['provider']} flagged {ioc_value} — {verdict['detail']}",
                    "critical" if confirmed_here else "medium",
                    f"Confidence {verdict['confidence']}%"
                    if confirmed_here
                    else "Community-pulse mention only — corroborating evidence, not a scan verdict.",
                )
            else:
                evidence_item(
                    "Reputation",
                    f"{verdict['provider']}: {verdict['detail']} ({ioc_value})",
                    "info",
                )
    if unavailable and not rep_summary["malicious_ioc_count"]:
        evidence_item(
            "Reputation",
            "No reputation source could confirm or clear this URL: " + ", ".join(sorted(unavailable)),
            "low",
            "Provider calls failed or no API key is configured — the verdict below is heuristic-only.",
        )

    scan_confirmed, reputation_score = _reputation_strength(reputation["results"])

    # --- risk ---
    components = {
        "static_url_score": static_score,
        "domain_intel_score": domain_intel["score"],
        "dns_score": dns_score,
        "redirect_score": redirect_score,
        "tls_score": tls_score,
        "reputation_score": reputation_score,
    }
    score = _combine(components)
    if scan_confirmed:
        score = max(score, REPUTATION_MALICIOUS_FLOOR)
    score = min(100, score)
    category = _categorize(score)

    breakdown = {
        **components,
        "weights": {
            "static_url": 1.0,
            "domain_intel": 1.0,
            "dns": EXTRA_SIGNAL_WEIGHT,
            "redirects": EXTRA_SIGNAL_WEIGHT,
            "tls": 1.0,
            "reputation": 1.0,
        },
        "method": "strongest signal + 20% of the corroborating signals, capped at 100",
    }

    # --- link-specific checks (rendered by the Link Checks tab) ---
    checks = {
        "submitted_url": raw_url.strip(),
        "normalized_url": normalized["url"],
        "display_url": normalized["display_url"],
        "host": normalized["host"],
        "display_host": normalized["display_host"],
        "registered_domain": normalized["registered_domain"],
        "suffix": normalized["suffix"],
        "unicode_host": normalized["homograph"]["decoded_host"],
        "is_ip": normalized["is_ip"],
        "tracking_params_removed": normalized["tracking_params_removed"],
        "normalization_notes": normalized["notes"],
        "static_score": static_score,
        "dns": {
            "resolved": dns_checks["resolved"],
            "addresses": dns_checks["addresses"],
            "records": dns_checks["records"],
            "mx": dns_checks["mx"],
            "error": dns_checks["error"],
            "error_kind": dns_checks["error_kind"],
        },
        "redirects": {
            "hops": chain["hops"],
            "hop_count": chain["hop_count"],
            "redirect_count": chain["redirect_count"],
            "max_hops": settings.LINK_MAX_REDIRECTS,
            "final_url": chain["final_url"],
            "final_host": chain["final_host"],
            "domain_changed": chain["domain_changed"],
            "scheme_downgrade": chain["scheme_downgrade"],
            "limit_exceeded": chain["limit_exceeded"],
            "loop_detected": chain["loop_detected"],
            "page_title": chain["page_title"],
            "error": chain["error"],
        },
        "tls": tls_checks,
        "reputation": {
            "results": reputation["results"],
            "summary": rep_summary,
            "unavailable_providers": sorted(unavailable),
        },
        "domain_intel": domain_intel,
        "homograph": normalized["homograph"],
    }

    # --- email-compatible report sections ---
    url_analysis = []
    main_item = analyze_single_url(normalized["url"])
    main_item["url"] = normalized["url"]
    main_item["domain"] = normalized["registered_domain"] or normalized["host"]
    main_item["reasons"] = static_reasons or main_item.get("reasons", [])
    main_item["risk_score"] = static_score
    main_item["risk"] = "HIGH" if static_score >= 50 else "MEDIUM" if static_score >= 20 else "LOW"
    url_analysis.append(main_item)

    if chain["domain_changed"] and chain["final_url"] != normalized["url"]:
        final_item = analyze_single_url(chain["final_url"])
        final_item["reasons"] = list(final_item.get("reasons", [])) + [
            f"Redirect destination reached from {normalized['host']}"
        ]
        url_analysis.append(final_item)

    header_analysis = {
        "spf": "N/A",
        "dkim": "N/A",
        "dmarc": "N/A",
        "sender_domain": normalized["registered_domain"] or normalized["host"],
        "return_path_domain": None,
        "domain_mismatch": False,
        "spoofing_risk": "LOW",
        "reasons": [
            "Link-only investigation — email authentication (SPF/DKIM/DMARC) does not apply.",
            f"Submitted host: {normalized['host']}",
        ],
    }

    parsed = {
        "from_addr": None,
        "to_addr": None,
        "subject": f"Link investigation — {normalized['display_host']}",
        "date": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "return_path": None,
        "reply_to": None,
        "received_headers": [],
        "body_text": chain.get("page_title") or "",
        "urls": [normalized["url"]] + ([chain["final_url"]] if chain["domain_changed"] else []),
        "attachments": [],
        "origin_url": normalized["url"],
        "display_url": normalized["display_url"],
        "investigation_type": "link",
    }

    ioc_summary = extract_iocs(
        {
            "from_addr": None,
            "body_text": "",
            "received_headers": [],
        },
        url_analysis,
        [],
    )
    if dns_checks["addresses"]:
        ioc_summary["ips"] = sorted({*ioc_summary["ips"], *dns_checks["addresses"][:4]})
    if normalized["registered_domain"]:
        ioc_summary["domains"] = sorted({*ioc_summary["domains"], normalized["registered_domain"]})

    mitre = map_techniques(header_analysis, url_analysis, [])

    ## Website Security Checks (passive)
    #
    # Security headers and the HTTP/TLS configuration come from the redirect
    # chain this investigation already fetched - the target is not requested a
    # second time for them. The only extra requests are one plain GET each to
    # /.env and /.git/HEAD, issued by the SSRF-validated probe below.

    hops = chain.get("hops") or []
    # Only a hop that actually returned an HTTP response carries headers; a DNS
    # failure records a hop with no status at all.
    fetched = any(hop.get("status") is not None for hop in hops)

    header_state: dict[str, dict] = {}
    http_config: dict = {}
    findings: list[dict] = []
    not_exposed: list[dict] = []

    if not fetched:
        website_security = {
            "status": "website checks unavailable",
            "summary": "Website checks unavailable - the target could not be fetched",
            "headers_present": 0,
            "headers_total": len(SECURITY_RESPONSE_HEADERS),
            "headers": {},
            "http": {},
            "findings": [],
            "not_exposed": [],
        }
    else:
        # Merge the security headers seen across every hop of the chain.
        all_headers: dict[str, str] = {}
        for hop in hops:
            for name, value in (hop.get("headers") or {}).items():
                all_headers[name.lower()] = value

        # --- HTTP configuration (from data already fetched) ---
        final_url = chain.get("final_url") or normalized["url"]
        final_scheme = "http" if final_url.lower().startswith("http://") else "https"
        submitted_scheme = normalized["scheme"]
        plain_http = final_scheme == "http"
        redirects_to_https = submitted_scheme == "http" and final_scheme == "https"
        started_on_http = any(
            (hop.get("url") or "").lower().startswith("http://") for hop in hops
        )
        tls_version = (tls_checks.get("chain") or {}).get("protocol") or None

        http_config = {
            "submitted_scheme": submitted_scheme,
            "final_scheme": final_scheme,
            "final_url": final_url,
            "plain_http": plain_http,
            "started_on_http": started_on_http,
            "redirects_to_https": redirects_to_https,
            "tls_version": tls_version,
            "tls_status": tls_checks.get("status"),
        }

        # --- Security headers ---
        for header in SECURITY_RESPONSE_HEADERS:
            present = header in all_headers
            header_state[header] = {
                "present": present,
                "value": all_headers.get(header) if present else None,
            }
            if present:
                findings.append(
                    {
                        "issue": f"Security header present: {header.upper()}",
                        "technical evidence": (
                            f"Header '{header.upper()}' returned in the response: "
                            f"{str(all_headers[header])[:200]}"
                        ),
                        "potential impact": (
                            f"{header.upper()} is enforced and provides its intended protection."
                        ),
                        "severity": "Low",
                        "recommended remediation": "Maintain this header configuration.",
                        "relevant limitation": (
                            "Header presence alone does not prove the policy is well configured."
                        ),
                    }
                )
                continue

            # A missing header is Low or Medium, never Critical. The single
            # high-severity case is HSTS absent on a site still served over HTTP.
            if header == "strict-transport-security" and plain_http:
                severity = "High"
            elif header in ("referrer-policy", "permissions-policy"):
                severity = "Low"
            else:
                severity = "Medium"
            findings.append(
                {
                    "issue": f"Security header missing: {header.upper()}",
                    "technical evidence": (
                        f"Response headers did not include '{header.upper()}'"
                        + (" (site is served over plain HTTP)" if plain_http else "")
                    ),
                    "potential impact": (
                        f"Without {header.upper()} the browser has no instruction for the "
                        "class of attack that header mitigates."
                    ),
                    "severity": severity,
                    "recommended remediation": f"Return a {header.upper()} header with an appropriate policy.",
                    "relevant limitation": (
                        "Read from one unauthenticated response of the final URL; other "
                        "routes or CDN edge nodes may differ."
                    ),
                }
            )

        # --- HTTP configuration finding ---
        hsts_present = header_state["strict-transport-security"]["present"]
        if plain_http:
            http_severity = "High"
            http_evidence = (
                f"Site is served over plain HTTP ({final_url}); "
                f"HSTS {'present' if hsts_present else 'missing'}; no HTTPS upgrade observed"
            )
            http_impact = (
                "Traffic is transmitted in cleartext, so credentials, cookies and page "
                "content can be read or modified in transit."
            )
            http_remediation = (
                "Serve the site over HTTPS with a valid certificate and redirect all HTTP "
                "traffic to it."
            )
        elif redirects_to_https:
            http_severity = "Low"
            http_evidence = (
                f"http:// was redirected to {final_url}; "
                f"TLS {tls_version or (tls_checks.get('status_label') or 'not checked')}"
            )
            http_impact = "The HTTP request is upgraded to HTTPS before any content is served."
            http_remediation = "Maintain the HTTP-to-HTTPS redirect."
        else:
            http_severity = "Low"
            http_evidence = (
                f"Site is served over HTTPS ({final_url}); TLS "
                f"{tls_version or (tls_checks.get('status_label') or 'not checked')}"
            )
            http_impact = "Content is delivered over an encrypted channel."
            http_remediation = "Maintain HTTPS enforcement."

        findings.append(
            {
                "issue": "HTTP configuration assessed",
                "technical evidence": http_evidence,
                "potential impact": http_impact,
                "severity": http_severity,
                "recommended remediation": http_remediation,
                "relevant limitation": (
                    f"Reflects the redirect chain that was followed (max "
                    f"{settings.LINK_MAX_REDIRECTS} hops); TLS details describe the final hop only."
                ),
            }
        )

        # --- Exposed sensitive endpoints (passive, same host, two paths only) ---
        try:
            probes = await probe_sensitive_paths(final_url, timeout=settings.LINK_FETCH_TIMEOUT)
        except Exception as exc:  # a probe must never break the investigation
            probes = []
            for path in SENSITIVE_PROBE_PATHS:
                not_exposed.append(
                    {
                        "path": f"/{path}",
                        "status": None,
                        "evidence": f"not checked - probe failed ({type(exc).__name__})",
                    }
                )

        for probe in probes:
            if probe.get("exposed"):
                findings.append(
                    {
                        "issue": f"Exposed sensitive endpoint: {probe['path']}",
                        "technical evidence": (
                            f"GET {probe['url']} returned HTTP {probe['status']} with "
                            f"{probe['bytes_read']} byte(s) of content"
                        ),
                        "potential impact": (
                            "A reachable .env or .git/HEAD can disclose secrets, API keys, "
                            "or source history to anyone who requests it."
                        ),
                        "severity": "High",
                        "recommended remediation": (
                            "Deny access to hidden files and the .git directory at the "
                            "web-server or CDN layer."
                        ),
                        "relevant limitation": (
                            "Only the status code and body size were checked; the body was "
                            "not inspected, so exposure is proven but the leaked data is unknown."
                        ),
                    }
                )
            else:
                status = probe.get("status")
                if status is None:
                    probe_evidence = f"not exposed - {probe.get('error') or 'no response'}"
                else:
                    probe_evidence = probe.get("note") or f"HTTP {status} - not exposed"
                not_exposed.append(
                    {"path": probe["path"], "status": status, "evidence": probe_evidence}
                )

        present_count = sum(1 for state in header_state.values() if state["present"])
        summary = f"{present_count} of {len(SECURITY_RESPONSE_HEADERS)} security headers present"
        if plain_http:
            summary += " (site served over plain HTTP)"
        if any(f["severity"] == "High" and f["issue"].startswith("Exposed") for f in findings):
            summary += "; exposed sensitive endpoint detected"

        website_security = {
            "status": "assessed",
            "summary": summary,
            "headers_present": present_count,
            "headers_total": len(SECURITY_RESPONSE_HEADERS),
            "headers": header_state,
            "http": http_config,
            "findings": findings,
            "not_exposed": not_exposed,
        }

    # These findings are deterministic - the AI may explain them, never decide them.
    checks["website_security"] = website_security

    recommendations = _recommendations(category, checks)

    ai_evidence = {
        "investigation_type": "standalone_url",
        "url": normalized["url"],
        "host": normalized["host"],
        "registered_domain": normalized["registered_domain"],
        "typosquat_brand": domain_intel["brand"],
        "homograph_suspicious": normalized["homograph"]["suspicious"],
        "suspicious_tld": domain_intel["suspicious_tld"],
        "dns_resolved": dns_checks["resolved"],
        "dns_error": dns_checks["error"],
        "tls_status": tls_checks.get("status"),
        "tls_issuer": (tls_cert or {}).get("issuer_organization")
        or (tls_cert or {}).get("issuer_common_name"),
        "tls_expired": bool((tls_cert or {}).get("expired")),
        "tls_not_yet_valid": bool((tls_cert or {}).get("not_yet_valid")),
        "tls_self_signed": bool((tls_cert or {}).get("self_signed")),
        "tls_hostname_match": (tls_checks.get("hostname") or {}).get("matches"),
        "tls_chain_trusted": (tls_checks.get("chain") or {}).get("trusted"),
        "tls_compromised_ca": (tls_checks.get("compromised_ca") or {}).get("matched"),
        "tls_ct_recently_issued": (tls_checks.get("ct") or {}).get("recently_issued_count"),
        "redirect_count": chain["redirect_count"],
        "redirects_to_unrelated_domain": chain["domain_changed"],
        "final_url": chain["final_url"],
        "url_heuristic_reasons": static_reasons,
        "threat_intel_malicious_count": rep_summary["malicious_ioc_count"],
        "threat_intel_scan_confirmed": scan_confirmed,
        "threat_intel_malicious_iocs": rep_summary["malicious_iocs"],
        "threat_intel_unavailable_providers": sorted(unavailable),
        "risk_score": score,
        "risk_category": category,
    }
    ai_verdict = get_ai_verdict(ai_evidence)

    summary_line = (
        f"{VERDICT_BY_CATEGORY[category]} ({score}/100) — {len(indicators)} indicator(s), "
        f"{chain['redirect_count']} redirect(s), "
        f"{'DNS resolved' if dns_checks['resolved'] else 'DNS did not resolve'}, "
        f"TLS {tls_checks.get('status_label') or 'not checked'}"
    )

    # Map the 0-100 score to the 5-class risk_class (Prompt 3 mapping)
    risk_class = risk_class_for(
        score, has_threat_intel=(reputation.get("summary", {}).get("malicious_ioc_count", 0) > 0)
    )

    # Website security assessment (passive, no re-fetch)

    return {
        "investigation_type": "link",
        "checks": checks,
        "website_security": website_security,
        "risk_class": risk_class,
        # summary fields (0-10 score mirrors risk_report.score, which stays 0-100)
        "verdict": VERDICT_BY_CATEGORY[category],
        "risk_score": round(score / 10, 1),
        "summary": summary_line,
        "indicators": indicators,
        "evidence": evidence,
        "recommendations": recommendations,
        # email-compatible sections — the existing dashboard renders these unchanged
        "parsed": parsed,
        "header_analysis": header_analysis,
        "url_analysis": url_analysis,
        "attachment_analysis": [],
        "ioc_summary": ioc_summary,
        "threat_intel": {"results": reputation["results"], "summary": rep_summary},
        "mitre_techniques": mitre,
        "risk_report": {"score": score, "category": category, "breakdown": breakdown},
        "ai_verdict": ai_verdict,
        "analyzed_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }
