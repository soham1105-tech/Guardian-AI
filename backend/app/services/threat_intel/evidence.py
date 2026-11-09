"""Threat-intel evidence qualification (single-vendor false-positive fix).

A reputation flag counts as *qualifying* malicious evidence only when:
- the source reports an independent vendor/flag/scan count and that count is >= 2, OR
- the source reports no such vendor count but a second independent source also reports
  a positive (checked) match for the same IOC.

A single-vendor flag (e.g. 1/92) is recorded as an informational note, contributes 0 to
risk scoring, and can never trigger Confirmed Malicious.
"""

from __future__ import annotations

import re

VENDOR_EVIDENCE_THRESHOLD = 2

# Providers whose positive verdict is an actual scan/blocklist verdict with a count of
# independent flagging entities in the detail (e.g. VT "N/total vendors").
VENDOR_COUNT_PROVIDERS = {"VirusTotal", "URLScan.io"}

INFORMATIONAL_SINGLE_VENDOR_NOTE = (
    "1 vendor flagged this domain (below the evidence threshold of 2) — not counted toward the score"
)

_VT_VENDORS = re.compile(r"^(\d+)/\d+\s+vendors?\s+flagged", re.IGNORECASE)
_URLSCAN_HITS = re.compile(r"^(\d+)\s+of\s+\d+\s+urlscan\.io\s+scan", re.IGNORECASE)


def parse_vendor_count(provider: str, detail: str) -> int | None:
    detail = detail or ""
    if provider == "VirusTotal":
        m = _VT_VENDORS.search(detail)
        return int(m.group(1)) if m else None
    if provider == "URLScan.io":
        m = _URLSCAN_HITS.search(detail)
        return int(m.group(1)) if m else None
    return None


def qualifies_standalone(provider: str, verdict: dict) -> bool:
    """True when this verdict alone qualifies as TI evidence (vendor-count source, >=2)."""
    if not verdict.get("checked") or not verdict.get("malicious"):
        return False
    count = verdict.get("vendor_count")
    if count is None:
        count = parse_vendor_count(provider, verdict.get("detail") or "")
    if count is not None:
        return count >= VENDOR_EVIDENCE_THRESHOLD
    # No vendor count (OTX pulses, URLhaus listing, AbuseIPDB score, etc.): not standalone.
    return False


def is_positive_checked(verdict: dict) -> bool:
    return bool(verdict.get("checked") and verdict.get("malicious"))


def qualifying_for_ioc(verdicts: list[dict]) -> list[dict]:
    """Return verdicts that count as qualifying TI evidence for one IOC.

    - vendor-count positives qualify alone when count >= 2
    - no-vendor-count positives qualify only when corroborated by a second independent
      positive source for the same IOC (another qualifying vendor-count positive OR any
      other independent positive source)
    """
    standalone = []
    non_vendor_positive = []
    for v in verdicts or []:
        if not is_positive_checked(v):
            continue
        provider = v.get("provider") or ""
        if qualifies_standalone(provider, v):
            standalone.append(v)
        else:
            count = v.get("vendor_count")
            if count is None:
                count = parse_vendor_count(provider, v.get("detail") or "")
            # Single-vendor flag: explicitly not qualifying, never corroborates.
            if count is not None and count < VENDOR_EVIDENCE_THRESHOLD:
                continue
            non_vendor_positive.append(v)

    qualifying = list(standalone)
    # No-vendor-count positives need corroboration from a second independent source.
    if len(non_vendor_positive) >= 2 or (non_vendor_positive and standalone):
        qualifying.extend(non_vendor_positive)
    return qualifying


def has_qualifying_ti_match(threat_intel_results: dict) -> bool:
    for verdicts in (threat_intel_results or {}).values():
        if qualifying_for_ioc(verdicts):
            return True
    return False


def qualifying_malicious_iocs(threat_intel_results: dict) -> list[str]:
    return [ioc for ioc, verdicts in (threat_intel_results or {}).items() if qualifying_for_ioc(verdicts)]


def qualifying_max_confidence(threat_intel_results: dict) -> int:
    max_c = 0
    for verdicts in (threat_intel_results or {}).values():
        for v in qualifying_for_ioc(verdicts):
            max_c = max(max_c, int(v.get("confidence") or 0))
    return max_c
