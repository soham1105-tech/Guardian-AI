import asyncio
from typing import Dict, List

from .base import IOCVerdict
from .virustotal import VirusTotalProvider
from .abuseipdb import AbuseIPDBProvider
from .urlhaus import URLhausProvider
from .urlscan import URLScanProvider
from .otx import OTXProvider

PROVIDERS = [
    VirusTotalProvider(),
    AbuseIPDBProvider(),
    URLhausProvider(),
    URLScanProvider(),
    OTXProvider(),
]

# Maps our internal IOC summary keys to the generic ioc_type used by providers
TYPE_MAP = {"ips": "ip", "domains": "domain", "urls": "url", "hashes": "hash"}


async def check_ioc(ioc_type: str, value: str) -> List[IOCVerdict]:
    applicable = [p for p in PROVIDERS if p.supports(ioc_type)]
    if not applicable:
        return []
    return list(await asyncio.gather(*(p.check(ioc_type, value) for p in applicable)))


async def check_iocs_batch(ioc_summary: dict, max_per_type: int = 5) -> Dict[str, list]:
    """
    Checks a limited number of IOCs per type (to respect free-tier rate limits)
    against every applicable provider, concurrently.

    A single IOC value can legitimately appear under more than one type
    (rare, but possible after extraction) — results are merged per value
    rather than overwritten, so no provider result is silently lost.

    Returns: { "<ioc_value>": [ {provider, malicious, confidence, detail, checked}, ... ] }
    """
    tasks, keys = [], []

    for summary_key, ioc_type in TYPE_MAP.items():
        values = ioc_summary.get(summary_key, [])[:max_per_type]
        for value in values:
            tasks.append(check_ioc(ioc_type, value))
            keys.append(value)

    if not tasks:
        return {}

    results = await asyncio.gather(*tasks)

    output: Dict[str, list] = {}
    for key, verdicts in zip(keys, results):
        formatted = [
            {
                "provider": v.provider,
                "malicious": v.malicious,
                "confidence": v.confidence,
                "detail": v.detail,
                "checked": v.checked,
            }
            for v in verdicts
        ]
        if key in output:
            output[key].extend(formatted)
        else:
            output[key] = formatted

    return output


def summarize_threat_intel(threat_intel_results: dict) -> dict:
    """Produces a compact summary used by the risk engine and AI evidence."""
    malicious_iocs = [
        ioc_value
        for ioc_value, verdicts in threat_intel_results.items()
        if any(v["checked"] and v["malicious"] for v in verdicts)
    ]
    max_confidence = 0
    for verdicts in threat_intel_results.values():
        for v in verdicts:
            if v["checked"] and v["malicious"]:
                max_confidence = max(max_confidence, v["confidence"])

    return {
        "total_iocs_checked": len(threat_intel_results),
        "malicious_ioc_count": len(malicious_iocs),
        "malicious_iocs": malicious_iocs,
        "max_confidence": max_confidence,
    }