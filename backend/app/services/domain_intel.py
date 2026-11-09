"""
Domain-level heuristics for the standalone link investigator:

- typosquatting / brand impersonation against backend/brands.json
- confusable (homograph) character detection
- suspicious TLD detection, especially when combined with a brand-like name

All offline — no network calls.
"""

import json
from functools import lru_cache
from pathlib import Path

from app.services.url_normalizer import (
    confusable_skeleton,
    is_homograph_risk,
    is_ip_address,
    normalize_text,
)

BRANDS_PATH = Path(__file__).resolve().parents[2] / "brands.json"

# Score contributions (0-100 scale, same scale the rest of the app uses).
_SCORE_BRAND_IN_DOMAIN = 40
_SCORE_BRAND_IN_SUBDOMAIN = 35
_SCORE_BRAND_IN_PATH = 25
_SCORE_TYPOSQUAT = 45
_SCORE_CONFUSABLE_TYPOSQUAT = 50
_SCORE_SUSPICIOUS_TLD = 10
_SCORE_SUSPICIOUS_TLD_WITH_BRAND = 15
_SCORE_HOMOGRAPH = 45
_SCORE_IP_LITERAL = 20


@lru_cache(maxsize=1)
def load_brands() -> dict:
    with open(BRANDS_PATH, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    return {
        "brands": data.get("brands", []),
        "suspicious_tlds": {tld.lower() for tld in data.get("suspicious_tlds", [])},
    }


def levenshtein(a: str, b: str, max_distance: int = 3) -> int:
    """Bounded Levenshtein distance (returns max_distance + 1 once exceeded)."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1

    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost))
        if min(current) > max_distance:
            return max_distance + 1
        previous = current
    return previous[-1]


def _brand_for_name(name: str) -> str | None:
    """Returns the brand whose token appears in `name`, if any."""
    lowered = normalize_text(name)
    skeleton = confusable_skeleton(lowered)
    for brand in load_brands()["brands"]:
        for token in brand["tokens"]:
            if token in lowered or token in skeleton:
                return brand["name"]
    return None


def check_domain(normalized: dict) -> dict:
    """
    Runs every offline domain heuristic on a dict from normalize_url().

    Returns {"score": 0-100, "indicators": [...], "brand": str|None, ...}
    """
    host = normalized["host"]
    registered = normalized.get("registered_domain") or host
    suffix = (normalized.get("suffix") or "").lower()
    path = (normalized.get("path") or "").lower()
    domain_label = normalized.get("domain_label") or registered
    subdomain = normalized.get("subdomain") or ""

    indicators: list[dict] = []
    matched_brand = None
    score = 0

    def add(kind: str, detail: str, severity: str, points: int):
        nonlocal score
        score += points
        indicators.append({"type": kind, "detail": detail, "severity": severity})

    # --- raw IP host ---
    if normalized.get("is_ip") or is_ip_address(host):
        add(
            "ip_literal",
            f"Link points directly at IP address {host} instead of a domain name",
            "medium",
            _SCORE_IP_LITERAL,
        )

    # --- homograph / confusable characters ---
    homograph = is_homograph_risk(host)
    if homograph["suspicious"]:
        add(
            "homograph",
            "; ".join(homograph["reasons"]) + " — possible homograph (IDN spoofing) attack",
            "high",
            _SCORE_HOMOGRAPH,
        )

    brands = load_brands()
    official_domains = {d.lower() for b in brands["brands"] for d in b["official_domains"]}
    is_official = registered.lower() in official_domains or host.lower() in official_domains

    if not is_official:
        labels = [label for label in [domain_label, *subdomain.split(".")] if label]
        skeleton_domain = confusable_skeleton(domain_label)

        for brand in brands["brands"]:
            brand_name = brand["name"]
            tokens = brand["tokens"]
            hit_in_domain = next((t for t in tokens if t in domain_label.lower()), None)
            hit_in_skeleton = next(
                (t for t in tokens if len(t) >= 3 and t in skeleton_domain), None
            )
            hit_in_subdomain = next(
                (t for t in tokens if any(t in label.lower() for label in subdomain.split(".") if label)),
                None,
            )

            if hit_in_domain or hit_in_skeleton:
                matched_brand = matched_brand or brand_name
                token = hit_in_domain or hit_in_skeleton
                extra = "" if not hit_in_skeleton or hit_in_domain else " (after homoglyph normalisation)"
                near_miss = next(
                    (
                        candidate
                        for candidate in tokens
                        if len(candidate) >= 4
                        and domain_label.lower() != candidate
                        and 1 <= levenshtein(domain_label.lower(), candidate) <= 2
                    ),
                    None,
                )
                if near_miss:
                    add(
                        "typosquatting",
                        f"Domain '{registered}' is a near-miss misspelling of '{near_miss}' "
                        f"({brand_name}) — likely typosquat",
                        "high",
                        _SCORE_TYPOSQUAT,
                    )
                else:
                    add(
                        "brand_impersonation",
                        f"Registered domain '{registered}' contains brand token '{token}' "
                        f"but is not an official {brand_name} domain{extra}",
                        "high",
                        _SCORE_BRAND_IN_DOMAIN,
                    )
                break

            if hit_in_subdomain:
                matched_brand = matched_brand or brand_name
                add(
                    "brand_impersonation",
                    f"Brand token '{hit_in_subdomain}' ({brand_name}) used as a subdomain "
                    f"of unrelated domain '{registered}' — classic brand-in-subdomain spoof",
                    "high",
                    _SCORE_BRAND_IN_SUBDOMAIN,
                )
                break

            # --- typosquatting: near-miss label of a brand's own domain label ---
            for token in tokens:
                if len(token) < 4:
                    continue
                for candidate in labels:
                    distance = levenshtein(candidate.lower(), token)
                    if 1 <= distance <= 2:
                        matched_brand = matched_brand or brand_name
                        add(
                            "typosquatting",
                            f"Domain label '{candidate}' is {distance} character(s) away from "
                            f"'{token}' ({brand_name}) — likely typosquat",
                            "high",
                            _SCORE_TYPOSQUAT,
                        )
                        break
                else:
                    continue
                break

            # --- confusable typosquat: paypa1 / g00gle / sbi-vérify ---
            if not (hit_in_domain or hit_in_skeleton):
                for token in tokens:
                    if len(token) < 3:
                        continue
                    if token in skeleton_domain and token not in domain_label.lower():
                        matched_brand = matched_brand or brand_name
                        add(
                            "typosquatting",
                            f"Domain label '{domain_label}' mimics '{token}' using "
                            f"confusable characters (resolves to '{skeleton_domain}')",
                            "high",
                            _SCORE_CONFUSABLE_TYPOSQUAT,
                        )
                        break

        path_brand = _brand_for_name(path) if path else None
        if path_brand and not matched_brand:
            matched_brand = path_brand
            add(
                "brand_impersonation",
                f"URL path references brand '{path_brand}' on unrelated domain '{registered}'",
                "medium",
                _SCORE_BRAND_IN_PATH,
            )

    # --- suspicious TLD, weighted by how brand-like the name is ---
    if suffix and suffix in brands["suspicious_tlds"]:
        brand_like = _brand_for_name(domain_label) or _brand_for_name(registered)
        if brand_like or matched_brand:
            add(
                "suspicious_tld",
                f"Suspicious TLD '.{suffix}' combined with brand-like name "
                f"'{domain_label or registered}' — high-abuse namespace",
                "high",
                _SCORE_SUSPICIOUS_TLD + _SCORE_SUSPICIOUS_TLD_WITH_BRAND,
            )
        else:
            add(
                "suspicious_tld",
                f"'.{suffix}' is a high-abuse TLD often used for throwaway phishing domains",
                "medium",
                _SCORE_SUSPICIOUS_TLD,
            )

    return {
        "score": min(score, 100),
        "indicators": indicators,
        "brand": matched_brand,
        "is_official_brand_domain": is_official,
        "suspicious_tld": suffix in brands["suspicious_tlds"],
        "homograph": homograph,
        "registered_domain": registered,
        "domain_label": domain_label,
        "suffix": suffix,
    }
