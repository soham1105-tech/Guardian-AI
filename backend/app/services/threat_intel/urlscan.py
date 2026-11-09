import httpx

from app.config import settings
from .base import ThreatIntelProvider, IOCVerdict
from .evidence import VENDOR_EVIDENCE_THRESHOLD


class URLScanProvider(ThreatIntelProvider):
    """
    URLScan.io — free community scanning service.

    Uses the search API (a previously submitted scan) rather than the
    submission API: we never push a user's link to a public third party
    from inside an investigation. The search API needs a free API key.
    """
    name = "URLScan.io"
    supported_types = {"url", "domain"}
    BASE_URL = "https://urlscan.io/api/v1/search/"

    async def check(self, ioc_type: str, value: str) -> IOCVerdict:
        if not settings.URLSCAN_API_KEY:
            return self._unavailable(ioc_type, value, "missing API key (URLSCAN_API_KEY)")
        if not self.supports(ioc_type):
            return self._unavailable(ioc_type, value, "unsupported IOC type")

        query = f'page.url:"{value}"' if ioc_type == "url" else f"domain:{value}"

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    self.BASE_URL,
                    params={"q": query, "size": 10},
                    headers={"API-Key": settings.URLSCAN_API_KEY},
                )
            if resp.status_code in (401, 403):
                return self._unavailable(ioc_type, value, f"API key rejected (HTTP {resp.status_code})")
            if resp.status_code == 429:
                return self._unavailable(ioc_type, value, "rate limit reached")
            resp.raise_for_status()
            data = resp.json()

            total = int(data.get("total", 0) or 0)
            if total == 0:
                return IOCVerdict(self.name, ioc_type, value, False, 0, "No previous urlscan.io scans found")

            malicious_hits = []
            best_score = 0
            for result in data.get("results", [])[:10]:
                overall = (result.get("verdicts") or {}).get("overall") or {}
                score = int(overall.get("score", 0) or 0)
                if overall.get("malicious"):
                    malicious_hits.append((result.get("page") or {}).get("url", value))
                    best_score = max(best_score, score)

            hit_count = len(malicious_hits)
            if hit_count == 1:
                return IOCVerdict(
                    self.name, ioc_type, value, False, 0,
                    f"1 urlscan.io scan returned a malicious verdict (below the evidence threshold of {VENDOR_EVIDENCE_THRESHOLD}) — not counted toward the score",
                    checked=True,
                    vendor_count=1,
                    qualifying=False,
                )
            if hit_count >= VENDOR_EVIDENCE_THRESHOLD:
                confidence = min(100, max(60, best_score))
                return IOCVerdict(
                    self.name,
                    ioc_type,
                    value,
                    True,
                    confidence,
                    f"{hit_count} of {total} urlscan.io scan(s) returned a malicious verdict (score {best_score})",
                    checked=True,
                    vendor_count=hit_count,
                    qualifying=True,
                )

            return IOCVerdict(
                self.name, ioc_type, value, False, 0, f"{total} previous urlscan.io scan(s), none flagged malicious"
            )

        except httpx.HTTPStatusError as e:
            return self._unavailable(ioc_type, value, f"HTTP {e.response.status_code} error from urlscan.io")
        except httpx.TimeoutException:
            return self._unavailable(ioc_type, value, "request timed out")
        except httpx.RequestError as e:
            return self._unavailable(ioc_type, value, f"network error ({type(e).__name__})")
        except (KeyError, ValueError, TypeError) as e:
            return self._unavailable(ioc_type, value, f"unexpected response format ({type(e).__name__})")
        except Exception as e:
            return self._unavailable(ioc_type, value, str(e) or type(e).__name__)
