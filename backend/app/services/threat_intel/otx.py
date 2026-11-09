import httpx

from app.config import settings
from .base import ThreatIntelProvider, IOCVerdict


class OTXProvider(ThreatIntelProvider):
    name = "AlienVault OTX"
    supported_types = {"domain", "ip", "hash"}
    BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

    SECTION_MAP = {"domain": "domain", "ip": "IPv4", "hash": "file"}

    async def check(self, ioc_type: str, value: str) -> IOCVerdict:
        if not self.supports(ioc_type):
            return self._unavailable(ioc_type, value, "unsupported IOC type")
        if not settings.OTX_API_KEY:
            return self._unavailable(ioc_type, value, "missing API key")

        section = self.SECTION_MAP[ioc_type]
        headers = {"X-OTX-API-KEY": settings.OTX_API_KEY}
        url = f"{self.BASE_URL}/{section}/{value}/general"

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()

            pulse_count = data.get("pulse_info", {}).get("count", 0)
            is_malicious = pulse_count > 0
            confidence = min(pulse_count * 20, 100)
            detail = (
                f"Found in {pulse_count} community threat-intel pulse(s)"
                if pulse_count else "No threat pulses found"
            )

            return IOCVerdict(self.name, ioc_type, value, is_malicious, confidence, detail)

        except httpx.HTTPStatusError as e:
            status = e.response.status_code
            if status == 404:
                # OTX returns 404 for indicators it has never indexed —
                # this is a valid "clean/unknown" result, not a failure.
                return IOCVerdict(
                    self.name, ioc_type, value, False, 0,
                    "Not indexed in AlienVault OTX", checked=True,
                )
            if status == 429:
                return self._unavailable(ioc_type, value, "rate limit exceeded (429)")
            if status == 403:
                return self._unavailable(ioc_type, value, "invalid or unauthorized API key (403)")
            return self._unavailable(ioc_type, value, f"HTTP {status} error from OTX")

        except httpx.TimeoutException:
            return self._unavailable(ioc_type, value, "request timed out")

        except httpx.RequestError as e:
            return self._unavailable(ioc_type, value, f"network error ({type(e).__name__})")

        except (KeyError, ValueError) as e:
            return self._unavailable(ioc_type, value, f"unexpected response format ({type(e).__name__})")

        except Exception as e:
            # Last-resort catch-all — always include the exception type
            # so the reason is never a blank string in the UI.
            reason = str(e) or type(e).__name__
            return self._unavailable(ioc_type, value, reason)