import httpx

from .base import ThreatIntelProvider, IOCVerdict


class URLhausProvider(ThreatIntelProvider):
    """
    URLhaus (abuse.ch) — no API key required, free open API
    for known malware distribution URLs.
    """
    name = "URLhaus"
    supported_types = {"url"}
    BASE_URL = "https://urlhaus-api.abuse.ch/v1/url/"

    async def check(self, ioc_type: str, value: str) -> IOCVerdict:
        if not self.supports(ioc_type):
            return self._unavailable(ioc_type, value, "unsupported IOC type")

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(self.BASE_URL, data={"url": value})
            resp.raise_for_status()
            data = resp.json()

            if data.get("query_status") != "ok":
                return IOCVerdict(self.name, ioc_type, value, False, 0, "Not found in URLhaus malware database")

            threat = data.get("threat", "malware_download")
            status = data.get("url_status", "unknown")
            detail = f"Listed in URLhaus as '{threat}' (status: {status})"

            return IOCVerdict(self.name, ioc_type, value, True, 90, detail)

        except httpx.ConnectError as e:
            # Covers SSL certificate failures and general connection issues
            reason = str(e)[:120] or "connection/SSL error"
            return self._unavailable(ioc_type, value, f"connection/SSL error: {reason}")

        except httpx.HTTPStatusError as e:
            return self._unavailable(ioc_type, value, f"HTTP {e.response.status_code} error from URLhaus")

        except httpx.TimeoutException:
            return self._unavailable(ioc_type, value, "request timed out")

        except httpx.RequestError as e:
            return self._unavailable(ioc_type, value, f"network error ({type(e).__name__})")

        except (KeyError, ValueError) as e:
            return self._unavailable(ioc_type, value, f"unexpected response format ({type(e).__name__})")

        except Exception as e:
            reason = str(e) or type(e).__name__
            return self._unavailable(ioc_type, value, reason)