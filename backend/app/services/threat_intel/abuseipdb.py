import httpx

from app.config import settings
from .base import ThreatIntelProvider, IOCVerdict


class AbuseIPDBProvider(ThreatIntelProvider):
    name = "AbuseIPDB"
    supported_types = {"ip"}
    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    async def check(self, ioc_type: str, value: str) -> IOCVerdict:
        if not self.supports(ioc_type):
            return self._unavailable(ioc_type, value, "unsupported IOC type")
        if not settings.ABUSEIPDB_API_KEY:
            return self._unavailable(ioc_type, value, "missing API key")

        headers = {"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": value, "maxAgeInDays": 90}

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(self.BASE_URL, headers=headers, params=params)
            resp.raise_for_status()
            data = resp.json()["data"]

            score = data.get("abuseConfidenceScore", 0)
            reports = data.get("totalReports", 0)
            is_malicious = score >= 50
            detail = f"Abuse confidence {score}% based on {reports} community reports"

            return IOCVerdict(self.name, ioc_type, value, is_malicious, score, detail)

        except Exception as e:
            return self._unavailable(ioc_type, value, str(e))