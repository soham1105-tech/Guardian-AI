import base64
import httpx

from app.config import settings
from .base import ThreatIntelProvider, IOCVerdict


class VirusTotalProvider(ThreatIntelProvider):
    name = "VirusTotal"
    supported_types = {"domain", "url", "hash"}
    BASE_URL = "https://www.virustotal.com/api/v3"

    async def check(self, ioc_type: str, value: str) -> IOCVerdict:
        if not settings.VIRUSTOTAL_API_KEY:
            return self._unavailable(ioc_type, value, "missing API key")
        if not self.supports(ioc_type):
            return self._unavailable(ioc_type, value, "unsupported IOC type")

        headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                if ioc_type == "domain":
                    resp = await client.get(f"{self.BASE_URL}/domains/{value}", headers=headers)
                elif ioc_type == "url":
                    url_id = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
                    resp = await client.get(f"{self.BASE_URL}/urls/{url_id}", headers=headers)
                else:  # hash
                    resp = await client.get(f"{self.BASE_URL}/files/{value}", headers=headers)

            if resp.status_code == 404:
                return IOCVerdict(self.name, ioc_type, value, False, 0, "Not found in VirusTotal database")

            resp.raise_for_status()
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) or 1

            is_malicious = malicious > 0
            confidence = min(int(((malicious + suspicious) / total) * 100), 100)
            detail = f"{malicious}/{total} vendors flagged as malicious"
            if suspicious:
                detail += f", {suspicious} flagged suspicious"

            return IOCVerdict(self.name, ioc_type, value, is_malicious, confidence, detail)

        except Exception as e:
            return self._unavailable(ioc_type, value, str(e))