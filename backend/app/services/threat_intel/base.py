from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class IOCVerdict:
    provider: str
    ioc_type: str          # "ip" | "domain" | "url" | "hash"
    ioc_value: str
    malicious: bool
    confidence: int        # 0-100
    detail: str
    checked: bool = True   # False if the provider call failed/unavailable


class ThreatIntelProvider(ABC):
    """
    Common interface every threat-intel source must implement.
    If one provider goes down or hits a rate limit, the pipeline
    keeps working using the others — no single point of failure.
    """
    name: str = "base"
    supported_types: set = set()

    def supports(self, ioc_type: str) -> bool:
        return ioc_type in self.supported_types

    @abstractmethod
    async def check(self, ioc_type: str, value: str) -> IOCVerdict:
        ...

    def _unavailable(self, ioc_type: str, value: str, reason: str = "provider error") -> IOCVerdict:
        return IOCVerdict(
            provider=self.name,
            ioc_type=ioc_type,
            ioc_value=value,
            malicious=False,
            confidence=0,
            detail=f"{self.name} unavailable: {reason}",
            checked=False,
        )