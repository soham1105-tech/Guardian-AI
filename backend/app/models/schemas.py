from pydantic import BaseModel, Field, field_validator
from typing import List, Optional
from datetime import datetime


# ---------- Upload ----------
class UploadResponse(BaseModel):
    email_id: str
    filename: str
    status: str


# ---------- Standalone Link Investigation (Module 1) ----------
class InvestigateRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=1,
        max_length=4096,
        description="Any URL or bare domain to investigate, e.g. https://example.com/login",
    )

    @field_validator("url")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("url must not be empty")
        return value


# ---------- Parsed Email ----------
class ParsedEmail(BaseModel):
    from_addr: Optional[str] = None
    to_addr: Optional[str] = None
    subject: Optional[str] = None
    date: Optional[str] = None
    return_path: Optional[str] = None
    reply_to: Optional[str] = None
    received_headers: List[str] = []
    body_text: Optional[str] = None
    urls: List[str] = []
    attachments: List[dict] = []


# ---------- Header Analysis ----------
class HeaderAnalysisResult(BaseModel):
    spf: str
    dkim: str
    dmarc: str
    sender_domain: Optional[str] = None
    return_path_domain: Optional[str] = None
    domain_mismatch: bool = False
    spoofing_risk: str
    reasons: List[str] = []


# ---------- URL Analysis ----------
class UrlAnalysisItem(BaseModel):
    url: str
    domain: str
    risk: str
    reasons: List[str] = []


# ---------- Attachment Analysis ----------
class AttachmentAnalysisItem(BaseModel):
    filename: str
    extension: str
    mime_type: Optional[str] = None
    size_bytes: int
    sha256: str
    risk: str
    reasons: List[str] = []


# ---------- IOC ----------
class IOCSummary(BaseModel):
    ips: List[str] = []
    domains: List[str] = []
    urls: List[str] = []
    emails: List[str] = []
    hashes: List[str] = []


# ---------- Threat Intelligence (V2) ----------
class ThreatIntelVerdict(BaseModel):
    provider: str
    malicious: bool
    confidence: int
    detail: str
    checked: bool = True


class ThreatIntelSummary(BaseModel):
    total_iocs_checked: int
    malicious_ioc_count: int
    malicious_iocs: List[str] = []
    max_confidence: int = 0


class ThreatIntelReport(BaseModel):
    results: dict  # { ioc_value: List[ThreatIntelVerdict] }
    summary: ThreatIntelSummary


# ---------- MITRE ATT&CK (V2) ----------
class MitreTechnique(BaseModel):
    id: str
    name: str
    tactic: str


# ---------- AI Verdict ----------
class AIVerdict(BaseModel):
    classification: str
    confidence: int
    explanation: str
    recommended_action: str


# ---------- Final Risk Report ----------
class RiskReport(BaseModel):
    score: int
    category: str
    breakdown: dict


# ---------- Full Analysis Response ----------
class AnalysisResult(BaseModel):
    email_id: str
    parsed: ParsedEmail
    header_analysis: HeaderAnalysisResult
    url_analysis: List[UrlAnalysisItem]
    attachment_analysis: List[AttachmentAnalysisItem]
    ioc_summary: IOCSummary
    threat_intel: ThreatIntelReport
    mitre_techniques: List[MitreTechnique] = []
    risk_report: RiskReport
    ai_verdict: Optional[AIVerdict] = None
    analyzed_at: datetime = datetime.utcnow()