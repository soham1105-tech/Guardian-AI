import os
from dotenv import load_dotenv

load_dotenv()

_DEFAULT_CORS_ORIGINS = [
    "http://localhost:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
]


def _cors_origins() -> list:
    """Allowed origins from CORS_ORIGINS (comma-separated). Defaults keep local dev."""
    raw = os.getenv("CORS_ORIGINS", "").strip()
    if not raw:
        return list(_DEFAULT_CORS_ORIGINS)
    origins = [o.strip() for o in raw.split(",") if o.strip()]
    return origins or list(_DEFAULT_CORS_ORIGINS)


class Settings:
    APP_NAME: str = "Guardian.AI"
    APP_VERSION: str = "0.2.0"

    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./guardian.db")

    # Upload
    UPLOAD_DIR: str = os.getenv("UPLOAD_DIR", "./uploads")
    MAX_FILE_SIZE_MB: int = 10
    ALLOWED_EXTENSIONS: set = {".eml"}

    # AI / LLM
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    AI_MODEL: str = os.getenv("AI_MODEL", "openai/gpt-oss-20b")

    # Threat Intelligence (V2)
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    URLSCAN_API_KEY: str = os.getenv("URLSCAN_API_KEY", "")
    URLHAUS_API_KEY: str = os.getenv("URLHAUS_API_KEY", "")
    OTX_API_KEY: str = os.getenv("OTX_API_KEY", "")
    MAX_IOC_CHECK_PER_TYPE: int = int(os.getenv("MAX_IOC_CHECK_PER_TYPE", "5"))

    # Standalone Link Investigation (Module 1)
    LINK_FETCH_TIMEOUT: float = float(os.getenv("LINK_FETCH_TIMEOUT", "5"))
    LINK_TLS_TIMEOUT: float = float(os.getenv("LINK_TLS_TIMEOUT", "5"))
    LINK_CT_TIMEOUT: float = float(os.getenv("LINK_CT_TIMEOUT", "5"))
    LINK_CT_MAX_BYTES: int = int(os.getenv("LINK_CT_MAX_BYTES", str(1024 * 1024)))
    LINK_MAX_REDIRECTS: int = int(os.getenv("LINK_MAX_REDIRECTS", "5"))
    LINK_MAX_RESPONSE_BYTES: int = int(os.getenv("LINK_MAX_RESPONSE_BYTES", str(1024 * 1024)))
    CT_LOG_URL: str = os.getenv("CT_LOG_URL", "https://crt.sh")

    # Risk Engine Weights (V2 — rebalanced to include threat intel; must sum to 100)
    WEIGHT_SENDER: int = 25
    WEIGHT_URL: int = 25
    WEIGHT_ATTACHMENT: int = 15
    WEIGHT_CONTENT: int = 10
    WEIGHT_THREAT_INTEL: int = 25

    # Risk Thresholds
    THRESHOLD_SAFE: int = 30
    THRESHOLD_SUSPICIOUS: int = 60
    THRESHOLD_HIGH: int = 80

    # CORS — CORS_ORIGINS env var (comma-separated) overrides; defaults keep local dev.
    FRONTEND_ORIGINS: list = _cors_origins()


settings = Settings()

# Ensure upload dir exists
os.makedirs(settings.UPLOAD_DIR, exist_ok=True)