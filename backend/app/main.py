from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import init_db
from app.api import upload, analyze, investigate, messages, reports

app = FastAPI(title=settings.APP_NAME, version=settings.APP_VERSION)

# CORS — allow frontend dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.FRONTEND_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Init DB tables on startup
@app.on_event("startup")
def on_startup():
    init_db()

# Routers
app.include_router(upload.router, prefix="/api", tags=["Upload"])
app.include_router(analyze.router, prefix="/api", tags=["Analyze"])
app.include_router(investigate.router, prefix="/api", tags=["Investigation"])
app.include_router(messages.router, prefix="/api", tags=["Message"])
app.include_router(reports.router, prefix="/api", tags=["Reports"])


@app.get("/")
def root():
    return {"status": "ok", "service": settings.APP_NAME}