import os
import uuid
import shutil
from fastapi import APIRouter, UploadFile, File, HTTPException

from app.config import settings
from app.database import get_db
from app.models.schemas import UploadResponse

router = APIRouter()


@router.post("/upload", response_model=UploadResponse)
async def upload_email(file: UploadFile = File(...)):
    # Validate extension
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Only .eml files are allowed")

    # Generate unique ID
    email_id = str(uuid.uuid4())
    saved_filename = f"{email_id}{ext}"
    filepath = os.path.join(settings.UPLOAD_DIR, saved_filename)

    # Save file to disk
    with open(filepath, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Check file size after saving
    size_mb = os.path.getsize(filepath) / (1024 * 1024)
    if size_mb > settings.MAX_FILE_SIZE_MB:
        os.remove(filepath)
        raise HTTPException(status_code=400, detail="File too large")

    # Save record in DB
    with get_db() as conn:
        conn.execute(
            "INSERT INTO emails (id, filename, filepath, status) VALUES (?, ?, ?, ?)",
            (email_id, file.filename, filepath, "uploaded"),
        )
        conn.commit()

    return UploadResponse(email_id=email_id, filename=file.filename, status="uploaded")