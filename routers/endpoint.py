from fastapi import APIRouter, UploadFile, File, Form, Request, HTTPException
import httpx
from services.quarantine_file_store_service import QuarantineFileStoreService
from exceptions import MinIOException, QuarantineFileStoreException
from pydantic import BaseModel
from typing import List
from config.settings import settings
from logs import get_app_logger, get_error_logger

error_logger = get_error_logger()
app_logger = get_app_logger()

class FileMeta(BaseModel):
    filename: str
    content_type: str

class PresignedURLRequest(BaseModel):
    userid: str
    files: List[FileMeta]

class PresignedURLResponse(BaseModel):
    urls: List[str]
    object_paths: List[str]

class FileIngestMeta(BaseModel):
    filename: str
    content_type: str
    storage_path: str

class FilesRequest(BaseModel):
    userid: str
    files: List[FileIngestMeta]

router = APIRouter(
    prefix="/file",
    tags=["image-file"]
)

@router.post("/put_presigned_url")
async def put_presigned_url(req: PresignedURLRequest):
    filenames = [file.filename for file in req.files]
    file_service = QuarantineFileStoreService(filenames, req.userid, expires=10)    
    try:
        urls, object_paths = await file_service.get_put_url()
        return PresignedURLResponse(urls=urls, object_paths=object_paths)
    except (MinIOException, QuarantineFileStoreException) as e:
        raise  HTTPException(status_code=500, detail=e.to_dict())
    except Exception as e:
        raise  HTTPException(status_code=500, detail=str(e))

@router.post("/ingest_event")
async def ingest_event(
    payload: FilesRequest
):
    try:
        async with httpx.AsyncClient() as client:
            res = await client.post(
                f"{settings.TINES_WEBHOOK_URL}/{settings.TINES_SECRET}",
                json=payload.model_dump()
            )
            res.raise_for_status()
        return {"status": "success"}
    except Exception as e:
        error_logger.error(f"Failed to ingest event to Tines: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    
@router.get("/get_presigned_url")
async def get_presigned_url(
    filename: str = Form(...),
    userid: str = Form(...)
):
    file_service = QuarantineFileStoreService(filename, userid)
    
    try:
        url = file_service.generate_presigned_download_url_minio()
        return {"presigned_url" : url} 
    except MinIOException as e:
        raise  HTTPException(status_code=500, detail=e.to_dict())
    except Exception as e:
        raise  HTTPException(status_code=500, detail=str(e))
    