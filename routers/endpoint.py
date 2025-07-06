from fastapi import APIRouter, UploadFile, File, Form, Request, HTTPException

from services.quarantine_file_store_service import QuarantineFileStoreService
from exceptions import MinIOException, QuarantineFileStoreException
from pydantic import BaseModel
from typing import List

class FileMeta(BaseModel):
    filename: str
    content_type: str

class PresignedURLRequest(BaseModel):
    userid: str
    files: List[FileMeta]

class PresignedURLResponse(BaseModel):
    urls: List[str]


router = APIRouter(
    prefix="/file",
    tags=["image-file"]
)

@router.post("/put_presigned_url")
async def put_presigned_url(req: PresignedURLRequest):
    filenames = [file.filename for file in req.files]
    file_service = QuarantineFileStoreService(filenames, req.userid, expires=10)    
    try:
        urls = await file_service.get_put_url()
        return PresignedURLResponse(urls=urls)
    except (MinIOException, QuarantineFileStoreException) as e:
        raise  HTTPException(status_code=500, detail=e.to_dict())
    except Exception as e:
        raise  HTTPException(status_code=500, detail=str(e))
    
    
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
    