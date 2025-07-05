from fastapi import APIRouter, UploadFile, File, Form, Request, HTTPException
# from services.file_pipeline import FilePipeline
from services.quarantine_file_store_service import QuarantineFileStoreService
from exceptions import MinIOException
# from services.service_factory import ServiceFactory


router = APIRouter(
    prefix="/file",
    tags=["image-file"]
)

@router.post("/put_presigned_url")
async def put_presigned_url(
    filename: str = Form(...),
    contentType: str = Form(...),
    isValidFile: str = Form(...),
    extension: str = Form(...),
    userid: str = Form(...),
    
):
    if not bool(isValidFile == 'true'):
        raise HTTPException(status_code=400, detail=f"Invalid file extension: '{extension}'")
    
    file_service = QuarantineFileStoreService(filename, userid)
    object_key = f'{userid}/{filename}'
    
    try:
        url = file_service.generate_presigned_upload_url_minio()
        return {"upload_url" : url, "object_key" : object_key, "contentType" : contentType, "extension" : extension}
    except MinIOException as e:
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
    