from fastapi import APIRouter, UploadFile, File, Form, Request, HTTPException
# from services.file_pipeline import FilePipeline
from services.orchestrators.quarantine_file_check_pipeline import QuarantineFileCheckPipeline
from exceptions import QuarantineFileCheckException
# from services.service_factory import ServiceFactory


router = APIRouter(
    prefix="/quarantine/file",
    tags=["quarantine"]
)

@router.post("/check")
async def check_quarantine_file(
    url: str = Form(...),
    filename: str = Form(...),
    userid: str = Form(...),
    
):
    try:
        return await QuarantineFileCheckPipeline.process("",url, filename, userid)
    except QuarantineFileCheckException as e:
        raise HTTPException(status_code=500, detail=e.to_dict())
    except Exception as e:
        raise  HTTPException(status_code=500, detail=str(e))
    