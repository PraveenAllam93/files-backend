from services.service_factory import ServiceFactory
from services.image_quarantine_check_service import ImageQuarantineCheckService
from services.pdf_quarantine_check_service import PDFQuarantineCheckService
from config.settings import settings
from exceptions import QuarantineFileCheckException
from typing import List

from logs import get_app_logger, get_error_logger

app_logger = get_app_logger()
error_logger = get_error_logger()

class QuarantineFileCheckPipeline:
    
    @classmethod
    async def process(cls,
                query: str,
                urls: str, 
                filenames: str,
                userid: str):
        
        result = {
            "success": False,
            "query": None,
            "userid": "",
            "filenames": [],
            "file_size_exceeds": None,
            "magic_numbers": None,
            "malware": None,
            "sensitive_info": None,
            "seen_files_collections": {},
            "unseen_filenames": [],
            "presigned_urls": {},
            "collection": None,
            "anonymized_content": None,
        }
        
        file_service = ServiceFactory.create_service(
            query, [urls], [filenames], userid
        )
        
        result.update(query= query, userid= userid, filenames= [filenames], sensitive_info = False)
        await file_service.process_download_file()
        if not file_service._file_contents:
            raise QuarantineFileCheckException("Failed to download file content")
            
        file_service.process_get_file_size()
        if any(size > settings.MAX_FILE_SIZE for size in file_service._file_sizes) or sum(file_service._file_sizes) > settings.MAX_UPLOAD_SIZE:
            result.update(success=True, file_size_exceeds=True)
            return result
        
        file_service.process_file_hashing()
        # file_service.process_check_file_in_redis()
        file_service._seen_status = [None] * len(file_service._file_sizes)
        
        seen_files_collections = {hashed_filename: collection for hashed_filename, collection in zip(file_service._hashed_filenames, file_service._seen_status) if collection}
        unseen_filenames = [filename for filename, seen in zip([filenames], file_service._seen_status) if not seen]
        
        result.update(seen_files_collections = seen_files_collections, unseen_filenames= unseen_filenames)

        if unseen_filenames:
            file_service.process_verify_magic_number()
            await file_service.process_scan_for_malware()
            result.update(magic_numbers = False, malware = False)
            
            if isinstance(file_service, ImageQuarantineCheckService):
                file_type_check_response = file_service.scan_multiple_files()
            file_type_check_response = await file_service.scan_multiple_files()
            result.update(file_type_check_response)

            url = file_service.copy_object(userid, file_service.filenames[0], file_service._hashed_filenames[0])
            file_service.delete_object(userid, filenames)
            presigned_urls = {
                file_service._hashed_filenames[0] : {
                    "url" : url,
                    "seen" : False,
                    "filename" : filenames
                }
            }
            result.update(presigned_urls = presigned_urls)
            
        result.update(success = True)
        return result