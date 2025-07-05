from services.image_quarantine_check_service import ImageQuarantineCheckService
from services.pdf_quarantine_check_service import PDFQuarantineCheckService

from fastapi import UploadFile
from config.settings import settings
from exceptions import QuarantineFileCheckException
from typing import List

class ServiceFactory:
    
    @staticmethod
    def extract_attachments(filenames: List[str]) -> dict:
        image_types = settings.IMAGE_EXTENSIONS
        pdf_types = settings.PDF_EXTENSIONS
        source_code_types = settings.SOURCE_CODE_EXTENSIONS
        tabular_types = settings.TABULAR_EXTENSIONS
        validate_list = []
        
        try:
            for filename in filenames:
                filetype = filename.split('.')[-1].lower()
                print(f"{filetype=}")
                if not (filetype in image_types or filetype in pdf_types or filetype in source_code_types or filetype in tabular_types):
                    others = True
                    validate = None
                    return {"others" : others, "validate_lists" : validate}

                if filetype in image_types:
                    validate_list.append("image_types")
                elif filetype in pdf_types:
                    validate_list.append("pdf_types")
                elif filetype in source_code_types:
                    validate_list.append("source_code_types")
                elif filetype in tabular_types:
                    validate_list.append("tabular_types")

                if len(list(set(validate_list))) > 1:
                    others = None
                    validate = False
                    return {"others" : others, "validate_lists" : validate}
            
            is_tabular = True if filenames[0].split('.')[-1].lower() in tabular_types else False
            is_image = True if filenames[0].split('.')[-1].lower() in image_types else False
            is_pdf = True if filenames[0].split('.')[-1].lower() in pdf_types else False
            is_source_code = True if filenames[0].split('.')[-1].lower() in source_code_types else False
            
            return {"others" : False, "validate_lists" : True, "is_image" : is_image, "is_pdf" : is_pdf, "is_source_code" : is_source_code, "is_tabular" : is_tabular}
        except Exception as e:
            raise QuarantineFileCheckException(f"Error while extracting attachments and checking for filetypes", e)

    
    @classmethod
    def create_service(cls,
                        query: str, 
                        urls: List[str], 
                        filenames: List[str], 
                        userid: str, 
                        timeout: int = 30,):
        
        attachments_validation = ServiceFactory.extract_attachments(filenames)
        if attachments_validation["others"] or not attachments_validation["validate_lists"]:
            print("Invalid file type or multiple file types detected")
            raise QuarantineFileCheckException("Invalid file type or multiple file types detected")
        
        if attachments_validation.get("is_image"):
            return ImageQuarantineCheckService(query, urls, filenames, userid, timeout)
        
        if attachments_validation.get("is_pdf"):
            return PDFQuarantineCheckService(query, urls, filenames, userid, timeout)