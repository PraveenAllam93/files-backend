from abc import ABC, abstractmethod
from .quarantine_file_check import QuarantineFileCheck


class PDFQuarantineCheck(QuarantineFileCheck, ABC):
    
    @abstractmethod
    def is_valid_signature(self, file_content: bytes) -> bool:
        """Validates the file signature"""
        pass
    
    @abstractmethod
    def is_pdf_encrypted(self, file_content: bytes) -> bool:
        """Checks for password protected files"""
        pass
    
    @abstractmethod
    def has_javascript(self, file_content: bytes) -> bool:
        """Checks for embedded JavaScript"""
        pass
    
    @abstractmethod
    def list_embedded_files(self, file_content: bytes) -> list:
        """Lists embedded files"""
        pass
    
    @abstractmethod
    def detect_zip_bomb(self, file_content: bytes) -> bool:
        """Detects zip bomb"""
        pass
            
    @abstractmethod
    def has_invisible_text(self, file_content: bytes) -> bool:
        """Checks for invisible texts"""
        pass
    
    @abstractmethod
    async def run_pdf_check_pipeline(self, file_content: bytes) -> dict:
        pass