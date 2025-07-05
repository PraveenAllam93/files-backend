from models.pdf_quarantine_check import PDFQuarantineCheck
from typing import List, Optional
from io import BytesIO
from dataclasses import dataclass
from exceptions import PDFFileCHeckException

import os
import fitz
import tempfile
import zipfile
from pdfid import pdfid
import pikepdf
from services.quarantine_file_check_service import QuarantineFileCheckService
from config.settings import settings
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
import traceback
import asyncio

import logging

logger = logging.getLogger(__name__)

@dataclass
class PDFCheckResult:
    filename: str
    file_size: Optional[int] = None
    malicious: bool = False
    reason: str = None

class PDFQuarantineCheckService(PDFQuarantineCheck, QuarantineFileCheckService):
    def __init__(self,
                 query: str, 
                 urls: List[str], 
                 filenames: List[str], 
                 userid: str, 
                 timeout: int = 30,
            ):
        
        super().__init__(query, urls, filenames, userid, timeout)
        self.executor = ThreadPoolExecutor(max_workers=10)
        
    def is_valid_signature(self, file_content: bytes) -> bool:
        return file_content.startswith(b"%PDF-") and b"%%EOF" in file_content
    
    def is_pdf_encrypted(self, file_content: bytes) -> bool:
        try:
            with pikepdf.open(BytesIO(file_content)) as pdf:
                return pdf.is_encrypted
            
        except pikepdf._qpdf.PasswordError:
            return True
        
        except Exception as e:
            raise PDFFileCHeckException("Failed to check if PDF is encrypted", e)
    
    def has_javascript(self, file_content: bytes) -> bool:
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            tmp_file.write(file_content)
            tmp_file.flush()
            temp_path = tmp_file.name
        
        try:
            result = pdfid.PDFiD(temp_path)
            return (
                "/JavaScript" in result.keywords
                or "/AA" in result.keywords
                or "/OpenAction" in result.keywords
            )
        except Exception as e:
            raise PDFFileCHeckException("Failed to check for JavaScript", e)
        finally:
            os.remove(temp_path)
            
    def list_embedded_files(self, file_content: bytes) -> list:
        try:
            with pikepdf.open(BytesIO(file_content)) as pdf:
                return list(pdf.attachments.keys())
        except Exception as e:
            raise PDFFileCHeckException("Failed to list embedded files", e)
    
    def detect_zip_bomb(self, file_content: bytes) -> bool:
        try:
            with zipfile.ZipFile(BytesIO(file_content)) as content:
                total_size = sum([content.getinfo(f).file_size for f in content.namelist()])
                if total_size > 10 * 1024 * 1024:
                    return True
        except zipfile.BadZipFile:
            return False
        except Exception as e:
            raise PDFFileCHeckException("Failed to detect zip bomb", e)
        
        return False
    
    def has_invisible_text(self, file_content: bytes) -> bool:
        with fitz.open(stream= BytesIO(file_content), filetype="pdf") as document:
            for page in document:
                blocks = page.get_text("dict")["blocks"]
                for block in blocks:
                    for line in block.get("lines", []):
                        for span in line.get("spans",  []):
                            font_size = span.get("size", 0)
                            color = span.get("color", 0)
                            
                            if font_size < 1 or color == 0xFFFFFF: # too small or white text
                                return True
        
        return False
    
    
    async def run_pdf_check_pipeline(self, file_content: bytes, filename: str) -> PDFCheckResult:
        file_size = round(len(file_content) / (1024 * 1024), 2)
        logger.info(f"Checking pdf {filename} for checks...")
        loop = asyncio.get_running_loop()
        
        valid_signature = await loop.run_in_executor(self.executor, self.is_valid_signature, file_content)
        if not valid_signature:
            return PDFCheckResult(
                filename,
                file_size,
                malicious = True,
                reason = "Invalid signature"
            )
        
        is_encrypted = await loop.run_in_executor(self.executor, self.is_pdf_encrypted, file_content)
        if is_encrypted:
            return PDFCheckResult(
                filename,
                file_size,
                malicious = True,
                reason = "Encrypted"
            )
        
        # has_js = await loop.run_in_executor(self.executor, self.has_javascript, file_content)
        # if has_js:
        #     return PDFCheckResult(
            #     filename,
            #     file_size,
            #     malicious = True,
            #     reason = "JavaScript detected"
            # )
    
        embedded_files = await loop.run_in_executor(self.executor, self.list_embedded_files, file_content)
        if embedded_files:
            return PDFCheckResult(
                filename,
                file_size,
                malicious = True,
                reason = f"Embedded files detected - {len(embedded_files)}",
            )
        
        has_zip_bomb = await loop.run_in_executor(self.executor, self.detect_zip_bomb, file_content)
        if has_zip_bomb:
            return PDFCheckResult(
                filename,
                file_size,
                malicious = True,
                reason = "Zip bomb detected",
            )
        
        # invisible_text = await loop.run_in_executor(self.executor, self.has_invisible_text, file_content)
        # if invisible_text:
        #     return PDFCheckResult(
            #     filename,
            #     file_size,
            #     malicious = True,
            #     reason = "Invisible text detected"
            # )
    
        return PDFCheckResult(
            filename,
            file_size,
            malicious = False,
            reason = "Passed All tests",
        )
    
    async def scan_multiple_files(self) -> dict:
        if not self._file_contents:
            logger.warning(f"No file contents to process for user {self.userid}")
            raise PDFFileCHeckException(f"No file contents to process for user {self.userid}")
        
        if self._file_contents:
            if len(self._file_contents) == 1:
                result = await self.run_pdf_check_pipeline(self._file_contents[0], self.filenames[0])
                return self.get_validation_summary([result])
            
            tasks = [
                self.run_pdf_check_pipeline(file_content, filename)
                for file_content, filename in zip(self._file_contents, self.filenames)
            ]
            results = await asyncio.gather(*tasks, return_exceptions= True)
            return self.get_validation_summary(results)
                
    def get_validation_summary(self, results: List[PDFCheckResult]) -> dict:
        """Get summary statistics from validation results."""
        if not results:
            return {}
        
        is_malicious = [r.reason for r in results if r.malicious]
        
        if is_malicious:
            raise PDFFileCHeckException(f"PDF file check failed - {is_malicious}") from is_malicious
            # return {"malicious": True, "reason": is_malicious}
        
        return {
            "total_files": len(results),
            'total_mb': sum(r.file_size for r in results if r.file_size),
            'max_file_size': max(
                (r.file_size) for r in results if r.file_size
            ),
            "is_pdf": True
        }
            