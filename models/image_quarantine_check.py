from abc import ABC, abstractmethod
from .quarantine_file_check import QuarantineFileCheck
from PIL import Image

class ImageQuarantineCheck(QuarantineFileCheck, ABC):
    
    
    @abstractmethod
    def _validate_image_dimensions(self, width: int, height: int):
        pass
    
    @abstractmethod
    def _validate_megapixel_limit(self, width: int, height: int):
        """Checks for pixel flooding attack"""
        pass
    
    @abstractmethod
    def _validate_file_density(self, width: int, height: int, file_size: int):
        pass
    
    @abstractmethod
    def run_image_check_pipeline(self, file_content: bytes, filename: str): 
        pass