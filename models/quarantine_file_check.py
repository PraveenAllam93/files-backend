from abc import ABC, abstractmethod

class QuarantineFileCheck(ABC):
    
    @abstractmethod
    async def download_file(self) -> bytes:
        """Downloads file from the given URL"""
        pass
    
    @abstractmethod
    def get_file_size(self, file_content: bytes) -> float:
        """Gets the size of the file"""
        pass
    
    
    @abstractmethod
    def generate_unique_filename(self, file_content: bytes, filename: str) -> str:
        """Generates the hashname for the file"""
        pass
    
    @abstractmethod
    def check_file_in_redis(self, hash: str) -> str | bool:
        """Checks whether the file is previously uplaoded or not with redis"""
        pass
    
    @abstractmethod
    def verify_magic_number(self, file_content: bytes, filename: str) -> bool:
        """Verify the filetype using magic numbers"""
        pass
    
    @abstractmethod
    def scan_for_malware(self, hashed_filename: str) -> bool:
        """Scan the file for malware"""
        pass
    
    @abstractmethod
    def scan_multiple_files(self):
        pass
    
    # @abstractmethod
    # def sanitize_metadata(self):
    #     """Sanitizes metadata"""
    #     pass
    
    @abstractmethod
    def delete_file_from_quarantine(self, filename: str) -> bool:
        """Deletes file(s) from quarantine bucket of MinIO"""
        pass
    
    @abstractmethod
    def move_file_from_quarantine(self, filename: str, hashed_filename: str) -> bool:
        """Moves file(s) from quarantine bucket to main bucket of MinIO"""
        pass
    