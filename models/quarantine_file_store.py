from abc import ABC, abstractmethod

class QuarantineFileStore(ABC):
    
    @abstractmethod
    async def get_put_url(self) -> str:
        """Stores the object in MinIO"""
        pass
    
    @abstractmethod
    def generate_presigned_download_url_minio(self) -> str:
        """Gets the presigned URL from MinIO"""
        pass