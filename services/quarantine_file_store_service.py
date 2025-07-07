import os
import io
import hashlib
from fastapi import UploadFile
from datetime import timedelta
from models.quarantine_file_store import QuarantineFileStore
from config.settings import settings
from config.minio_config import minio_client
from exceptions import MinIOException, QuarantineFileStoreException

from .minio_service import generate_presigned_upload_url_minio
from fastapi.concurrency import run_in_threadpool
from typing import List, Tuple
import asyncio

class QuarantineFileStoreService(QuarantineFileStore):
    
    def __init__(self, filenames: List[str], userid: str, expires: int = 10):
        self.filenames = filenames
        self.userid = userid
        self.expires = timedelta(minutes=expires)
        
    async def get_put_url(self) -> Tuple[List[str], List[str]]:
        if not self.filenames or not self.userid:
            raise QuarantineFileStoreException("Filenames and User ID must be provided")
        
        if len(self.filenames) > settings.MAX_FILES_COUNT:
            raise QuarantineFileStoreException(f"Maximum {settings.MAX_FILES_COUNT} files are allowed in quarantine")
        
        if not all(isinstance(filename, str) for filename in self.filenames):
            raise QuarantineFileStoreException("All filenames must be strings")
        
        async def generate_presigned_upload_urls(filename: str):
            return await run_in_threadpool(
                generate_presigned_upload_url_minio,
                filename=filename,
                userid=self.userid,
                expires=self.expires 
            )
        
        try:
            urls_info = await asyncio.gather(
                *[generate_presigned_upload_urls(file) for file in self.filenames]
            )
            urls = [info[0] for info in urls_info]
            object_paths = [info[1] for info in urls_info]
            return urls, object_paths
        except MinIOException as e:
            raise e
        except Exception as e:
            raise QuarantineFileStoreException("Failed to generate presigned **UPLOAD URL** for MinIO", e)
        
    def generate_presigned_download_url_minio(self, expires: timedelta = timedelta(minutes = 10)):
        object_name = f'{self.userid}/{self.filename}'
        try:
            url = minio_client.presigned_get_object(
                bucket_name= settings.MINIO_QUARANTINE_BUCKET.lower().replace("_", "-"), 
                object_name=object_name, 
                expires=expires
            ) 
            return url 
        except Exception as e: 
           raise MinIOException("Failed to generate presigned **DOWNLOAD URL** for MinIO", e)