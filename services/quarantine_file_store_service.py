import os
import io
import hashlib
from fastapi import UploadFile
from datetime import timedelta
from models.quarantine_file_store import QuarantineFileStore
from config.settings import settings
from config.minio_config import minio_client
from exceptions import MinIOException

class QuarantineFileStoreService(QuarantineFileStore):
    
    def __init__(self, filename, userid):
        self.filename = filename
        self.userid = userid
        
    def generate_presigned_upload_url_minio(self, expires: timedelta = timedelta(minutes = 10)) -> str:
        try:
            object_name = f'{self.userid}/{self.filename}'
            url = minio_client.presigned_put_object(
                bucket_name= settings.MINIO_QUARANTINE_BUCKET.lower().replace("_", "-"), 
                object_name=object_name, 
                expires=expires
            )
            return url
        except Exception as e:
            raise MinIOException("Failed to generate presigned **UPLOAD URL** for MinIO", e)
        
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