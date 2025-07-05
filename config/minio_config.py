import os
from minio import Minio
from .settings import settings

def setup_minio():
    return Minio(
        settings.MINIO_ENDPOINT,
        access_key = settings.MINIO_ACCESS_KEY,
        secret_key = settings.MINIO_SECRET_KEY,
        secure=False 
    )

minio_client = setup_minio()