from config.settings import settings
from config.minio_config import minio_client

from exceptions import MinIOException
from logs import get_app_logger, get_error_logger

app_logger = get_app_logger()
error_logger = get_error_logger()


def generate_presigned_upload_url_minio(filename: str, userid: str, expires: int = 600) -> str:
    try:
        url = minio_client.presigned_put_object(
            bucket_name= settings.MINIO_QUARANTINE_BUCKET.lower().replace("_", "-"), 
            object_name=f"{userid}/{filename}", 
            expires=expires
        )
        app_logger.info(f"Presigned upload URL generated for user: {userid}, filename: {filename}")
        return url
    except Exception as e:
        error_logger.error(f"Failed to generate presigned upload URL for user: {userid}, filename: {filename} => {str(e)}")
        raise MinIOException("Failed to generate presigned **UPLOAD URL** for MinIO", e)
    