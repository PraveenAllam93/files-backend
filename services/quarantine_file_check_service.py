from models.quarantine_file_check import QuarantineFileCheck
from config.settings import settings
from config.minio_config import minio_client
# from config.redis_config import get_redis_pool, pool
import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import asyncio
import hashlib
import os
import magic
from .redis_service import get_redis_hash_values
import traceback
import io
from minio.commonconfig import REPLACE, CopySource


from PIL import Image
import vt
from typing import List, Dict, Union, Optional
from config.settings import settings
from config.minio_config import minio_client

from exceptions import QuarantineFileCheckException
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

from logs import get_app_logger, get_error_logger

app_logger = get_app_logger()
error_logger = get_error_logger()

class QuarantineFileCheckService(QuarantineFileCheck):
    
    def __init__(self, query: str, urls: List[str], filenames: List[str], userid: str, timeout: int = 30):
        self.query = query
        self.urls = urls
        self.filenames = filenames
        self.userid = userid
        self.timeout = timeout
        self.aiohttp_timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_workers = os.cpu_count()
        
        self.bucket_name = settings.MINIO_QUARANTINE_BUCKET
        
        
        self._file_sizes = None
        self._file_contents = None
        self._hashed_filenames = None
        self._seen_status = None
        self._minio_status = None
        self._urls = None
        
    
    def _log_info(self, message: str) -> None:
        """Log an info message if logger is available."""
        if app_logger:
            print(message)
    
    def _log_error(self, message: str, exc_info: bool = False) -> None:
        """Log an error message if error_logger is available."""
        if error_logger:
            if exc_info:
                error_logger.exception(message)
            else:
                error_logger.error(message)

    
    @retry(
        stop=stop_after_attempt(2),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError, aiohttp.ClientConnectionError)),
        before= lambda retry_state: print(
            f"[Retrying] Attempt {retry_state.attempt_number} to download the file after exception: {retry_state.outcome.exception() if retry_state.outcome else 'Unknown'}" if retry_state.attempt_number != 1 else "Starting File Download attempt.."
        ),
        after=lambda retry_state: print(f"Retry finished: attempt {retry_state.attempt_number}")
    )
    async def download_file(self, session: aiohttp.ClientSession, url: str, filename: str):  
        async with session.get(url) as response:
            print(f"📡 HTTP status: {response.status}")
            # await response.raise_for_status() 
            file_content = await response.read()
        print(f"Downloaded the file uploaded by user: '{self.userid}' with filename: '{filename}'")
        return file_content
                
    def get_file_size(self, file_content: bytes) -> float:
        return round(len(file_content) / (1024 * 1024), 2)
    
            
    def generate_unique_filename(self, file_content: bytes, filename: str) -> str:
        try:
            file_extension = os.path.splitext(filename)[-1].lower()
            hasher = hashlib.sha256()
            hasher.update(file_content)
            if file_extension in settings.TABULAR_EXTENSIONS:
                file_extension = ".parquet"
            hashed_filename = hasher.hexdigest() + file_extension
            return hashed_filename
        except Exception as e:
            self._log_error(f"Unexpected error hashing data with SHA-256 => {str(e)}\n\n{traceback.format_exc()}")
            raise QuarantineFileCheckException("Unexpected error hashing data with SHA-256", e)
    
    def check_file_in_redis(self, hash: str) -> str | bool :
        try:
            redis_file_reference_key = f"file-references:{self.userid}:summaries"
            file_in_redis = get_redis_hash_values(redis_file_reference_key, hash)
            if file_in_redis:
                vector_db_collection = file_in_redis[0].get("collection")
                return vector_db_collection
            return False
        except Exception as e:
            print(f"Error while checking seen status in redis")
            return False

    def verify_magic_number(self, file_content: bytes, filename: str) -> bool:
        try:
            detected_mime = magic.from_buffer(file_content, mime=True)
            file_extension = os.path.splitext(filename)[-1].lower().lstrip('.')
            expected_mime = settings.ALLOWED_MIME_TYPES.get(file_extension)
            
            if '.' in file_extension:
                raise QuarantineFileCheckException(f"Suspicious double extension: {filename}")
        
            if expected_mime is None:
                raise QuarantineFileCheckException(f"Unsupported file type: {detected_mime} with extension: {file_extension}")

            if expected_mime != detected_mime:
                raise QuarantineFileCheckException(f"Mismatch: filename suggests {expected_mime}, but file is {detected_mime}")
            
            return True
        except Exception as e:
            raise QuarantineFileCheckException("Error while verifying magic numbers", e)
    
    
    async def scan_for_malware(self, hashed_filename: str) -> bool:
        try:
            async with vt.Client(settings.VIRUSTOTAL_API_KEY) as client:
                response = await client.get_object_async(f"/files/{hashed_filename.split('.')[0]}")
                
            sandbox_verdicts = response.get("sandbox_verdicts", {})
            total_votes = response.get("total_votes", {})
            reputation = response.get("reputation", 0)
            
            if total_votes.get("malicious", 0) > 0 or reputation < 0:
                app_logger.warning("VirusTotal flagged the file as malicious")
                raise QuarantineFileCheckException(f"VirusTotal flagged the file as malicious")
            
            for verdict in sandbox_verdicts.values():
                if verdict.get("category") != "harmless":
                    app_logger.warning(f"Sandbox verdict not harmless: {verdict}")
                    raise QuarantineFileCheckException(f"Sandbox verdict not harmless: {verdict}\nFile is malicious")
            
            return True
        
        except vt.error.APIError as e:
            if e.args[0] == "NotFoundError":
                print(f"Unknown hash...Not Scanning")
                return True
        except Exception as e:
            raise QuarantineFileCheckException("Error while scanning for malware using Virus Total", e)
    
    
    def move_file_from_quarantine(self, filename: str, hashed_filename: str) -> bool:

        try:
            if not minio_client.bucket_exists(self.userid):
                minio_client.make_bucket(self.userid)
            minio_client.copy_object(self.userid, hashed_filename,
                CopySource(
                    settings.MINIO_QUARANTINE_BUCKET.lower().replace("_", "-"),
                    object_name = f'{self.userid}/{filename}'
                )
            )
            
            url = minio_client.presigned_get_object(
                bucket_name= userid, 
                object_name=hashed_filename, 
            ) 
            
            return url
        except Exception as e:
            raise QuarantineFileCheckException("Error while copying object to user bucket", e)
        
    def delete_file_from_quarantine(self, filename: str) -> bool:
        try: 
            minio_client.remove_object(
                settings.MINIO_QUARANTINE_BUCKET.lower().replace("_", "-"),
                f'{self.userid}/{filename}'
            )
            return True
        except Exception as e:
            raise QuarantineFileCheckException("Error while deleting object from quarantine bucket", e)
    

#-----------------------------------------------------------------------------------------------------
#                                       Asynchronous wrappers                                                                              
#-----------------------------------------------------------------------------------------------------

    async def process_download_file(self) -> Dict | List[bytes]:
        try:
            tasks = []
            async with aiohttp.ClientSession() as session:
                tasks = [
                    self.download_file(session, url, filename)
                    for url, filename in zip(self.urls, self.filenames)
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception) or not isinstance(result, bytes):
                    print(f"{result=}")
                    raise QuarantineFileCheckException(f"Error while Downloading the files for user - {self.userid}")
            
            self._file_contents = results
            print("Downloading done")
            return True
        
        except Exception as e:
            raise QuarantineFileCheckException(f"Error while Downloading the files for user - {self.userid}", e)
        
    def process_file_hashing(self) -> Optional[Dict]:
        futures = []
        executor = None
        results = []
        if self._file_contents:
            try:
                executor = ThreadPoolExecutor(max_workers=self.max_workers)
                
                for content, filename in zip(self._file_contents, self.filenames):
                    future = executor.submit(self.generate_unique_filename, content, filename)
                    futures.append((future, filename))

                for future, filename in futures:
                    try:
                        result = future.result(timeout = 10)
                        results.append(result)
                    except FuturesTimeoutError as e:
                        self._log_error(message = f"Timeout while getting hashed file name for file'{filename}' of user '{self.userid}' => {str(e)}\n\n{traceback.format_exc()}", exc_info = True)
                        results.append(None)
                    except Exception as e:
                        self._log_error(f"Error processing file for getting hashed file name for file'{filename}' of user '{self.userid}' => {str(e)}\n\n{traceback.format_exc()}")
                        results.append(None)
                
                if None in results:
                    raise QuarantineFileCheckException(f"Error processing file for getting hashed file names of user '{self.userid}'")
                
                self._hashed_filenames = results
                return None
            
            except Exception as e:
                self._log_error(f"Error file hashing files of user '{self.userid}' => {str(e)}\n\n{traceback.format_exc()}")
                raise QuarantineFileCheckException(f"Error processing file for getting hashed file names of user '{self.userid}'", e)
            
            finally:
                if executor:
                    executor.shutdown(wait=True)
        return None
    
    def process_get_file_size(self) -> Optional[List[float]]:
        if self._file_contents:
            self._file_sizes = [
                self.get_file_size(file_content)
                for file_content in self._file_contents
            ]
            return True
        raise QuarantineFileCheckException("There might be some issue while downlaoding files, not able to access file contents to get file size")
    
    async def process_check_file_in_redis(self):
        check_file_in_redis_tasks = [ 
            asyncio.to_thread(self.check_file_in_redis, self.userid, hashed_filename) 
            for hashed_filename in self._hashed_filenames
        ]
        self._seen_status = await asyncio.gather(*check_file_in_redis_tasks)
        
    def process_verify_magic_number(self):
        futures = []
        executor = None
        results = []
        if self._file_contents:
            try:
                executor = ThreadPoolExecutor(max_workers=self.max_workers)
                
                for content, filename, seen in zip(self._file_contents, self.filenames, self._seen_status):
                    if not seen:
                        future = executor.submit(self.verify_magic_number, content, filename)
                        futures.append((future, filename))

                for future, filename in futures:
                    try:
                        result = future.result(timeout = 10)
                        results.append(result)
                    except FuturesTimeoutError as e:
                        self._log_error(message = f"Timeout while checking for magic numbers for '{filename}' of user '{self.userid}' => {str(e)}\n\n{traceback.format_exc()}", exc_info = True)
                        results.append(None)
                    except Exception as e:
                        self._log_error(f"Error processing file while checking for magic numbers for  file '{filename}' of user '{self.userid}' => {str(e)}\n\n{traceback.format_exc()}")
                        results.append(None)
                
                if None in results:
                    raise QuarantineFileCheckException(f"Error processing file while checking for magic numbers of user '{self.userid}'")

                return True
            
            except Exception as e:
                self._log_error(f"Error file hashing files of user '{self.userid}' => {str(e)}\n\n{traceback.format_exc()}")
                raise QuarantineFileCheckException(f"Error processing file while checking for magic numbers of user '{self.userid}'", e)
            
            finally:
                if executor:
                    executor.shutdown(wait=True)
        return None
    
    async def process_scan_for_malware(self):
        scan_for_malware_tasks = [ 
            self.scan_for_malware(hashed_filename)
            for hashed_filename, seen in zip(self._hashed_filenames, self._seen_status)
            if not seen
        ]
        await asyncio.gather(*scan_for_malware_tasks)
        return True