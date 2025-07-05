from models.image_quarantine_check import ImageQuarantineCheck
from typing import List, Iterator, Optional
from dataclasses import dataclass
from io import BytesIO
from PIL import Image

from exceptions import ImageFileCheckException
from services.quarantine_file_check_service import QuarantineFileCheckService
from config.settings import settings
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from contextlib import contextmanager
import logging

logger = logging.getLogger(__name__)


@dataclass
class ImageCheckResult:
    filename: str
    width: Optional[int] = None
    height: Optional[int] = None
    file_size: Optional[int] = None
    

class ImageQuarantineCheckService(ImageQuarantineCheck, QuarantineFileCheckService):
    
    def __init__(self,
                 query: str, 
                 urls: List[str], 
                 filenames: List[str], 
                 userid: str, 
                 timeout: int = 30,
                 max_workers: int = 10,
            ):
        
        super().__init__(query, urls, filenames, userid, timeout)
        self.max_workers = max_workers

        
    def _validate_image_dimensions(self, width: int, height: int):
        """Validate image dimensions against security limits."""
        try:
            if width > settings.IMAGE_MAX_WIDTH or height > settings.IMAGE_MAX_HEIGHT:
                raise ImageFileCheckException(
                f"Image dimensions {width}x{height} exceed maximum allowed "
                f"{settings.IMAGE_MAX_WIDTH}x{settings.IMAGE_MAX_HEIGHT}"
            )
        except Exception as e:
            raise ImageFileCheckException(f"Image file check failed", e)

    def _validate_megapixel_limit(self, width: int, height: int):
        try:
            megapixels = (width * height) / 1_000_000
            if megapixels > settings.MAX_MEGAPIXELS:
                raise ImageFileCheckException(
                f"Image {megapixels:.2f}MP exceeds maximum {settings.MAX_MEGAPIXELS}MP"
            )
        except Exception as e:
            raise ImageFileCheckException(f"Image file check failed", e)
        
    def _validate_file_density(self, width: int, height: int, file_size: int):
        try: 
            pixel_count = width * height
            if pixel_count == 0:
                raise ImageFileCheckException("Image has zero pixels")
            
            bpp = file_size / pixel_count
            if bpp < settings.BYTES_PER_PIXEL:
                raise ImageFileCheckException(
                f"File density {bpp:.4f} bytes/pixel below minimum {settings.BYTES_PER_PIXEL}"
            )
        except Exception as e:
            raise ImageFileCheckException(f"Image file check failed", e)
        
    def run_image_check_pipeline(self, file_content: bytes, filename: str):
        file_size = len(file_content)
        file_size_mb = round(file_size / (1024 * 1024), 2)
        logger.info(f"Checking image {filename} for pixel flooding attack...")
        try:        
            with Image.open(BytesIO(file_content)) as img:
                width, height = img.size
                self._validate_image_dimensions(width, height)
                self._validate_megapixel_limit(width, height)
                self._validate_file_density(width, height, file_size)
            
            logger.info(
                f"Image validation passed for {filename}: "
                f"{width}x{height}, {file_size_mb} MB"
            )
            return ImageCheckResult(
                filename,
                width,
                height,
                file_size_mb,
            )
        except ImageFileCheckException:
            raise 
        except Exception as e:
            logger.error(
                f"Unexpected error processing {filename}: {e}",
                exc_info=True
            )
            raise ImageFileCheckException(f"Failed to process image {filename}: {e}")
        
    
    @contextmanager
    def _managed_thread_pool(self) -> Iterator[ThreadPoolExecutor]:
        """Context manager for thread pool with guaranteed cleanup."""
        executor = ThreadPoolExecutor(max_workers=self.max_workers)
        try:
            yield executor
        finally:
            executor.shutdown(wait=True)  # Graceful shutdown with timeout  
        
    def scan_multiple_files(self):
        """
        Process multiple images for pixel flooding attacks.
        
        Args:
            fail_fast: If True, stop processing on first failure
            
        Returns:
            List of ImageCheckResult objects
        """
        
        if not self._file_contents:
            logger.warning(f"No file contents to process for user {self.userid}")
            raise ImageFileCheckException(f"No file contents to process for user {self.userid}")
        
        logger.info(
            f"Starting pixel flooding check for {len(self._file_contents)} files "
            f"for user {self.userid}"
        )
        
        results = []
        
        with self._managed_thread_pool() as executor:
            future_to_filename = {}
            
            for content, filename, seen in zip(self._file_contents, self.filenames, self._seen_status):
                if not seen:
                    future = executor.submit(self.run_image_check_pipeline, content, filename)
                    future_to_filename[future] = filename
                    
            for future in as_completed(future_to_filename, timeout= self.timeout):
                filename = future_to_filename[future]
                
                try:
                    result = future.result(timeout=10)
                    results.append(result)
                
                except TimeoutError:
                    logger.error(f"Timeout checking {filename} for user {self.userid}")
                    raise ImageFileCheckException(
                        f"Timeout while checking {filename} for pixel flooding attack"
                    )
                
                except ImageFileCheckException as e:
                    logger.error(f"Security check failed for {filename}: {e}")
                    raise
                except Exception as e:
                    logger.error(f"Unexpected error processing {filename}: {e}", exc_info=True)
                    raise ImageFileCheckException(
                        f"Error processing {filename} for pixel flooding attack: {e}"
                    )
        
        logger.info(f"All {len(results)} images passed pixel flooding check")
        results = self.get_validation_summary(results)
        return results
        

    def get_validation_summary(self, results: List[ImageCheckResult]) -> dict:
        """Get summary statistics from validation results."""
        if not results:
            return {}
        
        return {
            "total_files": len(results),
            'total_pixels': sum(r.width * r.height for r in results if r.width and r.height),
            'total_mb': sum(r.file_size for r in results if r.file_size),
            'max_dimensions': max(
                (r.width, r.height) for r in results if r.width and r.height
            ),
            "is_image": True
        }