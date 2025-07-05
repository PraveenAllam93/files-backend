import os
from dotenv import load_dotenv
from pydantic_settings import BaseSettings
from typing import ClassVar, List

load_dotenv()

class Settings(BaseSettings):
    
    API_V1_STR: ClassVar[str] = "api/v1"
    PROJECT_NAME: ClassVar[str] = "File Processing Service"

    DEBUG: bool = os.getenv("DEBUG", "False").lower() == "true"

    BACKEND_CORS_ORIGINS: List[str] = ["*"]

    MINIO_ACCESS_KEY: str = os.getenv("MINIO_ACCESS_KEY")
    MINIO_SECRET_KEY: str = os.getenv("MINIO_SECRET_KEY")
    MINIO_ENDPOINT: str = os.getenv("MINIO_ENDPOINT")
    MINIO_BUCKET: str = os.getenv("MINIO_BUCKET", "from_sgc")
    MINIO_QUARANTINE_BUCKET: str = os.getenv("MINIO_QUARANTINE_BUCKET", "praveen-allam-quarantine-files")
    
    REDIS_HOST: str = os.getenv("REDIS_HOST")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))

    IMAGE_MAX_WIDTH: int = 5000
    IMAGE_MAX_HEIGHT: int = 5000
    MAX_MEGAPIXELS: int = 25
    BYTES_PER_PIXEL: float = 0.05
    
    MAX_UPLOAD_SIZE: int = 15
    MAX_FILE_SIZE: int = 15
    IMAGE_EXTENSIONS: List[str] = ["jpg", "jpeg", "png"]
    PDF_EXTENSIONS: List[str] = ["pdf"]
    SOURCE_CODE_EXTENSIONS: List[str] = ['cpp', 'cc', 'cxx', 'h', 'go', 'java', 'kt', 'kts', 'js', 'mjs', 'cjs', 'ts', 'tsx', 'php', 'phtml', 'php3', 'php4', 'php5', 'phps', 'proto', 'py', 'pyw', 'rst', 'rb', 'rhtml', 'rs', 'scala', 'swift', 'md', 'markdown', 'tex', 'ltx', 'cls', 'sty', 'html', 'htm', 'xhtml', 'sol', 'cs', 'cob', 'cbl', 'cpy', 'c', 'h', 'lua', 'pl', 'pm', 't', 'hs', 'lhs', 'ex', 'exs', 'ps1', 'psm1', 'psd1', 'txt']
    TABULAR_EXTENSIONS: List[str] = ["csv", "xlsx", "xls", "parquet"]
    
    ALLOWED_MIME_TYPES: dict = {
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'png': 'image/png',
        'pdf': 'application/pdf',
        'cpp': 'text/x-c++src',
        'cc': 'text/x-c++src',
        'cxx': 'text/x-c++src',
        'h': 'text/x-c',
        'go': 'text/x-go',
        'java': 'text/x-java',
        'kt': 'text/x-kotlin',
        'kts': 'text/x-kotlin',
        'js': 'text/javascript',
        'mjs': 'text/javascript',
        'cjs': 'text/javascript',
        'ts': 'text/typescript',
        'tsx': 'text/typescript-jsx',
        'php': 'application/x-php',
        'phtml': 'application/x-php',
        'php3': 'application/x-php',
        'php4': 'application/x-php',
        'php5': 'application/x-php',
        'phps': 'application/x-php',
        'proto': 'text/plain',
        'py': 'text/x-python',
        'pyw': 'text/x-python',
        'rst': 'text/x-rst',
        'rb': 'text/x-ruby',
        'rhtml': 'text/x-ruby',
        'rs': 'text/x-rust',
        'scala': 'text/x-scala',
        'swift': 'text/x-swift',
        'md': 'text/markdown',
        'markdown': 'text/markdown',
        'tex': 'application/x-tex',
        'ltx': 'application/x-tex',
        'cls': 'application/x-tex',
        'sty': 'application/x-tex',
        'html': 'text/html',
        'htm': 'text/html',
        'xhtml': 'application/xhtml+xml',
        'sol': 'text/plain',
        'cs': 'text/x-csharp',
        'cob': 'text/x-cobol',
        'cbl': 'text/x-cobol',
        'cpy': 'text/x-cobol',
        'c': 'text/x-c',
        'lua': 'text/x-lua',
        'pl': 'text/x-perl',
        'pm': 'text/x-perl',
        't': 'text/x-perl',
        'hs': 'text/x-haskell',
        'lhs': 'text/x-haskell',
        'ex': 'text/x-elixir',
        'exs': 'text/x-elixir',
        'ps1': 'application/x-powershell',
        'psm1': 'application/x-powershell',
        'psd1': 'application/x-powershell',
        'txt': 'text/plain',
        'csv': 'text/csv',
        'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'xls': 'application/vnd.ms-excel',
        'parquet': 'application/vnd.apache.parquet'
    }

    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")

    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))

    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()