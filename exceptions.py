import traceback


class BaseCustomException(Exception):
    def __init__(self, message: str, original_exception: Exception = None):
        super().__init__(message)
        self.message = message
        self.original_exception = original_exception
        self.error_type = (
            type(original_exception).__name__ if original_exception else None
        )
        self.error_message = str(original_exception) if original_exception else None
        self.traceback = (
            "".join(traceback.format_tb(original_exception.__traceback__))
            if original_exception and original_exception.__traceback__
            else None
        )

    def to_dict(self):
        return {
            "exception": self.__class__.__name__,
            "message": self.message,
            "error_type": self.error_type,
            "error_message": self.error_message,
            "traceback": self.traceback,
        }


class MinIOException(BaseCustomException):
    pass


class QuarantineFileCheckException(BaseCustomException):
    pass


class ImageFileCheckException(BaseCustomException):
    pass


class PDFFileCHeckException(BaseCustomException):
    pass
