from typing import Optional, Dict, Any
from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from domain.contracts.logging import logger
import traceback

class AppException(HTTPException):
    """کلاس پایه برای همه خطاهای سفارشی برنامه"""
    def __init__(
        self,
        status_code: int,
        detail: str,
        error_code: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        super().__init__(status_code=status_code, detail=detail)
        self.error_code = error_code or f"ERR_{status_code}"
        self.metadata = metadata or {}

class NotFoundException(AppException):
    def __init__(self, detail: str = "Resource not found", metadata: Optional[Dict[str, Any]] = None):
        super().__init__(status_code=status.HTTP_404_NOT_FOUND, detail=detail, error_code="NOT_FOUND", metadata=metadata)

class BadRequestException(AppException):
    def __init__(self, detail: str = "Bad request", metadata: Optional[Dict[str, Any]] = None):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail, error_code="BAD_REQUEST", metadata=metadata)

class UnauthorizedException(AppException):
    def __init__(self, detail: str = "Unauthorized", metadata: Optional[Dict[str, Any]] = None):
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail, error_code="UNAUTHORIZED", metadata=metadata)

class ConflictException(AppException):
    def __init__(self, detail: str = "Conflict", metadata: Optional[Dict[str, Any]] = None):
        super().__init__(status_code=status.HTTP_409_CONFLICT, detail=detail, error_code="CONFLICT", metadata=metadata)

class ServiceUnavailableException(AppException):
    def __init__(self, detail: str = "Service unavailable", metadata: Optional[Dict[str, Any]] = None):
        super().__init__(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=detail, error_code="SERVICE_UNAVAILABLE", metadata=metadata)

class ExternalServiceException(AppException):
    def __init__(self, detail: str = "External service error", metadata: Optional[Dict[str, Any]] = None):
        super().__init__(status_code=status.HTTP_502_BAD_GATEWAY, detail=detail, error_code="EXTERNAL_ERROR", metadata=metadata)

def register_exception_handlers(app):
    """ثبت همه هندلرهای خطا در FastAPI"""
    
    @app.exception_handler(AppException)
    async def app_exception_handler(request: Request, exc: AppException):
        logger.error(
            f"AppException: {exc.detail}",
            extra={
                "error_code": exc.error_code,
                "status_code": exc.status_code,
                "metadata": exc.metadata,
                "path": request.url.path
            }
        )
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "success": False,
                "error": {
                    "code": exc.error_code,
                    "message": exc.detail,
                    "metadata": exc.metadata
                }
            }
        )
    
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        errors = []
        for error in exc.errors():
            errors.append({
                "field": ".".join(str(loc) for loc in error.get("loc", [])),
                "message": error.get("msg", "Invalid value"),
                "type": error.get("type", "validation_error")
            })
        
        logger.warning(
            f"Validation error: {errors}",
            extra={"path": request.url.path}
        )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "success": False,
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Request validation failed",
                    "details": errors
                }
            }
        )
    
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        logger.warning(
            f"HTTP exception: {exc.detail}",
            extra={"status_code": exc.status_code, "path": request.url.path}
        )
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "success": False,
                "error": {
                    "code": f"HTTP_{exc.status_code}",
                    "message": exc.detail
                }
            }
        )
    
    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception):
        logger.error(
            f"Unhandled exception: {str(exc)}",
            extra={
                "path": request.url.path,
                "traceback": traceback.format_exc()
            }
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "success": False,
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "An unexpected error occurred. Please try again later."
                }
            }
        )