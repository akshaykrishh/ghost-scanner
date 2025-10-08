"""
Ghost Scanner - Custom Exceptions

Custom exception classes for the Ghost Scanner application.
"""

from fastapi import HTTPException, status

class GhostScannerException(Exception):
    """Base exception for Ghost Scanner."""
    
    def __init__(self, detail: str, status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR):
        self.detail = detail
        self.status_code = status_code
        super().__init__(detail)

class AuthenticationError(GhostScannerException):
    """Authentication related errors."""
    
    def __init__(self, detail: str = "Authentication failed"):
        super().__init__(detail, status.HTTP_401_UNAUTHORIZED)

class AuthorizationError(GhostScannerException):
    """Authorization related errors."""
    
    def __init__(self, detail: str = "Insufficient permissions"):
        super().__init__(detail, status.HTTP_403_FORBIDDEN)

class ValidationError(GhostScannerException):
    """Validation related errors."""
    
    def __init__(self, detail: str = "Validation failed"):
        super().__init__(detail, status.HTTP_422_UNPROCESSABLE_ENTITY)

class NotFoundError(GhostScannerException):
    """Resource not found errors."""
    
    def __init__(self, detail: str = "Resource not found"):
        super().__init__(detail, status.HTTP_404_NOT_FOUND)

class ConflictError(GhostScannerException):
    """Resource conflict errors."""
    
    def __init__(self, detail: str = "Resource conflict"):
        super().__init__(detail, status.HTTP_409_CONFLICT)

class RateLimitError(GhostScannerException):
    """Rate limiting errors."""
    
    def __init__(self, detail: str = "Rate limit exceeded"):
        super().__init__(detail, status.HTTP_429_TOO_MANY_REQUESTS)

class ScanError(GhostScannerException):
    """Scan execution errors."""
    
    def __init__(self, detail: str = "Scan execution failed"):
        super().__init__(detail, status.HTTP_500_INTERNAL_SERVER_ERROR)

class AIAnalysisError(GhostScannerException):
    """AI analysis errors."""
    
    def __init__(self, detail: str = "AI analysis failed"):
        super().__init__(detail, status.HTTP_500_INTERNAL_SERVER_ERROR)
