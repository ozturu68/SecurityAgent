import logging
from functools import wraps

logger = logging.getLogger(__name__)

class SecurityException(Exception):
    """Temel güvenlik hatası"""
    pass

class ScanException(SecurityException):
    """Tarama işlem hatası"""
    pass

class AIException(SecurityException):
    """AI analiz hatası"""
    pass

def safe_execute(fallback=None):
    """Hata yakalama decorator'ı"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                logger.error(f"{func.__name__} hatası: {e}", exc_info=True)
                return fallback() if callable(fallback) else fallback
        return wrapper
    return decorator