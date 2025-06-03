# src/tzEnc2/log_config.py
import logging
from logging.handlers import RotatingFileHandler
import sys
from tzEnc2.constants import LOGS_DIR

# Constants
LOG_FILE = LOGS_DIR / "tzenc.log"
LOG_FORMAT = "[%(asctime)s] %(levelname)s - %(name)s - %(message)s"
DEFAULT_LOG_LEVEL = logging.ERROR

# Ensure log directory exists
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# Rotating file handler (5 MB max, 3 backup files)
file_handler = RotatingFileHandler(
    LOG_FILE,
    maxBytes=5 * 1024 * 1024,
    backupCount=3,
    encoding="utf-8"
)

# Console handler
console_handler = logging.StreamHandler(sys.stdout)

# Formatter
formatter = logging.Formatter(LOG_FORMAT)
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Root logger configuration
root_logger = logging.getLogger()
root_logger.setLevel(DEFAULT_LOG_LEVEL)
# root_logger.addHandler(file_handler)
root_logger.addHandler(console_handler)

def set_log_level(level: str):
    """
    Dynamically set the log level for the root logger.
    
    Args:
        level (str): Log level as string ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
    """
    level = level.upper()
    numeric_level = getattr(logging, level, DEFAULT_LOG_LEVEL)
    root_logger.setLevel(numeric_level)

def get_logger(name: str) -> logging.Logger:
    """
    Retrieve a logger with the given name.
    
    Args:
        name (str): Usually `__name__`
        
    Returns:
        logging.Logger: Configured logger instance
    """
    return logging.getLogger(name)
