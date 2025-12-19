# backend/app/core/logging.py
import logging
import sys
import json
from datetime import datetime
from typing import Dict, Any
from pythonjsonlogger import jsonlogger


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter for structured logging"""
    
    def add_fields(self, log_record: Dict[str, Any], record: logging.LogRecord, message_dict: Dict[str, Any]):
        super().add_fields(log_record, record, message_dict)
        
        if not log_record.get("timestamp"):
            log_record["timestamp"] = datetime.utcnow().isoformat()
        
        if record.name:
            log_record["logger"] = record.name
        
        log_record["level"] = record.levelname
        
        # Add request context if available
        if hasattr(record, "tenant_id"):
            log_record["tenant_id"] = record.tenant_id
        
        if hasattr(record, "user_id"):
            log_record["user_id"] = record.user_id
        
        if hasattr(record, "request_id"):
            log_record["request_id"] = record.request_id


def setup_logging(level: str = "INFO") -> logging.Logger:
    """Configure structured JSON logging"""
    logger = logging.getLogger("forgescan")
    logger.setLevel(level)
    logger.propagate = False
    
    # Console handler with JSON formatting
    console_handler = logging.StreamHandler(sys.stdout)
    formatter = CustomJsonFormatter(
        "%(timestamp)s %(level)s %(logger)s %(message)s"
    )
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger


# Initialize logger
logger = setup_logging()