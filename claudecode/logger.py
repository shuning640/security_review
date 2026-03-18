"""Logging configuration for ClaudeCode."""

import logging
import sys

def get_logger(name: str) -> logging.Logger:
    """Get a configured logger that outputs to stderr.
    
    Args:
        name: The name of the logger (usually __name__)
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    
    # Only configure if not already configured
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        
        # 新的格式：包含时间(asctime)、logger名称(name)和日志消息(message)
        format_str = '%(asctime)s [%(name)s] %(message)s'
        
        formatter = logging.Formatter(format_str, datefmt='%Y-%m-%d %H:%M:%S')
        
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    
    return logger