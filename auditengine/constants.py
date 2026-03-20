"""
Constants and configuration values for the analysis engine.
"""

import os

# API Configuration
DEFAULT_MODEL_ID = os.environ.get('MODEL_ID') or 'GLM-4.7'
DEFAULT_PROVIDER_ID = os.environ.get('PROVIDER_ID') or 'yun'
DEFAULT_TIMEOUT_SECONDS = 1200  # 20 minutes
DEFAULT_MAX_RETRIES = 3
RATE_LIMIT_BACKOFF_MAX = 30  # Maximum backoff time for rate limits

# Token Limits
PROMPT_TOKEN_LIMIT = 16384

# Exit Codes
EXIT_SUCCESS = 0
EXIT_GENERAL_ERROR = 1
EXIT_CONFIGURATION_ERROR = 2

# Subprocess Configuration
SUBPROCESS_TIMEOUT = 1200  # 20 minutes
