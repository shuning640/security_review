"""
Constants and configuration values for the analysis engine.
"""

import os


def _get_str(name: str, default: str = "") -> str:
    value = os.environ.get(name)
    if value is None:
        return default
    stripped = value.strip()
    return stripped if stripped else default


def _get_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


def _get_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value.strip())
    except (TypeError, ValueError):
        return default


def _get_csv_list(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]

# API Configuration
NO_PROXY = _get_str("NO_PROXY", "127.0.0.1,7.185.124.169,7.192.168.161,localhost,*.huawei.com")
OPENCODE_SERVER_BIN = _get_str("OPENCODE_SERVER_BIN", "opencode")
OPENCODE_API_URL = _get_str("OPENCODE_API_URL")
OPENCODE_PORT = _get_int("OPENCODE_PORT", 4096)

LLM_BACKEND = _get_str("LLM_BACKEND", "opencode").lower()
OPENAI_BASE_URL = _get_str("OPENAI_BASE_URL")
OPENAI_API_KEY = _get_str("OPENAI_API_KEY")
OPENAI_MODEL = _get_str("OPENAI_MODEL")

DEFAULT_MODEL_ID = _get_str("MODEL_ID")
DEFAULT_PROVIDER_ID = _get_str("PROVIDER_ID")
DEFAULT_TIMEOUT_SECONDS = _get_int("DEFAULT_TIMEOUT_SECONDS", 1200)
DEFAULT_MAX_RETRIES = _get_int("DEFAULT_MAX_RETRIES", 3)
RATE_LIMIT_BACKOFF_MAX = _get_int("RATE_LIMIT_BACKOFF_MAX", 30)

# Token Limits
PROMPT_TOKEN_LIMIT = _get_int("PROMPT_TOKEN_LIMIT", 100000)

# Workflow/Scan Configuration
ANALYSIS_SCOPE = _get_str("ANALYSIS_SCOPE")
USE_PHASED_ANALYSIS = _get_bool("USE_PHASED_ANALYSIS", True)
PHASE_PARALLELISM = _get_int("PHASE_PARALLELISM", 4)
EXCLUDE_DIRECTORIES = _get_csv_list("EXCLUDE_DIRECTORIES")

ENABLE_OPENCODE_FILTERING = _get_bool("ENABLE_OPENCODE_FILTERING", True)
ENABLE_HARD_EXCLUSIONS = _get_bool("ENABLE_HARD_EXCLUSIONS", True)

FALSE_POSITIVE_FILTERING_INSTRUCTIONS = _get_str("FALSE_POSITIVE_FILTERING_INSTRUCTIONS")
CUSTOM_SECURITY_SCAN_INSTRUCTIONS = _get_str("CUSTOM_SECURITY_SCAN_INSTRUCTIONS")

# Runtime Context
GITHUB_TOKEN = _get_str("GITHUB_TOKEN")
GIT_URL = _get_str("GIT_URL")
PR_NUMBER = _get_str("PR_NUMBER")
REPO_PATH = _get_str("REPO_PATH")
REPO_NAME = _get_str("REPO_NAME")
OUTPUT_DIR = _get_str("OUTPUT_DIR")
CWD_CATALOG_PATH = _get_str("CWD_CATALOG_PATH")
RUNTIME_USER = _get_str("USER", "system")

# Exit Codes
EXIT_SUCCESS = 0
EXIT_GENERAL_ERROR = 1
EXIT_CONFIGURATION_ERROR = 2

# Subprocess Configuration
SUBPROCESS_TIMEOUT = _get_int("SUBPROCESS_TIMEOUT", 1200)
