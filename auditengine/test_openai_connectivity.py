#!/usr/bin/env python3
"""Simple connectivity test for OpenAI-compatible model from env config."""

import os
import sys
import time
from pathlib import Path
from typing import Dict


def _load_dotenv_file(dotenv_path: Path) -> Dict[str, str]:
    """Load KEY=VALUE pairs from .env without external dependencies."""
    loaded: Dict[str, str] = {}
    if not dotenv_path.exists() or not dotenv_path.is_file():
        return loaded

    for raw_line in dotenv_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if not key:
            continue
        loaded[key] = value
    return loaded


def _ensure_env_loaded() -> None:
    """Load .env from project root if variables are not already exported."""
    project_root = Path(__file__).resolve().parent.parent
    dotenv_path = project_root / ".env"
    env_from_file = _load_dotenv_file(dotenv_path)
    for key, value in env_from_file.items():
        os.environ.setdefault(key, value)


def main() -> int:
    _ensure_env_loaded()

    base_url = os.environ.get("OPENAI_BASE_URL", "").strip()
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    model = os.environ.get("OPENAI_MODEL", "").strip() or os.environ.get("MODEL_ID", "").strip()
    timeout_seconds_str = os.environ.get("DEFAULT_TIMEOUT_SECONDS", "120")

    missing = []
    if not base_url:
        missing.append("OPENAI_BASE_URL")
    if not api_key:
        missing.append("OPENAI_API_KEY")
    if not model:
        missing.append("OPENAI_MODEL or MODEL_ID")

    if missing:
        print(f"[ERROR] Missing env config: {', '.join(missing)}")
        print("Hint: set values in .env or export them before running this script.")
        return 1

    try:
        timeout_seconds = int(timeout_seconds_str)
    except ValueError:
        timeout_seconds = 120

    try:
        from langchain_openai import ChatOpenAI
        from langchain_core.messages import HumanMessage
    except Exception as exc:
        print(f"[ERROR] Failed to import langchain_openai dependencies: {exc}")
        return 1

    print("[INFO] Testing OpenAI-compatible model connectivity...")
    print(f"[INFO] base_url={base_url}")
    print(f"[INFO] model={model}")

    try:
        client = ChatOpenAI(
            model=model,
            api_key=api_key,
            base_url=base_url,
            timeout=timeout_seconds,
        )

        start = time.time()
        response = client.invoke([HumanMessage(content="Reply exactly with: pong")])
        elapsed = time.time() - start

        content = response.content if isinstance(response.content, str) else str(response.content)
        preview = content.strip().replace("\n", " ")[:200]
        print(f"[OK] Model call succeeded in {elapsed:.2f}s")
        print(f"[OK] Response preview: {preview}")
        return 0
    except Exception as exc:
        print(f"[ERROR] Model call failed: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
