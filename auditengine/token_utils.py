"""Token counting and truncation utilities."""

from typing import Dict, Optional

import tiktoken


def _get_encoding(model: Optional[str] = None):
    if model:
        try:
            return tiktoken.encoding_for_model(model)
        except Exception:
            pass
    return tiktoken.get_encoding("cl100k_base")


def count_tokens(text: str, model: Optional[str] = None) -> int:
    if not text:
        return 0
    enc = _get_encoding(model)
    try:
        return len(enc.encode(text))
    except Exception:
        return 0


def truncate_to_token_limit(text: str, max_tokens: int, model: Optional[str] = None) -> str:
    if not text or max_tokens <= 0:
        return ""
    enc = _get_encoding(model)
    try:
        tokens = enc.encode(text)
    except Exception:
        return text
    if len(tokens) <= max_tokens:
        return text
    return enc.decode(tokens[:max_tokens])


def fit_prompts_to_token_limit(
    system_prompt: str,
    prompt: str,
    max_prompt_tokens: int,
    model: Optional[str] = None,
) -> Dict[str, object]:
    """Fit system/user prompts into max token budget by truncating user first."""
    system_prompt = system_prompt or ""
    prompt = prompt or ""

    original_system_tokens = count_tokens(system_prompt, model)
    original_prompt_tokens = count_tokens(prompt, model)
    original_total = original_system_tokens + original_prompt_tokens

    if original_total <= max_prompt_tokens:
        return {
            "system_prompt": system_prompt,
            "prompt": prompt,
            "trimmed": False,
            "original_total_tokens": original_total,
            "final_total_tokens": original_total,
            "original_system_tokens": original_system_tokens,
            "original_prompt_tokens": original_prompt_tokens,
        }

    available_for_prompt = max_prompt_tokens - original_system_tokens
    final_system_prompt = system_prompt
    if available_for_prompt < 0:
        final_system_prompt = truncate_to_token_limit(system_prompt, max_prompt_tokens // 2, model)
        system_tokens = count_tokens(final_system_prompt, model)
        available_for_prompt = max(0, max_prompt_tokens - system_tokens)

    final_prompt = truncate_to_token_limit(prompt, max(0, available_for_prompt), model)
    final_total = count_tokens(final_system_prompt, model) + count_tokens(final_prompt, model)

    return {
        "system_prompt": final_system_prompt,
        "prompt": final_prompt,
        "trimmed": True,
        "original_total_tokens": original_total,
        "final_total_tokens": final_total,
        "original_system_tokens": original_system_tokens,
        "original_prompt_tokens": original_prompt_tokens,
    }
