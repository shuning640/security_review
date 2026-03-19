"""Phase 1 prompt: ask model to bootstrap CWD skills."""

from typing import Optional
import json


def get_phase1_skill_bootstrap_prompt(
    cwd_catalog: dict,
    custom_scan_instructions: Optional[str] = None,
) -> str:
    """Generate phase-1 prompt for autonomous CWD skill bootstrap."""
    catalog_context = json.dumps(cwd_catalog, indent=2, ensure_ascii=False)

    custom_section = ""
    if custom_scan_instructions:
        custom_section = f"""

附加扫描要求：
{custom_scan_instructions}
"""

    return f"""你正在执行全仓安全分析的 Phase 1：技能预加载。

任务目标：
1) 根据给定的 CWD 分类目录，尝试自主加载对应技能（skills）。
2) 如果某个技能无法加载，不要中断，记录失败原因。
3) 后续分析阶段将依赖你在这里的加载结果。

CWD 分类目录：
{catalog_context}

输出要求（仅 JSON）：
{{
  "skill_bootstrap_status": "ok",
  "skills_requested": ["cwd-authz", "cwd-input-validation"],
  "skills_loaded": ["cwd-authz"],
  "skills_missing": ["cwd-input-validation"],
  "notes": ["missing skills will use fallback analysis method"]
}}

规则：
- 只输出 JSON。
- 不要输出 Markdown，不要输出额外解释文本。
- 若无法确认加载状态，放入 skills_missing 并在 notes 说明。
{custom_section}
"""


# Backward-compatible alias
get_phase0_skill_bootstrap_prompt = get_phase1_skill_bootstrap_prompt
