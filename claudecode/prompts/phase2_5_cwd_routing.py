"""Phase 2.5 prompt: module-to-CWD prioritization routing."""

from typing import Optional
import json


def get_phase2_5_cwd_routing_prompt(
    pr_data: dict,
    phase1_results: dict,
    phase2_results: dict,
    cwd_catalog: dict,
    custom_scan_instructions: Optional[str] = None,
) -> str:
    """Generate phase-2.5 prompt for module × CWD priority routing."""
    repo_name = pr_data.get("head", {}).get("repo", {}).get("full_name", "unknown")
    modules = phase1_results.get("modules", []) if isinstance(phase1_results, dict) else []
    module_risks = phase2_results.get("module_risk_analysis", []) if isinstance(phase2_results, dict) else []

    modules_context = json.dumps(modules, indent=2, ensure_ascii=False)
    risks_context = json.dumps(module_risks, indent=2, ensure_ascii=False)
    catalog_context = json.dumps(cwd_catalog, indent=2, ensure_ascii=False)

    custom_section = ""
    if custom_scan_instructions:
        custom_section = f"""

附加扫描要求：
{custom_scan_instructions}
"""

    return f"""你正在执行全仓安全分析的 Phase 2.5：CWD 路由规划。

仓库信息：
- repository: {repo_name}
- scan_scope: full_repository

Phase 1 模块划分：
{modules_context}

Phase 2 风险分析：
{risks_context}

CWD 分类目录：
{catalog_context}

任务要求：
1) 对每个模块从 CWD 分类目录中选出最需要优先检查的类型。
2) 每个模块至少给 1 个 CWD，最多 5 个 CWD。
3) 每条优先级都要给出：priority_score、skill_name、rationale、evidence_paths。
4) 只允许使用 catalog 中存在的 cwd_id 和 skill_name。

输出格式（仅 JSON）：
{{
  "module_cwd_priorities": [
    {{
      "module_name": "用户与认证",
      "cwd_rankings": [
        {{
          "cwd_id": "CWD-0285",
          "skill_name": "cwd-authz",
          "priority_score": 0.92,
          "rationale": "鉴权边界复杂且高风险入口集中",
          "evidence_paths": ["src/auth", "src/user"]
        }}
      ]
    }}
  ],
  "analysis_summary": {{
    "modules_total": 0,
    "cwd_types_considered": 0,
    "pairs_selected": 0
  }}
}}

规则：
- 只输出 JSON。
- 不要输出 Markdown 或解释文本。
- priority_score 范围 [0,1]。
{custom_section}
"""
