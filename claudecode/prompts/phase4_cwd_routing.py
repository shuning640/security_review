"""Phase 4 prompt: module-to-CWD prioritization routing."""

from typing import Optional
import json


def get_phase4_cwd_routing_prompt(
    pr_data: dict,
    phase2_results: dict,
    phase3_results: dict,
    cwd_catalog: dict,
    custom_scan_instructions: Optional[str] = None,
) -> str:
    """Generate phase-4 prompt for module × CWD priority routing."""
    repo_name = pr_data.get("head", {}).get("repo", {}).get("full_name", "unknown")
    modules = phase2_results.get("modules", []) if isinstance(phase2_results, dict) else []
    module_risks = phase3_results.get("module_risk_analysis", []) if isinstance(phase3_results, dict) else []

    modules_context = json.dumps(modules, indent=2, ensure_ascii=False)
    risks_context = json.dumps(module_risks, indent=2, ensure_ascii=False)
    catalog_context = json.dumps(cwd_catalog, indent=2, ensure_ascii=False)

    custom_section = ""
    if custom_scan_instructions:
        custom_section = f"""

附加扫描要求：
{custom_scan_instructions}
"""

    return f"""你正在执行模块级安全分析的 Phase 4：CWD 路由规划。

仓库信息：
- repository: {repo_name}
- scan_scope: module_only

当前模块信息：
{modules_context}

当前模块风险分析：
{risks_context}

CWD 分类目录：
{catalog_context}

任务要求：
1) 仅对当前模块从 CWD 分类目录中选出最需要优先检查的类型。
2) 当前模块至少给 1 个 CWD，最多 5 个 CWD。
3) 每条优先级都要给出：priority_score、skill_name、rationale、evidence_paths。
4) 只允许使用 catalog 中存在的 cwd_id 和 skill_name。

范围约束（必须遵守）：
- 输出中的 module_cwd_priorities 仅允许包含一个模块对象（即当前模块）。
- evidence_paths 必须来自当前模块 paths 或其直接子路径。
- 不得输出其他模块的路由结果。

输出格式（仅 JSON）：
{{
  "module_cwd_priorities": [
    {{
      "module_name": "用户与认证",
      "cwd_rankings": [
        {{
          "cwd_id": "CWD-1031",
          "skill_name": "",
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
