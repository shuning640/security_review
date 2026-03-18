"""Phase 3 prompt: module-level defect detection."""

from typing import Optional
import json

def get_phase3_vulnerability_assessment_prompt(
    pr_data: dict,
    pr_diff: Optional[str] = None,
    phase1_results: dict = None,
    phase2_results: dict = None,
    include_diff: bool = True,
    custom_scan_instructions: Optional[str] = None,
) -> str:
    """Generate phase-3 prompt for per-module defect detection."""
    repo_name = pr_data.get("head", {}).get("repo", {}).get("full_name", "unknown")
    modules = phase1_results.get("modules", []) if isinstance(phase1_results, dict) else []
    module_risks = phase2_results.get("module_risk_analysis", []) if isinstance(phase2_results, dict) else []

    modules_context = json.dumps(modules, indent=2, ensure_ascii=False)
    risks_context = json.dumps(module_risks, indent=2, ensure_ascii=False)

    custom_section = ""
    if custom_scan_instructions:
        custom_section = f"""

附加扫描要求：
{custom_scan_instructions}
"""

    return f"""你是一名资深应用安全工程师，正在执行全仓安全分析的 Phase 3：模块级缺陷检测。

仓库信息：
- repository: {repo_name}
- scan_scope: full_repository

Phase 1 模块划分：
{modules_context}

Phase 2 风险分析：
{risks_context}

任务要求：
1) 针对每个模块，结合业务逻辑和风险点，做针对性代码检测。
2) 仅输出真实可能触发的缺陷，减少理论性噪声。
3) 每个缺陷必须给出：
   - file
   - line
   - defect_type
   - severity (HIGH/MEDIUM/LOW)
   - description
   - module_name

输出格式必须为 JSON：
{{
  "module_defects": [
    {{
      "module_name": "用户与认证",
      "defects": [
        {{
          "file": "src/auth/service.py",
          "line": 128,
          "defect_type": "权限控制缺失",
          "severity": "HIGH",
          "description": "refresh token 未校验 token 归属用户，存在越权风险",
          "risk_reasoning": "攻击者可通过窃取 token 伪造刷新流程"
        }}
      ]
    }}
  ],
  "analysis_summary": {{
    "modules_scanned": 0,
    "total_defects": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "review_completed": true
  }}
}}

规则：
- 只输出 JSON。
- 不要输出 Markdown 或解释文本。
- 若某模块未发现问题，defects 返回空数组。
{custom_section}
"""
