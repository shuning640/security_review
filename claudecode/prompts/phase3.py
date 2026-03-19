"""Phase 3 prompt: module-level defect detection."""

from typing import Optional
import json

def get_phase3_vulnerability_assessment_prompt(
    pr_data: dict,
    pr_diff: Optional[str] = None,
    phase1_results: dict = None,
    phase2_results: dict = None,
    phase2_5_results: dict = None,
    include_diff: bool = True,
    custom_scan_instructions: Optional[str] = None,
) -> str:
    """Generate phase-3 prompt for per-module defect detection."""
    del pr_diff
    del include_diff

    repo_name = pr_data.get("head", {}).get("repo", {}).get("full_name", "unknown")
    modules = phase1_results.get("modules", []) if isinstance(phase1_results, dict) else []
    module_risks = phase2_results.get("module_risk_analysis", []) if isinstance(phase2_results, dict) else []
    module_cwd_priorities = phase2_5_results.get("module_cwd_priorities", []) if isinstance(phase2_5_results, dict) else []

    modules_context = json.dumps(modules, indent=2, ensure_ascii=False)
    risks_context = json.dumps(module_risks, indent=2, ensure_ascii=False)
    cwd_routing_context = json.dumps(module_cwd_priorities, indent=2, ensure_ascii=False)

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

Phase 2.5 CWD 路由规划：
{cwd_routing_context}

任务要求：
1) 针对每个模块，结合业务逻辑和风险点，做针对性代码检测。
2) 对每个模块优先按照 CWD 路由中 priority_score 高的类型进行审查。
3) 每个 CWD 类型审查前，尝试自主加载对应 skill_name；若无法加载，使用通用方法继续分析，但要标记状态。
2) 仅输出真实可能触发的缺陷，减少理论性噪声。
4) 缺陷必须满足“可利用性门槛”：必须给出触发路径和前置条件，否则不要报告。
5) 每个缺陷必须给出：
   - file
   - line
   - defect_type
   - severity (HIGH/MEDIUM/LOW)
   - description
   - module_name
   - cwd_id
   - skill_name
   - skill_load_status（loaded/failed/unknown）
   - analysis_method（skill/fallback）
   - exploit_path（source -> sink 或攻击步骤摘要）
   - preconditions（攻击成立所需条件）
   - recommendation（可执行修复建议）
   - confidence（0-1）

降噪规则（必须遵守）：
- 不报告仅理论成立、缺少具体代码证据的问题。
- 不报告仅属代码风格、可维护性或纯健壮性问题。
- 不报告与当前仓库运行边界无关的假设性攻击。
- 证据不足时返回空缺陷，而不是猜测。

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
          "cwd_id": "CWD-1031",
          "skill_name": "cwd-authz",
          "skill_load_status": "loaded",
          "analysis_method": "skill",
          "risk_reasoning": "攻击者可通过窃取 token 伪造刷新流程",
          "exploit_path": "stolen_refresh_token -> refresh endpoint -> session issuance",
          "preconditions": ["攻击者持有可用 refresh token"],
          "recommendation": "将 refresh token 与 user/device/session 绑定并二次校验",
          "confidence": 0.9
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
    "review_completed": true,
    "high_confidence_only": true
  }}
}}

规则：
- 只输出 JSON。
- 不要输出 Markdown 或解释文本。
- 若某模块未发现问题，defects 返回空数组。
- confidence 范围 [0, 1]。
- line 必须是整数；无法定位时使用 0，并在 description 说明定位受限。
{custom_section}
"""
