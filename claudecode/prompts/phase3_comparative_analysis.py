"""Phase 3 prompt: module business and risk analysis."""

from typing import Optional
import json

def get_phase3_comparative_analysis_prompt(
    pr_data: dict,
    pr_diff: Optional[str] = None,
    phase1_results: dict = None,
    include_diff: bool = True,
    custom_scan_instructions: Optional[str] = None,
) -> str:
    """Generate phase-3 prompt for per-module business flow and risk analysis."""
    del pr_diff
    del include_diff

    repo_name = pr_data.get("head", {}).get("repo", {}).get("full_name", "unknown")
    modules = phase1_results.get("modules", []) if isinstance(phase1_results, dict) else []

    modules_context = json.dumps(modules, indent=2, ensure_ascii=False)

    custom_section = ""
    if custom_scan_instructions:
        custom_section = f"""

附加扫描要求：
{custom_scan_instructions}
"""

    return f"""你是一名资深应用安全工程师，正在执行全仓安全分析的 Phase 3：模块业务逻辑与风险分析。

仓库信息：
- repository: {repo_name}
- scan_scope: full_repository

Phase 2 模块拆分结果如下：
{modules_context}

任务要求（对每个模块分别执行）：
1) 分析模块核心业务流程（包含调用链、关键函数、关键入口与出口、状态变化）。
2) 识别该模块下潜在风险点，至少覆盖以下类型：
   - 权限控制缺失
   - 输入校验不足
   - 敏感信息泄露
   - 并发/事务问题
   - 依赖组件风险
3) 风险必须绑定证据：每个风险都要提供可定位路径，必要时给出函数/类名。
4) 风险必须说明可利用前提（preconditions）和影响面（impact_scope），避免纯理论描述。
5) 对低确定性风险保持保守：若证据不足，请降级或不报。

输出必须是 JSON，且结构如下：
{{
  "module_risk_analysis": [
    {{
      "module_name": "用户与认证",
      "business_flow": [
        "入口: /login -> service.authenticate -> token.issue",
        "入口: /refresh -> token.validate -> token.rotate"
      ],
      "key_functions": ["auth_service.authenticate", "token_service.issue"],
      "attack_surfaces": ["/login", "/refresh", "token persistence"],
      "risks": [
        {{
          "risk_type": "权限控制缺失",
          "risk_level": "HIGH",
          "description": "刷新令牌接口未绑定用户设备上下文",
          "evidence_paths": ["src/auth/refresh.py"],
          "evidence_functions": ["refresh_token", "validate_refresh_token"],
          "preconditions": ["攻击者可获取可用 refresh token"],
          "impact_scope": "可能导致跨账户会话劫持",
          "confidence": 0.86
        }}
      ]
    }}
  ],
  "analysis_summary": {{
    "modules_analyzed": 0,
    "high_risk_count": 0,
    "medium_risk_count": 0,
    "low_risk_count": 0,
    "overall_confidence": 0.0
  }}
}}

规则：
- 仅输出 JSON。
- 不要输出 Markdown 或解释性文本。
- risk_level 使用 HIGH/MEDIUM/LOW。
- confidence 范围 [0, 1]。
- 若某模块未识别到有效风险，risks 返回空数组。
{custom_section}
"""


# Backward-compatible alias
get_phase2_comparative_analysis_prompt = get_phase3_comparative_analysis_prompt
