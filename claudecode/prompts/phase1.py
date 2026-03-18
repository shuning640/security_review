"""Phase 1 prompt: repository module decomposition."""

from typing import Optional

def get_phase1_context_study_prompt(
    pr_data: dict,
    pr_diff: Optional[str] = None,
    include_diff: bool = True,
    custom_scan_instructions: Optional[str] = None,
) -> str:
    """Generate phase-1 prompt for full-repository module decomposition."""
    repo_name = pr_data.get("head", {}).get("repo", {}).get("full_name", "unknown")
    repo_path = pr_data.get("repository_path", "unknown")
    total_files = pr_data.get("changed_files", 0)

    custom_section = ""
    if custom_scan_instructions:
        custom_section = f"""

附加扫描要求：
{custom_scan_instructions}
"""

    return f"""你是一名资深应用安全工程师，正在对整个代码仓进行阶段化缺陷检测（不是PR变更检测）。

阶段目标（Phase 1）：代码仓模块拆分。

仓库上下文：
- repository: {repo_name}
- repository_path: {repo_path}
- scan_scope: full_repository
- candidate_files: {total_files}

任务要求：
1) 先分析仓库目录结构、技术栈与业务特征。
2) 按业务逻辑拆分模块（例如用户、订单、支付、网关、配置中心等）。
3) 每个模块必须给出：
   - module_name
   - paths（目录/文件列表，优先目录）
   - responsibility（模块职责）

执行要求：
- 必须结合业务语义，不要仅按技术目录机械分组。
- 模块数量控制在 3-20 个，覆盖核心业务。
- paths 仅包含实际存在的代码路径，避免虚构。

你必须只输出 JSON，且符合以下结构：
{{
  "modules": [
    {{
      "module_name": "用户与认证",
      "paths": ["src/user", "src/auth"],
      "responsibility": "负责用户资料、登录鉴权、会话令牌管理"
    }}
  ],
  "analysis_summary": {{
    "repository_type": "web_service",
    "primary_languages": ["python"],
    "architecture_style": "monolith_or_microservice",
    "total_modules": 0,
    "notes": ["关键观察1", "关键观察2"]
  }}
}}

仅返回 JSON，不要输出 Markdown，不要输出代码块，不要附加解释文本。
{custom_section}
"""
