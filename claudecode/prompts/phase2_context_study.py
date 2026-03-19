"""Phase 2 prompt: repository module decomposition."""

from typing import Optional

def get_phase2_context_study_prompt(
    pr_data: dict,
    pr_diff: Optional[str] = None,
    include_diff: bool = True,
    custom_scan_instructions: Optional[str] = None,
) -> str:
    """Generate phase-2 prompt for full-repository module decomposition."""
    del pr_diff
    del include_diff

    repo_name = pr_data.get("head", {}).get("repo", {}).get("full_name", "unknown")
    repo_path = pr_data.get("repository_path", "unknown")
    total_files = pr_data.get("changed_files", 0)

    custom_section = ""
    if custom_scan_instructions:
        custom_section = f"""

附加扫描要求：
{custom_scan_instructions}
"""

    return f"""你是一名资深应用安全工程师，正在对整个代码仓进行阶段化缺陷检测。

阶段目标（Phase 2）：代码仓模块拆分。

仓库上下文：
- repository: {repo_name}
- repository_path: {repo_path}
- scan_scope: full_repository
- candidate_files: {total_files}

任务要求（先事实后判断，必须两步完成）：

Step A - 事实层（先做证据收集，不做深推理）：
1) 先分析仓库目录结构、技术栈与业务特征，识别核心业务域。
2) 输出模块候选（module_candidates），每个候选必须包含：
   - candidate_id（唯一标识，例如 CAND-1）
   - module_name（候选名）
   - evidence_paths（证据路径，必须是仓库中真实存在的目录/文件）
   - evidence_signals（命名/调用/路由/任务/配置等可观察信号）
   - confidence（0-1）

Step B - 判断层（基于 Step A 结果做模块归并与职责判断）：
3) 按业务逻辑拆分最终模块（modules），不要仅按技术目录分组。
4) 每个最终模块必须给出：
   - module_name
   - paths（目录/文件列表，优先目录）
   - responsibility（模块职责）
   - entrypoints（关键入口，如路由、消息消费者、定时任务、CLI 命令）
   - trust_boundaries（信任边界，如外部输入、跨服务调用、数据库写入）
   - critical_assets（关键资产，如令牌、凭据、PII、交易状态）
   - candidate_refs（引用的 candidate_id 列表，必须来自 module_candidates）

一致性约束（必须遵守）：
- modules[*].paths 必须来自对应 candidate_refs 的 evidence_paths，或是其直接子路径。
- 不允许在 modules 中新增完全无证据来源的路径。
- 若某模块证据不足，可保守合并到上层模块，但必须在 notes 说明。

模块拆分准则：
- 优先业务内聚：同一业务流程中的核心目录应尽量落在同一模块。
- 边界清晰：避免一个路径同时出现在多个模块；如确有交叉，在 notes 说明共享原因。
- 覆盖核心：核心执行路径必须被模块覆盖，避免只覆盖工具/配置目录。
- 严禁虚构：只引用可在仓库中定位到的路径。

执行要求：
- 模块数量控制在 3-20 个，覆盖核心业务。
- 对不确定模块使用保守策略：可暂不拆细，但不要凭空推断职责。

你必须只输出 JSON，且符合以下结构：
{{
  "module_candidates": [
    {{
      "candidate_id": "CAND-1",
      "module_name": "用户与认证候选",
      "evidence_paths": ["src/user", "src/auth"],
      "evidence_signals": ["auth service naming", "login route"],
      "confidence": 0.86
    }}
  ],
  "modules": [
    {{
      "module_name": "用户与认证",
      "paths": ["src/user", "src/auth"],
      "responsibility": "负责用户资料、登录鉴权、会话令牌管理",
      "entrypoints": ["POST /login", "POST /refresh"],
      "trust_boundaries": ["HTTP request -> auth service", "auth service -> token store"],
      "critical_assets": ["access_token", "refresh_token", "user_identity"],
      "candidate_refs": ["CAND-1"]
    }}
  ],
  "analysis_summary": {{
    "repository_type": "web_service",
    "primary_languages": ["python"],
    "architecture_style": "monolith_or_microservice",
    "total_modules": 0,
    "notes": ["关键观察1", "关键观察2"],
    "coverage_statement": "核心业务路径已覆盖，未纳入模块的仅为低风险支撑目录"
  }}
}}

仅返回 JSON，不要输出 Markdown，不要输出代码块，不要附加解释文本。
如果无法确定某字段，请返回空数组或 "unknown"，不要编造。
如果 module_candidates 为空，则 modules 也必须为空，并在 notes 说明原因。
{custom_section}
"""
