"""Phase 2 prompt: feature-driven repository module decomposition."""

from typing import Optional
import json

def get_phase2_context_study_prompt(
    pr_data: dict,
    phase1_results: Optional[dict] = None
) -> str:
    """Generate phase-2 prompt for feature-driven full-repository module decomposition."""

    repo_name = pr_data.get("head", {}).get("repo", {}).get("full_name", "unknown")
    repo_path = pr_data.get("repository_path", "unknown")
    total_files = pr_data.get("changed_files", 0)
    file_tree_with_loc = str(pr_data.get("repository_file_tree_with_loc", "")).strip()
    directory_relation_sentences = str(pr_data.get("directory_relation_sentences", "")).strip()
    feature_list_markdown = ""
    if isinstance(phase1_results, dict):
        feature_list_markdown = str(phase1_results.get("architecture_document_markdown", ""))
    if not feature_list_markdown:
        feature_list_markdown = json.dumps(phase1_results or {}, indent=2, ensure_ascii=False)
    if not file_tree_with_loc:
        file_tree_with_loc = "unknown"

    relation_section = ""
    if directory_relation_sentences:
        relation_section = f"""
目录关系信息（辅助参考）：
{directory_relation_sentences}
"""

    return f"""你是一名资深应用安全工程师，正在对整个代码仓进行阶段化缺陷检测。

阶段目标（Phase 2）：基于功能清单进行代码仓模块拆分。

仓库上下文：
- repository: {repo_name}
- repository_path: {repo_path}
- scan_scope: full_repository
- candidate_files: {total_files}

Phase 1 功能清单：
{feature_list_markdown}

项目文件树（带代码行数）：
{file_tree_with_loc}

{relation_section}

任务要求：
1) 根据 Phase 1 的功能清单拆分最终模块（modules），优先保持功能内聚。
2) 模块划分时必须同时考虑代码行数（LOC）与文件数量，避免大项目分得过粗。
3) 每个最终模块必须给出：
   - module_name
   - paths（目录/文件列表，优先目录）
   - responsibility（模块职责）
   - entrypoints（关键入口，如路由、消息消费者、定时任务、CLI 命令）
   - trust_boundaries（信任边界，如外部输入、跨服务调用、数据库写入）

模块拆分准则：
- 优先功能内聚：同一核心功能链路中的核心目录应尽量落在同一模块。
- 粒度均衡：模块规模需要在 LOC 和文件数量两个维度保持可维护。
- 大模块细分：若某模块 LOC 过高或文件数过多，必须进一步拆分。
- 聚合优先：避免碎片化，小型辅助目录（utils/config/common/scripts）应并入核心功能模块。
- 边界清晰：避免一个路径同时出现在多个模块；如确有交叉，在 notes 说明共享原因。
- 禁止路径嵌套冲突：不要输出会互相覆盖的父子路径组合。
- 覆盖核心：核心执行路径必须被模块覆盖，避免只覆盖工具/配置目录。
- 严禁虚构：只引用可在仓库中定位到的路径，不允许在 modules 中新增完全无证据来源的路径。

规模约束：
- 每个模块聚合后的代码行数应尽量控制在 3,000 到 30,000 行。
- 每个模块文件数应保持在可维护范围；文件数显著偏大的模块必须继续拆分。
- 当 LOC 与文件数约束冲突时，优先保证功能内聚与边界清晰。

你必须只输出 JSON，且符合以下结构：
{{
  "modules": [
    {{
      "module_name": "用户与认证",
      "paths": ["src/user", "src/auth"],
      "responsibility": "负责用户资料、登录鉴权、会话令牌管理",
      "entrypoints": ["POST /login", "POST /refresh"],
      "trust_boundaries": ["HTTP request -> auth service", "auth service -> token store"],
    }}
  ],
  "analysis_summary": {{
    "repository_type": "web_service",
    "primary_languages": ["{pr_data.get('primary_language', 'unknown') or 'unknown'}"],
    "architecture_style": "monolith_or_microservice",
    "total_modules": 0,
    "notes": ["关键观察1", "关键观察2"],
    "coverage_statement": "核心业务路径已覆盖，未纳入模块的仅为低风险支撑目录"
  }}
}}

仅返回 JSON，不要输出 Markdown，不要输出代码块，不要附加解释文本。
如果无法确定某字段，请返回空数组或 "unknown"，不要编造。
"""
