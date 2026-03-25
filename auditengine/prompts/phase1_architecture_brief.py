"""Phase 1 prompt: repository feature list generation."""

def get_phase1_architecture_brief_prompt(
    pr_data: dict
) -> str:
    """Generate phase-1 prompt for repository feature list."""

    repo_name = pr_data.get("head", {}).get("repo", {}).get("full_name", "unknown")
    repo_path = pr_data.get("repository_path", "unknown")
    total_files = pr_data.get("changed_files", 0)
    file_tree_with_loc = str(pr_data.get("repository_file_tree_with_loc", "")).strip()
    directory_relation_sentences = str(pr_data.get("directory_relation_sentences", "")).strip()

    if not file_tree_with_loc:
        file_tree_with_loc = "unknown"

    relation_section = ""
    if directory_relation_sentences:
        relation_section = f"""
目录关系信息：
{directory_relation_sentences}
"""

    return f"""你是一名资深软件架构师，正在执行阶段化安全检测流程的 Phase 1：项目功能清单生成。

仓库信息：
- repository: {repo_name}
- repository_path: {repo_path}
- scan_scope: full_repository
- candidate_files: {total_files}

项目文件树（带代码行数）：
{file_tree_with_loc}

{relation_section}

目标：
仅生成可用于后续模块划分的“功能清单”。

任务要求：
1) 识别主要业务功能与关键技术能力（如认证、调度、存储、通信、任务执行、数据处理等）。
2) 详细列出并逐一描述项目的核心功能，确保功能粒度适中，避免过粗或过细。
3) 每个功能都必须给出关键代码片段所在位置（目录或文件相对路径）。
4) 功能说明必须体现“做什么 + 关键实现机制”，避免空泛描述。
5) 优先级只能使用：高 / 中 / 低。
6) 所有结论必须基于真实代码路径，不要臆造。

输出格式要求：
- 仅输出 Markdown 表格，不要输出任何额外说明文本。
- 表头必须严格为：
| 功能清单 | 功能说明 | 关键代码位置 | 优先级 |
- 输出示例：
  | 功能清单 | 功能说明 | 关键代码位置 | 优先级 | 
  |-------|--------|------|--------| 
  | (示例) 创建主机 | 基于网络与规格元数据，注入配置、下载镜像、配置网络、构建主机 | 路径 | 高 |
  | (示例) 删除主机 | 删除主机对应的资源与主机实例 | 路径 | 高 |
  | (示例) 关闭主机 | 关机 | 路径 | 中 |

规则：
- 仅输出表格正文，不要输出代码块。
- 内容必须使用中文。
- 路径必须是可定位的仓库真实路径。
"""
