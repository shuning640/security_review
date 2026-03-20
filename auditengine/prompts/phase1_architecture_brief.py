"""Phase 1 prompt: repository software design documentation."""

from typing import Optional


def get_phase1_architecture_brief_prompt(
    pr_data: dict
) -> str:
    """Generate phase-1 prompt for repository architecture brief."""

    repo_name = pr_data.get("head", {}).get("repo", {}).get("full_name", "unknown")
    repo_path = pr_data.get("repository_path", "unknown")
    total_files = pr_data.get("changed_files", 0)

    return f"""你是一名资深软件架构师，正在执行阶段化安全检测流程的 Phase 1：软件设计文档生成。

仓库上下文：
- repository: {repo_name}
- repository_path: {repo_path}
- scan_scope: full_repository
- candidate_files: {total_files}

目标：
仅生成可用于后续模块划分的“软件与架构设计文档”。

任务要求：
1) 识别技术栈与工程结构：语言、框架、构建系统、运行方式、核心依赖。
2) 梳理系统边界与组件设计：核心组件、职责、组件间依赖关系。
3) 梳理关键入口与执行路径：HTTP 路由、CLI、消息消费者、定时任务、主流程入口。
4) 梳理数据与状态：关键数据存储、跨组件数据流、状态转换与持久化路径。
5) 标注信任边界与关键资产：外部输入边界、跨服务边界、数据库写入边界、敏感资产位置。
6) 所有结论必须基于真实代码路径，不要臆造。

输出格式要求：
- 输出为结构化 Markdown 文档（不是 JSON）。
- 文档标题建议为：`# 软件设计文档`。
- 文档至少包含以下章节：
  1. 仓库概况
  2. 架构总览
  3. 核心组件设计
  4. 入口点与执行路径
  5. 数据流与数据存储
  6. 信任边界与关键资产
  7. 面向模块划分的约束、未知项与备注

规则：
- 仅输出 Markdown 文档正文，不要使用代码块包裹整篇文档。
- 文档内容必须使用中文。
- 路径必须是可定位的仓库真实路径。
"""
