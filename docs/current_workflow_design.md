# 当前项目工作流程设计文档

## 1. 目的

本文档说明当前项目的安全审计能力与阶段化执行流程，重点描述缺陷检测如何结合 `skill` 调用完成分析与结果审计。

## 2. 能力概述

项目采用“全仓理解 + 模块化并发检测 + 聚合过滤”流程：

- 先生成全仓软件设计文档（中文 Markdown），形成后续分析上下文。
- 再进行模块拆分，明确模块边界和关键路径。
- 对每个模块并发执行 3/4/5 阶段（同一模块在同一 session 串行）。
- 汇总去重后执行误报过滤，输出最终缺陷报告。

## 3. 阶段流程

1. `Phase 1`：软件设计文档生成（全仓）
2. `Phase 2`：模块拆分（基于 Phase 1 文档）
3. `Phase 3`：模块业务与风险分析
4. `Phase 4`：模块 CWD 路由规划
5. `Phase 5`：模块缺陷检测（基于 skill）
6. `Phase 6`：缺陷聚合与去重
7. `Phase 7`：误报过滤与最终输出

## 4. 核心执行机制

### 4.1 模块级并发模型

- 系统按模块创建并发任务。
- 每个模块创建一个独立 OpenCode session。
- 在该模块 session 内串行执行 `Phase 3 -> Phase 4 -> Phase 5`。
- 支持部分成功汇总：部分模块失败不会阻断全部结果；仅当全部模块失败时阶段失败。

### 4.2 Phase 5 缺陷检测与 Skill 机制

缺陷检测并非只基于模型文本推断，而是结合 CWD 路由和 skill 使用证据：

1. `Phase 4` 先给出模块级 CWD 优先级（`cwd_id`, `skill_name`, `priority_score`）。
2. `Phase 5` 依据选择的CWD调用对应的SKILL，对模块代码进行针对性检测，输出缺陷明细（文件、行号、缺陷类型、可利用路径、修复建议等）。
3. 在模块 session 内，系统会拉取会话消息历史（`session.messages`）并审计 `tool=skill` 的调用轨迹。
4. 审计结果会回写到缺陷字段 `skill_load_status`，用于标注“是否有可验证 skill 调用证据”。

当前 `skill_load_status` 的审计语义：

- `loaded_verified`：检测到对应 skill 调用且状态完成。
- `failed_verified`：检测到对应 skill 被尝试调用，但未完成/失败。
- `unknown_unmatched_trace`：检测到 skill 工具调用轨迹，但与该缺陷 `skill_name` 未匹配。
- `unknown_no_trace`：未检测到任何 skill 工具调用轨迹。

说明：若未检测到 skill 调用轨迹，系统仅记录审计状态，不会直接判定模块失败。

## 5. 关键产物

- Phase 1
  - `phase1_architecture_document.md`
  - `phase1_architecture_result.json`
- Phase 2
  - `phase2_result.json`
- Phase 3/4/5（模块级）
  - `phase3_module_<idx>_*.json/.txt`
  - `phase4_module_<idx>_*.json/.txt`
  - `phase5_module_<idx>_*.json/.txt`
  - `phase5_module_<idx>_session_messages.json`
  - `phase5_module_<idx>_skill_audit.json`
- 汇总
  - `phase3_result.json`
  - `phase4_result.json`
  - `phase5_result.json`
  - `phase6_result.json`
  - `phase7_result.json`
  - `final_result.json`

## 6. 可观测性与稳定性

- 每个阶段都会输出统一 metadata（耗时、状态、输入输出文件）。
- JSON 解析失败不再静默回退为空结果，避免“无结果被误判为无漏洞”。
- `Phase 5` 汇总中包含 skill 审计统计（如有无 trace 的模块数、可验证 skill 缺陷数）。

## 7. 维护建议

- 调整提示词后，优先检查 `phase5_module_*_skill_audit.json` 与 `skill_load_status` 分布。
- 若 `unknown_no_trace` 占比异常高，优先排查模型工具调用可见性和服务端事件输出。
- 过滤策略应与目标漏洞类型保持一致，避免将核心缺陷类型系统性过滤。

## 8. 流程图

```mermaid
flowchart TD
    A[开始扫描] --> B[Phase 1: 生成软件设计文档]
    B --> C[Phase 2: 模块拆分]
    C --> D{按模块并发任务}

    D --> E1[模块Session-1\nPhase3 风险分析]
    D --> E2[模块Session-2\nPhase3 风险分析]
    D --> E3[模块Session-N\nPhase3 风险分析]

    E1 --> F1[Phase4 CWD路由]
    E2 --> F2[Phase4 CWD路由]
    E3 --> F3[Phase4 CWD路由]

    F1 --> G1[Phase5 基于SKILL进行缺陷检测]
    F2 --> G2[Phase5 基于SKILL进行缺陷检测]
    F3 --> G3[Phase5 基于SKILL进行缺陷检测]

    G1 --> I[汇总模块结果]
    G2 --> I
    G3 --> I

    I --> J[Phase6 聚合去重]
    J --> K[Phase7 误报过滤]
    K --> L[输出最终报告]
```
