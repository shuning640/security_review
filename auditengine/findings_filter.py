"""Findings filter for reducing false positives in security audit results."""

import re
from typing import Dict, Any, List, Tuple, Optional, Pattern
import time
from dataclasses import dataclass, field
import json
import os
from datetime import datetime
import sys
from pathlib import Path

from auditengine.unified_output_manager import UnifiedOutputManager, NoOpOutputManager
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from auditengine.session_manager import get_session_manager
from auditengine.constants import DEFAULT_MODEL_ID, DEFAULT_PROVIDER_ID, PROMPT_TOKEN_LIMIT, REPO_PATH
from auditengine.logger import get_logger
from auditengine.json_parser import parse_json_with_fallbacks
from auditengine.token_utils import count_tokens, truncate_to_token_limit

logger = get_logger(__name__)


@dataclass
class FilterStats:
    """Statistics about the filtering process."""
    total_findings: int = 0
    hard_excluded: int = 0
    ai_excluded: int = 0
    kept_findings: int = 0
    exclusion_breakdown: Dict[str, int] = field(default_factory=dict)
    confidence_scores: List[float] = field(default_factory=list)
    runtime_seconds: float = 0.0


class HardExclusionRules:
    """Hard exclusion rules for common false positives."""
    
    # Pre-compiled regex patterns for better performance
    _DOS_PATTERNS: List[Pattern] = [
        re.compile(r'\b(denial of service|dos attack|resource exhaustion)\b', re.IGNORECASE),
        re.compile(r'\b(exhaust|overwhelm|overload).*?(resource|memory|cpu)\b', re.IGNORECASE),
        re.compile(r'\b(infinite|unbounded).*?(loop|recursion)\b', re.IGNORECASE),
    ]
    
    
    _RATE_LIMITING_PATTERNS: List[Pattern] = [
        re.compile(r'\b(missing|lack of|no)\s+rate\s+limit', re.IGNORECASE),
        re.compile(r'\brate\s+limiting\s+(missing|required|not implemented)', re.IGNORECASE),
        re.compile(r'\b(implement|add)\s+rate\s+limit', re.IGNORECASE),
        re.compile(r'\bunlimited\s+(requests|calls|api)', re.IGNORECASE),
    ]
    
    _RESOURCE_PATTERNS: List[Pattern] = [
        re.compile(r'\b(resource|memory|file)\s+leak\s+potential', re.IGNORECASE),
        re.compile(r'\bunclosed\s+(resource|file|connection)', re.IGNORECASE),
        re.compile(r'\b(close|cleanup|release)\s+(resource|file|connection)', re.IGNORECASE),
        re.compile(r'\bpotential\s+memory\s+leak', re.IGNORECASE),
        re.compile(r'\b(database|thread|socket|connection)\s+leak', re.IGNORECASE),
    ]
    
    _OPEN_REDIRECT_PATTERNS: List[Pattern] = [
        re.compile(r'\b(open redirect|unvalidated redirect)\b', re.IGNORECASE),
        re.compile(r'\b(redirect.(attack|exploit|vulnerability))\b', re.IGNORECASE),
        re.compile(r'\b(malicious.redirect)\b', re.IGNORECASE),
    ]
    
    _MEMORY_SAFETY_PATTERNS: List[Pattern] = [
        re.compile(r'\b(buffer overflow|stack overflow|heap overflow)\b', re.IGNORECASE),
        re.compile(r'\b(oob)\s+(read|write|access)\b', re.IGNORECASE),
        re.compile(r'\b(out.?of.?bounds?)\b', re.IGNORECASE),
        re.compile(r'\b(memory safety|memory corruption)\b', re.IGNORECASE),
        re.compile(r'\b(use.?after.?free|double.?free|null.?pointer.?dereference)\b', re.IGNORECASE),
        re.compile(r'\b(segmentation fault|segfault|memory violation)\b', re.IGNORECASE),
        re.compile(r'\b(bounds check|boundary check|array bounds)\b', re.IGNORECASE),
        re.compile(r'\b(integer overflow|integer underflow|integer conversion)\b', re.IGNORECASE),
        re.compile(r'\barbitrary.?(memory read|pointer dereference|memory address|memory pointer)\b', re.IGNORECASE),
    ]

    _REGEX_INJECTION: List[Pattern] = [
        re.compile(r'\b(regex|regular expression)\s+injection\b', re.IGNORECASE),
        re.compile(r'\b(regex|regular expression)\s+denial of service\b', re.IGNORECASE),
        re.compile(r'\b(regex|regular expression)\s+flooding\b', re.IGNORECASE),
    ]
    
    _SSRF_PATTERNS: List[Pattern] = [
        re.compile(r'\b(ssrf|server\s+.?side\s+.?request\s+.?forgery)\b', re.IGNORECASE),
    ]
    
    @classmethod
    def get_exclusion_reason(cls, finding: Dict[str, Any]) -> Optional[str]:
        """Check if a finding should be excluded based on hard rules.
        
        Args:
            finding: Security finding to check
            
        Returns:
            Exclusion reason if finding should be excluded, None otherwise
        """
        # Check if finding is in a Markdown file
        file_path = finding.get('file', '')
        if file_path.lower().endswith('.md'):
            return "Finding in Markdown documentation file"
        
        description = finding.get('description', '')
        title = finding.get('title', '')
        
        # Handle None values
        if description is None:
            description = ''
        if title is None:
            title = ''
            
        combined_text = f"{title} {description}".lower()
        
        # Check DOS patterns
        for pattern in cls._DOS_PATTERNS:
            if pattern.search(combined_text):
                return "Generic DOS/resource exhaustion finding (low signal)"
        
        
        # Check rate limiting patterns  
        for pattern in cls._RATE_LIMITING_PATTERNS:
            if pattern.search(combined_text):
                return "Generic rate limiting recommendation"
        
        # Check resource patterns - always exclude
        for pattern in cls._RESOURCE_PATTERNS:
            if pattern.search(combined_text):
                return "Resource management finding (not a security vulnerability)"
        
        # Check open redirect patterns
        for pattern in cls._OPEN_REDIRECT_PATTERNS:
            if pattern.search(combined_text):
                return "Open redirect vulnerability (not high impact)"
            
        # Check regex injection patterns
        for pattern in cls._REGEX_INJECTION:
            if pattern.search(combined_text):
                return "Regex injection finding (not applicable)"
        
        # Check memory safety patterns - exclude if NOT in C/C++ files
        c_cpp_extensions = {'.c', '.cc', '.cpp', '.h'}
        file_ext = ''
        if '.' in file_path:
            file_ext = f".{file_path.lower().split('.')[-1]}"
        
        # If file doesn't have a C/C++ extension (including no extension), exclude memory safety findings
        if file_ext not in c_cpp_extensions:
            for pattern in cls._MEMORY_SAFETY_PATTERNS:
                if pattern.search(combined_text):
                    return "Memory safety finding in non-C/C++ code (not applicable)"
        
        # Check SSRF patterns - exclude if in HTML files only
        html_extensions = {'.html'}
        
        # If file has HTML extension, exclude SSRF findings
        if file_ext in html_extensions:
            for pattern in cls._SSRF_PATTERNS:
                if pattern.search(combined_text):
                    return "SSRF finding in HTML file (not applicable to client-side code)"
        
        return None


class FindingAnalyzer:
    """分析安全发现集合的类，使用OpenCodeSessionManager进行大模型调用"""
    
    def __init__(self, 
                 session_manager: Any,
                 output_manager: Optional[UnifiedOutputManager] = None):
        """初始化分析器
        
        Args:
            session_manager: OpenCode会话管理器
            output_manager: 统一输出管理器（未提供则不保存中间产物）
        """
        self.session_manager = session_manager

        self.output_manager = output_manager if output_manager is not None else NoOpOutputManager()
        self.filtering_session_dir = self.output_manager.get_session_dir()
        
        logger.info(f"分析器初始化成功，会话目录：{self.filtering_session_dir}")
    
    
    def _generate_system_prompt(self) -> str:
        """生成系统提示词"""
        return """你是一名资深代码安全审计专家，正在复核自动化安全审计发现。
你的任务是对每条发现做“真实性判定 + 风险强度评估”，并给出是否保留。

硬性要求：
1. 必须逐条评估所有 finding_index，不得遗漏。
2. 必须区分两类分数：
   - confidence_score(1-10): 你对结论正确性的把握度（证据充分性）。
   - risk_score(1-10): 该问题若成立时的风险强度（影响与可利用性）。
3. 必须输出 keep_finding（true/false）。
4. 必须严格按照用户提示中指定的格式返回有效JSON。
5. 不要包含解释文本、Markdown格式或代码块。"""

    @staticmethod
    def _is_embedded_context_mode(session_manager: Any) -> bool:
        return str(getattr(session_manager, "backend", "opencode")) == "openai_compatible"

    @staticmethod
    def _read_context_window(repo_dir: Path, file_path: str, line_no: int, window: int = 60) -> str:
        abs_path = (repo_dir / file_path.lstrip("./")).resolve()
        try:
            abs_path.relative_to(repo_dir.resolve())
        except Exception:
            return ""
        if not abs_path.exists() or not abs_path.is_file():
            return ""

        try:
            lines = abs_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            return ""

        if not lines:
            return ""

        center = max(1, int(line_no or 1))
        start = max(1, center - window)
        end = min(len(lines), center + window)

        numbered = []
        for idx in range(start, end + 1):
            numbered.append(f"{idx}: {lines[idx - 1]}")
        return "\n".join(numbered)

    def _build_findings_code_context(self, findings: List[Dict[str, Any]], pr_context: Optional[Dict[str, Any]]) -> str:
        repo_path = ""
        if isinstance(pr_context, dict):
            repo_path = str(pr_context.get("repo_path", "")).strip()
        if not repo_path:
            repo_path = REPO_PATH
        if not repo_path:
            return ""

        repo_dir = Path(repo_path).expanduser()
        if not repo_dir.exists() or not repo_dir.is_dir():
            return ""

        blocks = []
        total_chars = 0
        total_tokens = 0
        max_total_chars = 60000
        max_total_tokens = max(1024, int(PROMPT_TOKEN_LIMIT * 0.35))
        max_items = 30

        for index, finding in enumerate(findings):
            if index >= max_items or total_chars >= max_total_chars or total_tokens >= max_total_tokens:
                break
            file_path = str(finding.get("file", "")).strip()
            line_no = finding.get("line", 0)
            if not file_path:
                continue
            snippet = self._read_context_window(repo_dir, file_path, int(line_no or 0), window=50)
            if not snippet:
                continue

            block = (
                f"### Finding Index {index}\n"
                f"file: {file_path}\n"
                f"line: {line_no}\n"
                f"```text\n{snippet}\n```"
            )
            if total_chars + len(block) > max_total_chars:
                break
            block_tokens = count_tokens(block, getattr(self.session_manager, "model", None))
            if total_tokens + block_tokens > max_total_tokens:
                break
            blocks.append(block)
            total_chars += len(block)
            total_tokens += block_tokens

        context = "\n\n".join(blocks)
        return truncate_to_token_limit(context, max_total_tokens, getattr(self.session_manager, "model", None))
    
    def analyze_findings_batch(self,
                               findings: List[Dict[str, Any]],
                               pr_context: Optional[Dict[str, Any]] = None,
                               custom_filtering_instructions: Optional[str] = None) -> Tuple[bool, Dict[str, Any], str]:
        """批量分析安全发现，返回逐条过滤决策。"""
        if not findings:
            return True, {"finding_decisions": [], "analysis_summary": {"total_input_findings": 0}}, ""

        call_id = f"filter_findings_{len(findings)}"

        try:
            execution_mode = "embedded_context" if self._is_embedded_context_mode(self.session_manager) else "tool_call"
            code_context = self._build_findings_code_context(findings, pr_context) if execution_mode == "embedded_context" else None
            prompt = self._generate_batch_findings_prompt(
                findings,
                pr_context,
                custom_filtering_instructions,
                code_context=code_context,
                execution_mode=execution_mode,
            )
            system_prompt = self._generate_system_prompt()
            self.output_manager.save_text(
                f"{call_id}_prompt.txt",
                f"系统提示词:\n{system_prompt}\n\n用户提示词:\n{prompt}"
            )

            response_data = self.session_manager.send_message(prompt, system_prompt)
            response_text = ""
            if isinstance(response_data, dict) and 'parts' in response_data:
                for part in response_data['parts']:
                    if part.get('type') == 'text':
                        response_text += part.get('text', '')

            if not response_text:
                return False, {}, "响应文本为空"

            success, analysis_result = parse_json_with_fallbacks(response_text, "OpenCode批量过滤响应")
            if not success or not isinstance(analysis_result, dict):
                self.output_manager.save_json(
                    f"{call_id}_parse_error.json",
                    {
                        "analysis_id": call_id,
                        "error": "无法解析JSON响应",
                        "raw_response": response_text,
                        "input_findings_count": len(findings)
                    }
                )
                return False, {}, "无法解析JSON响应"

            self.output_manager.save_json(
                f"{call_id}_result.json",
                {
                    **analysis_result,
                    "analysis_id": call_id,
                    "input_findings_count": len(findings),
                    "analysis_timestamp": datetime.now().isoformat(),
                    "pr_context": pr_context,
                    "custom_filtering_instructions": custom_filtering_instructions,
                }
            )
            return True, analysis_result, ""

        except Exception as e:
            logger.exception(f"批量安全发现分析过程中出错：{str(e)}")
            self.output_manager.save_json(
                f"{call_id}_error.json",
                {
                    "analysis_id": call_id,
                    "error": str(e),
                    "exception_type": type(e).__name__,
                    "input_findings_count": len(findings),
                    "pr_context": pr_context,
                }
            )
            return False, {}, str(e)

    def _generate_batch_findings_prompt(self,
                                        findings: List[Dict[str, Any]],
                                        pr_context: Optional[Dict[str, Any]] = None,
                                        custom_filtering_instructions: Optional[str] = None,
                                        code_context: Optional[str] = None,
                                        execution_mode: str = "tool_call") -> str:
        """生成用于批量分析安全发现的提示词。"""
        pr_info = ""
        if pr_context and isinstance(pr_context, dict):
            pr_info = f"""
PR上下文:
- 仓库: {pr_context.get('repo_name', 'unknown')}
- PR #{pr_context.get('pr_number', 'unknown')}
- 标题: {pr_context.get('title', 'unknown')}
- 描述: {(pr_context.get('description') or '无描述')[:500]}...
"""

        indexed_findings = [
            {
                "finding_index": index,
                "file": finding.get("file", ""),
                "line": finding.get("line", 0),
                "severity": finding.get("severity", ""),
                "category": finding.get("category", finding.get("defect_type", "")),
                "description": finding.get("description", ""),
                "title": finding.get("title", ""),
                "module_name": finding.get("module_name", ""),
                "exploit_scenario": finding.get("exploit_scenario", ""),
                "recommendation": finding.get("recommendation", ""),
            }
            for index, finding in enumerate(findings)
        ]
        findings_json = json.dumps(indexed_findings, ensure_ascii=False, indent=2)

        if custom_filtering_instructions:
            filtering_section = custom_filtering_instructions
        else:
            filtering_section = """ 排除检测出来的测试部分等和生产业务不相关的缺陷 """

        capability_section = ""
        if execution_mode == "embedded_context":
            capability_section = f"""
执行模式：embedded_context（裸模型）
- 你不具备自主读取仓库文件的能力。
- 你必须仅基于下方“代码上下文片段”做真实性与风险评估。
- 若证据不足，请将 keep_finding 设为 false 并在 justification 说明缺失证据。

代码上下文片段：
{code_context or "未提供代码上下文。请仅基于已给证据保守判断。"}
"""
        else:
            capability_section = """
执行模式：tool_call（OpenCode）
- 你可以根据 file/line 自行查找相关文件、上下文与调用链后再判断。
"""

        return f"""我需要你批量分析来自自动化代码审计的安全发现，并确定哪些应被过滤。

{pr_info}

输入说明：
- 每条发现都包含 file 路径和 line 信息。
- 请基于代码证据和调用链做真实性判断。

{capability_section.strip()}

排除规则：
{filtering_section}

请按以下“逐条评估方法”执行：
1) 证据定位：根据 file/line 查找代码上下文，并提取关键调用链（输入来源 -> 处理函数 -> 风险点/敏感操作）。
2) 真实性判定：判断该问题是否真实存在，而不是理论推测；判断攻击前置条件是否现实；判断现有防护是否已阻断风险。
3) 风险分析：若问题真实存在，评估实际影响范围与可利用性，给出 risk_score（1-10）。
4) 置信度分析：根据证据完整度给出 confidence_score（1-10）。调用链闭合、可达性清晰、证据充分时置信度应更高。
5) 最终决策：
   - keep_finding=true：问题真实存在且具有实际安全意义；
   - keep_finding=false：误报、不可达、仅理论风险、或缺乏关键证据。

评分标准：
- confidence_score（结论把握度）
  - 1-3：证据薄弱，结论不可靠
  - 4-6：有一定证据，但仍需复核
  - 7-10：证据充分，结论可靠
- risk_score（风险强度）
  - 1-3：低风险/影响很小
  - 4-6：中等风险
  - 7-10：高风险/可造成显著安全影响

要分析的安全发现列表：
```json
{findings_json}
```

必须严格按照以下JSON结构回答（不要使用Markdown，不要使用代码块）：
{{
  "finding_decisions": [
    {{
      "finding_index": 0,
      "keep_finding": true,
      "confidence_score": 8,
      "risk_score": 7,
      "exclusion_reason": null,
      "justification": "清晰的SQL注入漏洞，具有具体利用路径",
      "checked_paths": ["src/auth/service.py", "src/auth/routes.py"],
      "call_chain_summary": ["/refresh -> validate_refresh_token -> issue_token"]
    }}
  ],
  "analysis_summary": {{
    "total_input_findings": 0,
    "decisions_returned": 0,
    "filtered_count": 0,
    "kept_count": 0
  }}
}}"""


class FindingsFilter:
    """Main filter class for security findings."""
    
    def __init__(self, 
                 use_hard_exclusions: bool = True,
                 use_ai_filtering: bool = True,
                 model: str = DEFAULT_MODEL_ID,
                 custom_filtering_instructions: Optional[str] = None,
                 provider_id: str = DEFAULT_PROVIDER_ID,
                 host: Optional[str] = None,
                 timeout_seconds: Optional[int] = None,
                 output_manager: Optional[UnifiedOutputManager] = None,
                 external_session_manager: Optional[Any] = None):
        """Initialize findings filter.
        
        Args:
            use_hard_exclusions: Whether to apply hard exclusion rules
            use_ai_filtering: Whether to use AI filtering
            model: Model ID to use for filtering
            custom_filtering_instructions: Optional custom filtering instructions
            provider_id: Provider ID for OpenCode
            host: OpenCode server address
            timeout_seconds: Timeout for API calls
            output_manager: Unified output manager (if None, artifacts are not saved)
            external_session_manager: External session manager to reuse (if provided, 
                                     the filter will use this session instead of creating a new one)
        """
        self.use_hard_exclusions = use_hard_exclusions
        self.use_ai_filtering = use_ai_filtering
        self.custom_filtering_instructions = custom_filtering_instructions
        self.owns_session = False  # Whether this filter owns and should close the session
        
        # Initialize session manager and analyzer if filtering is enabled
        self.session_manager = None
        self.finding_analyzer = None
        
        if self.use_ai_filtering:
            try:
                # Use external session manager if provided, otherwise create new one
                if external_session_manager is not None:
                    self.session_manager = external_session_manager
                    self.owns_session = False
                    logger.info("使用外部传入的OpenCode Session Manager")
                else:
                    # Create new session manager
                    self.session_manager = get_session_manager(
                        host=host,
                        model=model,
                        provider_id=provider_id,
                        timeout_seconds=timeout_seconds,
                    )
                    
                    # Create session if not exists
                    if self.session_manager.session_id is None:
                        self.session_manager.create_session()
                    
                    self.owns_session = True
                    logger.info("创建新的OpenCode Session Manager")
                
                # Initialize finding analyzer
                self.finding_analyzer = FindingAnalyzer(
                    session_manager=self.session_manager,
                    output_manager=output_manager
                )
                
                logger.info("OpenCode Session Manager初始化成功")
                
            except Exception as e:
                logger.error(f"Failed to initialize Session Manager: {str(e)}")
                self.session_manager = None
                self.finding_analyzer = None
                self.owns_session = False
                self.use_ai_filtering = False
    
    def close(self):
        """Close the session if this filter owns it."""
        if self.owns_session and self.session_manager:
            try:
                self.session_manager.close_session()
                logger.info("已关闭FindingsFilter创建的session")
            except Exception as e:
                logger.warning(f"关闭会话时出错: {str(e)}")
    
    def __del__(self):
        """析构函数，确保会话被正确关闭"""
        self.close()
    
    def __enter__(self):
        """Context manager entry point."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit point."""
        self.close()
        return False
    
    def filter_findings(self, 
                       findings: List[Dict[str, Any]],
                       pr_context: Optional[Dict[str, Any]] = None) -> Tuple[bool, Dict[str, Any], FilterStats]:
        """Filter security findings to remove false positives.
        
        Args:
            findings: List of security findings from automated audit
            pr_context: Optional PR context for better analysis
            
        Returns:
            Tuple of (success, filtered_results, stats)
        """
        start_time = time.time()
        
        if not findings:
            stats = FilterStats(total_findings=0, runtime_seconds=0.0)
            return True, {
                "filtered_findings": [],
                "excluded_findings": [],
                "analysis_summary": {
                    "total_findings": 0,
                    "kept_findings": 0,
                    "excluded_findings": 0,
                    "exclusion_breakdown": {}
                }
            }, stats
        
        logger.info(f"Filtering {len(findings)} security findings")
        
        # Initialize statistics
        stats = FilterStats(total_findings=len(findings))
        
        # Step 1: Apply hard exclusion rules
        findings_after_hard = []
        excluded_hard = []
        
        if self.use_hard_exclusions:
            for i, finding in enumerate(findings):
                exclusion_reason = HardExclusionRules.get_exclusion_reason(finding)
                if exclusion_reason:
                    excluded_hard.append({
                        "finding": finding,
                        "index": i,
                        "exclusion_reason": exclusion_reason,
                        "filter_stage": "hard_rules"
                    })
                    stats.hard_excluded += 1
                    
                    # Track exclusion breakdown
                    key = exclusion_reason.split('(')[0].strip()
                    stats.exclusion_breakdown[key] = stats.exclusion_breakdown.get(key, 0) + 1
                else:
                    findings_after_hard.append((i, finding))
            
            logger.info(f"Hard exclusions removed {stats.hard_excluded} findings")
        else:
            findings_after_hard = [(i, f) for i, f in enumerate(findings)]
        
        # Step 2: Apply AI filtering if enabled
        findings_after_ai = []
        excluded_ai = []
                
        if self.use_ai_filtering and self.finding_analyzer and findings_after_hard:
            logger.info(f"Batch processing {len(findings_after_hard)} findings through OpenCode Session Manager")

            candidate_findings = [finding for _, finding in findings_after_hard]
            success, analysis_result, error_msg = self.finding_analyzer.analyze_findings_batch(
                candidate_findings,
                pr_context,
                self.custom_filtering_instructions,
            )

            if success and isinstance(analysis_result, dict):
                decisions = analysis_result.get('finding_decisions', [])
                decision_map: Dict[int, Dict[str, Any]] = {}
                if isinstance(decisions, list):
                    for decision in decisions:
                        if not isinstance(decision, dict):
                            continue
                        index = decision.get('finding_index')
                        if isinstance(index, int):
                            decision_map[index] = decision

                for local_index, (_, finding) in enumerate(findings_after_hard):
                    decision = decision_map.get(local_index)
                    if decision is None:
                        enriched_finding = finding.copy()
                        enriched_finding['_filter_metadata'] = {
                            'confidence_score': 10.0,
                            'justification': 'Batch decision missing; keeping finding by fail-open strategy',
                        }
                        findings_after_ai.append(enriched_finding)
                        stats.kept_findings += 1
                        continue

                    confidence_raw = decision.get('confidence_score', 10.0)
                    try:
                        confidence = float(confidence_raw)
                    except (TypeError, ValueError):
                        confidence = 10.0

                    risk_raw = decision.get('risk_score', confidence)
                    try:
                        risk_score = float(risk_raw)
                    except (TypeError, ValueError):
                        risk_score = confidence

                    keep_finding = bool(decision.get('keep_finding', True))
                    justification = decision.get('justification', '')
                    exclusion_reason = decision.get('exclusion_reason')
                    checked_paths = decision.get('checked_paths', [])
                    call_chain_summary = decision.get('call_chain_summary', [])

                    stats.confidence_scores.append(confidence)

                    if not keep_finding:
                        excluded_ai.append({
                            "finding": finding,
                            "confidence_score": confidence,
                            "risk_score": risk_score,
                            "exclusion_reason": exclusion_reason or f"Low confidence score: {confidence}",
                            "justification": justification,
                            "checked_paths": checked_paths,
                            "call_chain_summary": call_chain_summary,
                            "filter_stage": "opencode_session_batch"
                        })
                        stats.ai_excluded += 1
                    else:
                        enriched_finding = finding.copy()
                        enriched_finding['_filter_metadata'] = {
                            'confidence_score': confidence,
                            'risk_score': risk_score,
                            'justification': justification,
                            'checked_paths': checked_paths,
                            'call_chain_summary': call_chain_summary,
                        }
                        findings_after_ai.append(enriched_finding)
                        stats.kept_findings += 1
            else:
                logger.warning(f"Batch finding analyzer call failed: {error_msg}")
                for _, finding in findings_after_hard:
                    enriched_finding = finding.copy()
                    enriched_finding['_filter_metadata'] = {
                        'confidence_score': 10.0,
                        'justification': f'OpenCode batch analysis failed: {error_msg}',
                    }
                    findings_after_ai.append(enriched_finding)
                    stats.kept_findings += 1
        else:
            # Filtering disabled or no analyzer - keep all findings from hard filter
            for orig_idx, finding in findings_after_hard:
                enriched_finding = finding.copy()
                enriched_finding['_filter_metadata'] = {
                    'confidence_score': 10.0,  # Default high confidence
                    'justification': 'OpenCode filtering disabled',
                }
                findings_after_ai.append(enriched_finding)
                stats.kept_findings += 1
        
        # Combine all excluded findings
        all_excluded = excluded_hard + excluded_ai
        
        # Calculate final statistics
        stats.runtime_seconds = time.time() - start_time
        
        # Build filtered results
        filtered_results = {
            "filtered_findings": findings_after_ai,
            "excluded_findings": all_excluded,
            "analysis_summary": {
                "total_findings": stats.total_findings,
                "kept_findings": stats.kept_findings,
                "excluded_findings": len(all_excluded),
                "hard_excluded": stats.hard_excluded,
                "ai_excluded": stats.ai_excluded,
                "exclusion_breakdown": stats.exclusion_breakdown,
                "average_confidence": sum(stats.confidence_scores) / len(stats.confidence_scores) if stats.confidence_scores else None,
                "runtime_seconds": stats.runtime_seconds
            }
        }
        
        logger.info(f"Filtering completed: {stats.kept_findings}/{stats.total_findings} findings kept "
                    f"({stats.runtime_seconds:.1f}s)")
        
        return True, filtered_results, stats
    
