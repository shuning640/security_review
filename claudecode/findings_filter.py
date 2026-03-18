"""Findings filter for reducing false positives in security audit results."""

import re
from typing import Dict, Any, List, Tuple, Optional, Pattern
import time
from dataclasses import dataclass, field
import json
from pathlib import Path
import os
from datetime import datetime
import sys

from claudecode.unified_output_manager import UnifiedOutputManager
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# from claudecode.claude_api_client import ClaudeAPIClient
from claudecode.session_manager import OpenCodeSessionManager
from claudecode.constants import DEFAULT_CLAUDE_MODEL, DEFAULT_CLAUDE_PROVIDER
from claudecode.logger import get_logger
from claudecode.json_parser import parse_json_with_fallbacks

logger = get_logger(__name__)


@dataclass
class FilterStats:
    """Statistics about the filtering process."""
    total_findings: int = 0
    hard_excluded: int = 0
    claude_excluded: int = 0
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
                 session_manager: OpenCodeSessionManager,
                 output_dir: Optional[Path] = None):
        """初始化分析器
        
        Args:
            session_manager: OpenCode会话管理器
            output_dir: 中间产物输出目录
        """
        self.session_manager = session_manager
        
        # 使用统一的输出管理器
        self.output_manager = UnifiedOutputManager(
            session_id=session_manager.session_id,
            base_output_dir=output_dir
        )
        self.filtering_session_dir = self.output_manager.get_session_dir()
        
        logger.info(f"分析器初始化成功，会话目录：{self.filtering_session_dir}")
    
    def analyze_single_finding(self, 
                               finding: Dict[str, Any], 
                               pr_context: Optional[Dict[str, Any]] = None,
                               custom_filtering_instructions: Optional[str] = None) -> Tuple[bool, Dict[str, Any], str]:
        """使用OpenCodeSessionManager分析单个安全发现以过滤误报。
        
        Args:
            finding: 要分析的单个安全发现
            pr_context: 可选的PR上下文以获得更好的分析
            custom_filtering_instructions: 可选的自定义过滤指令
            
        Returns:
            元组（成功，分析结果，错误消息）
        """
        # 兼容旧接口：单条分析统一走批量过滤实现，避免双实现分叉。
        success, batch_result, error_msg = self.analyze_findings_batch(
            findings=[finding],
            pr_context=pr_context,
            custom_filtering_instructions=custom_filtering_instructions,
        )

        if not success or not isinstance(batch_result, dict):
            return False, {}, error_msg

        decisions = batch_result.get("finding_decisions", [])
        if isinstance(decisions, list) and decisions:
            first = decisions[0]
            if isinstance(first, dict):
                return True, first, ""

        return False, {}, "批量过滤未返回单条决策"

        try:
            logger.info("\\n" + "=" * 60)
            logger.info("开始分析单个安全发现")
            logger.info("=" * 60)
            
            # 生成唯一的分析ID
            finding_id = f"finding_{finding.get('file', 'unknown').replace('/', '_')}_{finding.get('line', 0)}"
            timestamp = datetime.now().strftime("%H%M%S")
            call_id = f"{finding_id}_{timestamp}"
            
            logger.info(f"分析ID: {call_id}")
            logger.info(f"文件: {finding.get('file', 'unknown')}:{finding.get('line', 0)}")
            logger.info(f"类别: {finding.get('category', 'unknown')}")
            
            # 生成包含文件内容的分析提示词
            prompt = self._generate_single_finding_prompt(finding, pr_context, custom_filtering_instructions)
            system_prompt = self._generate_system_prompt()
            
            logger.info(f"提示词长度: {len(prompt)} 字符")
            
            # 保存提示词到文件
            prompt_file = self.output_manager.save_text(f"{call_id}_prompt.txt", 
                f"系统提示词:\n{system_prompt}\n\n用户提示词:\n{prompt}")
            logger.info(f"API调用提示词已保存到: {prompt_file}")
            
            # 使用OpenCodeSessionManager进行大模型调用
            try:
                response_data = self.session_manager.send_message(prompt, system_prompt)
                
                # 提取响应文本
                response_text = ""
                if 'parts' in response_data:
                    for part in response_data['parts']:
                        if part.get('type') == 'text':
                            response_text += part.get('text', '')
                
                # 保存原始响应到文件
                response_data_to_save = {
                    "final_response_text": response_text,
                    "raw_response": response_data
                }
                response_file = self.output_manager.save_json(f"{call_id}_response.json", response_data_to_save)
                logger.info(f"API原始响应已保存到: {response_file}")
                
                if not response_text:
                    logger.warning(f"响应文本为空")
                    return False, {}, "响应文本为空"
                
                logger.info(f"API响应长度: {len(response_text)} 字符")
                
                # 使用json_parser解析JSON响应
                success, analysis_result = parse_json_with_fallbacks(response_text, "OpenCode响应")
                if success:
                    logger.info("成功解析单个安全发现的OpenCode响应")
                    
                    # 保存最终解析结果
                    result_file = self.filtering_session_dir / f"{call_id}_result.json"
                    final_result = analysis_result.copy()
                    final_result.update({
                        "analysis_id": call_id,
                        "original_finding": finding,
                        "pr_context": pr_context,
                        "analysis_timestamp": datetime.now().isoformat(),
                        "custom_filtering_instructions": custom_filtering_instructions
                    })
                    
                    with open(result_file, 'w', encoding='utf-8') as f:
                        json.dump(final_result, f, ensure_ascii=False, indent=2)
                    
                    logger.info(f"最终分析结果已保存到: {result_file}")
                    logger.info(f"置信度评分: {analysis_result.get('confidence_score', 'N/A')}")
                    logger.info(f"是否保留发现: {analysis_result.get('keep_finding', 'N/A')}")
                    
                    return True, analysis_result, ""
                else:
                    # 后备：返回错误
                    logger.error("无法解析JSON响应")
                    
                    # 保存解析失败信息
                    parse_error_file = self.filtering_session_dir / f"{call_id}_parse_error.json"
                    parse_error_data = {
                        "analysis_id": call_id,
                        "error": "无法解析JSON响应",
                        "raw_response": response_text,
                        "original_finding": finding
                    }
                    
                    with open(parse_error_file, 'w', encoding='utf-8') as f:
                        json.dump(parse_error_data, f, ensure_ascii=False, indent=2)
                    
                    logger.info(f"解析错误信息已保存到: {parse_error_file}")
                    return False, {}, "无法解析JSON响应"
                    
            except Exception as e:
                logger.error(f"OpenCode调用失败: {str(e)}")
                
                # 保存错误信息
                error_file = self.filtering_session_dir / f"{call_id}_error.json"
                error_data = {
                    "analysis_id": call_id,
                    "error": str(e),
                    "exception_type": type(e).__name__,
                    "original_finding": finding,
                    "pr_context": pr_context
                }
                
                with open(error_file, 'w', encoding='utf-8') as f:
                    json.dump(error_data, f, ensure_ascii=False, indent=2)
                
                logger.info(f"错误信息已保存到: {error_file}")
                return False, {}, str(e)
                
        except Exception as e:
            logger.exception(f"单个安全发现分析过程中出错：{str(e)}")
            
            # 保存异常信息
            exception_file = self.filtering_session_dir / f"{call_id}_exception.json"
            exception_data = {
                "analysis_id": call_id,
                "error": str(e),
                "exception_type": type(e).__name__,
                "original_finding": finding,
                "pr_context": pr_context
            }
            
            with open(exception_file, 'w', encoding='utf-8') as f:
                json.dump(exception_data, f, ensure_ascii=False, indent=2)
            
            logger.info(f"异常信息已保存到: {exception_file}")
            return False, {}, f"单个安全发现分析失败：{str(e)}"
    
    def _generate_system_prompt(self) -> str:
        """生成系统提示词"""
        return """你是一名安全专家，正在审查来自自动化代码审计工具的发现。
你的任务是过滤掉误报和低信号发现，以减少警报疲劳。
你必须在提高精度的同时保持高召回率（不要漏掉真正的漏洞）。

必须严格按照用户提示中指定的格式返回有效的JSON。
不要包含解释文本、Markdown格式或代码块。"""
    
    def _generate_single_finding_prompt(self, 
                                       finding: Dict[str, Any], 
                                       pr_context: Optional[Dict[str, Any]] = None,
                                       custom_filtering_instructions: Optional[str] = None) -> str:
        """生成用于分析单个安全发现的提示词。
        
        Args:
            finding: 单个安全发现
            pr_context: 可选的PR上下文
            
        Returns:
            格式化的提示词字符串
        """
        pr_info = ""
        if pr_context and isinstance(pr_context, dict):
            pr_info = f"""
PR上下文:
- 仓库: {pr_context.get('repo_name', 'unknown')}
- PR #{pr_context.get('pr_number', 'unknown')}
- 标题: {pr_context.get('title', 'unknown')}
- 描述: {(pr_context.get('description') or '无描述')[:500]}...
"""
        
        file_content = ""
        
        finding_json = json.dumps(finding, indent=2)
        
        # Use custom filtering instructions if provided, otherwise use defaults
        if custom_filtering_instructions:
            filtering_section = custom_filtering_instructions
        else:
            filtering_section = """硬性排除规则 - 自动排除匹配以下模式的发现：
1. 拒绝服务漏洞或资源耗尽攻击
2. 存储在磁盘上的密钥/凭据（这些由单独流程管理）
3. 速率限制问题或服务过载场景（服务不需要实现速率限制）
4. 内存消耗或CPU耗尽问题
5. 缺乏输入验证但没有已证明安全影响的非安全关键字段
6. GitHub Action工作流中的输入清理问题
7. 缺少安全强化措施。代码不需要实现所有的安全最佳实践，只要避免明显的漏洞即可。
8. 理论上而非实际问题的竞态条件或计时攻击。只有在竞态条件极其严重时才报告。
9. 与过时第三方库相关的漏洞。这些由单独管理，不应在此报告。
10. 缓冲区溢出或释放后使用等内存安全问题在Rust中是不可能存在的。不要报告Rust代码中的内存安全问题。
11. 仅作为单元测试或仅在测试运行中使用的文件。
12. 日志欺骗问题。将未经清理的用户输入输出到日志不是漏洞。
13. 仅控制路径的SSRF漏洞。只有当SSRF能够控制主机或协议时才是问题。
14. 在AI系统提示中包含用户控制的内容不是漏洞。通常，在AI提示中包含用户输入不是漏洞。
15. 不要报告与向项目添加不可从相关包仓库获得的依赖相关的问题。依赖不可公开访问的内部库不是漏洞。
16. 不要报告导致代码崩溃但实际上不是漏洞的问题。例如，未定义或null的变量不是漏洞。
  
信号质量标准 - 对于剩余的发现，评估：
1. 是否存在具体的、可利用的漏洞和清晰的攻击路径？
2. 这代表真正的安全风险还是理论最佳实践？
3. 是否有具体的代码位置和重现步骤？
4. 这个发现对安全团队来说是否可操作？
  
先例标准 - 
1. 以明文形式记录高价值密钥是漏洞。否则，不要报告密钥理论暴露的问题。记录URL被认为是安全的。记录请求头被认为是危险的，因为它们可能包含凭据。
2. UUID可以假设为不可猜测，不需要验证。如果漏洞需要猜测UUID，则不是有效的漏洞。
3. 审计日志不是关键安全功能，如果它们缺失或修改，不应报告为漏洞。
4. 环境变量和CLI标志是可信值。攻击者无法在安全环境中修改它们。任何依赖于控制环境变量的攻击都是无效的。
5. 内存或文件描述符泄漏等资源管理问题不是有效的。
6. 细微或低影响的Web漏洞，如标签劫持、XS-Leaks、原型污染和开放重定向，不是有效的。
7. 与过时第三方库相关的漏洞。这些由单独管理，不应在此报告。
8. React通常对XSS安全。React不需要清理或转义用户输入，除非它使用dangerouslySetInnerHTML或类似方法。不要报告React组件或tsx文件中的XSS漏洞，除非它们使用不安全的方法。
9. 大多数GitHub Action工作流中的漏洞在实践中不可利用。在验证GitHub Action工作流漏洞之前，确保它是具体的且有非常具体的攻击路径。
10. 客户端TS代码中缺少权限检查或身份验证不是漏洞。客户端代码不受信任，不需要实现这些检查，它们在服务器端处理。这同样适用于所有将不受信任数据发送到后端的流程，后端负责验证和清理所有输入。
11. 只有当中等严重性发现是明显和具体的问题时才包含。
12. 大多数IPython笔记本(*.ipynb文件)中的漏洞在实践中不可利用。在验证笔记本漏洞之前，确保它是具体的且有非常具体的攻击路径。
13. 记录非PII数据不是漏洞，即使数据可能是敏感的。只有当日志漏洞暴露敏感信息（如密钥、密码或个人身份信息(PII)）时才报告。
14. Shell脚本中的命令注入漏洞在实践中通常不可利用，因为Shell脚本通常不会使用不受信任的用户输入运行。只有当Shell脚本中的命令注入漏洞对不受信任的输入有具体且有非常具体的攻击路径时才报告。
15. 客户端JavaScript/TypeScript文件（.js, .ts, .tsx, .jsx）中的SSRF（服务器端请求伪造）漏洞是无效的，因为客户端代码无法做出会绕过防火墙或访问内部资源的服务器端请求。只在服务器端代码中报告SSRF（例如，已知在服务器端运行的Python或JS）。相同逻辑适用于路径遍历攻击，它们在客户端JS中不是问题。
16. 使用../的路径遍历攻击在触发HTTP请求时通常不是问题。这些通常只在读取文件时相关，其中../可能允许访问意外文件。
17. 注入到日志查询中通常不是问题。只有当注入明确导致向外部用户暴露敏感数据时才报告。"""
        
        return f"""我需要你分析来自自动化代码审计的一个安全发现，并确定它是否为误报。
  
{pr_info}
  
{filtering_section}
  
分配1-10的置信度评分：
- 1-3：低置信度，可能是误报或噪音
- 4-6：中等置信度，需要进一步调查  
- 7-10：高置信度，可能是真正的漏洞
  
要分析的安全发现：
```json
{finding_json}
```
{file_content}
  
必须严格按照以下JSON结构回答（不要使用Markdown，不要使用代码块）：
{{
  "original_severity": "高",
  "confidence_score": 8,
  "keep_finding": true,
  "exclusion_reason": null,
  "justification": "清晰的SQL注入漏洞，具有具体利用路径"
}}"""
    
    def analyze_findings_batch(self,
                               findings: List[Dict[str, Any]],
                               pr_context: Optional[Dict[str, Any]] = None,
                               custom_filtering_instructions: Optional[str] = None) -> Tuple[bool, Dict[str, Any], str]:
        """批量分析安全发现，返回逐条过滤决策。"""
        if not findings:
            return True, {"finding_decisions": [], "analysis_summary": {"total_input_findings": 0}}, ""

        call_id = f"filter_findings_{len(findings)}"

        try:
            prompt = self._generate_batch_findings_prompt(findings, pr_context, custom_filtering_instructions)
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

            self.output_manager.save_json(
                f"{call_id}_response.json",
                {"final_response_text": response_text, "raw_response": response_data}
            )

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
                                        custom_filtering_instructions: Optional[str] = None) -> str:
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

        filtering_section = custom_filtering_instructions or """硬性排除规则：过滤DoS、速率限制、资源耗尽、仅理论问题、与实际运行边界无关的问题；仅保留具备明确攻击路径和可操作修复建议的发现。"""

        return f"""我需要你批量分析来自自动化代码审计的安全发现，并确定哪些应被过滤。

{pr_info}

输入说明：
- 每条发现都包含 file 路径和 line 信息。
- 你必须根据这些路径自行查找相关文件、上下文与调用链后再判断。
- 不要依赖我手工提供文件内容；请基于代码库真实上下文做决定。

{filtering_section}

分配1-10的置信度评分：
- 1-3：低置信度，可能是误报或噪音
- 4-6：中等置信度，需要进一步调查
- 7-10：高置信度，可能是真正的漏洞

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
                 use_claude_filtering: bool = True,
                 api_key: Optional[str] = None,
                 model: str = DEFAULT_CLAUDE_MODEL,
                 custom_filtering_instructions: Optional[str] = None,
                 provider_id: str = DEFAULT_CLAUDE_PROVIDER,
                 host: Optional[str] = None,
                 timeout_seconds: Optional[int] = None,
                 output_dir: Optional[Path] = None,
                 external_session_manager: Optional[OpenCodeSessionManager] = None):
        """Initialize findings filter.
        
        Args:
            use_hard_exclusions: Whether to apply hard exclusion rules
            use_claude_filtering: Whether to use Claude API for filtering
            api_key: Anthropic API key for Claude filtering (deprecated, unused)
            model: Claude model to use for filtering
            custom_filtering_instructions: Optional custom filtering instructions
            provider_id: Provider ID for OpenCode
            host: OpenCode server address
            timeout_seconds: Timeout for API calls
            output_dir: Output directory for intermediate artifacts
            external_session_manager: External session manager to reuse (if provided, 
                                     the filter will use this session instead of creating a new one)
        """
        del api_key

        self.use_hard_exclusions = use_hard_exclusions
        self.use_claude_filtering = use_claude_filtering
        self.custom_filtering_instructions = custom_filtering_instructions
        self.owns_session = False  # Whether this filter owns and should close the session
        
        # Initialize session manager and analyzer if filtering is enabled
        self.session_manager = None
        self.finding_analyzer = None
        
        if self.use_claude_filtering:
            try:
                # Use external session manager if provided, otherwise create new one
                if external_session_manager is not None:
                    self.session_manager = external_session_manager
                    self.owns_session = False
                    logger.info("使用外部传入的OpenCode Session Manager")
                else:
                    # Create new session manager
                    self.session_manager = OpenCodeSessionManager(
                        host=host,
                        model=model,
                        provider_id=provider_id,
                        timeout_seconds=timeout_seconds
                    )
                    
                    # Create session if not exists
                    if self.session_manager.session_id is None:
                        self.session_manager.create_session()
                    
                    self.owns_session = True
                    logger.info("创建新的OpenCode Session Manager")
                
                # Initialize finding analyzer
                self.finding_analyzer = FindingAnalyzer(
                    session_manager=self.session_manager,
                    output_dir=output_dir
                )
                
                logger.info("OpenCode Session Manager初始化成功")
                
            except Exception as e:
                logger.error(f"Failed to initialize Session Manager: {str(e)}")
                self.session_manager = None
                self.finding_analyzer = None
                self.owns_session = False
                self.use_claude_filtering = False
    
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
            findings: List of security findings from Claude Code audit
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
        
        # Step 2: Apply Claude API filtering if enabled
        findings_after_claude = []
        excluded_claude = []
                
        if self.use_claude_filtering and self.finding_analyzer and findings_after_hard:
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
                        findings_after_claude.append(enriched_finding)
                        stats.kept_findings += 1
                        continue

                    confidence_raw = decision.get('confidence_score', 10.0)
                    try:
                        confidence = float(confidence_raw)
                    except (TypeError, ValueError):
                        confidence = 10.0

                    keep_finding = bool(decision.get('keep_finding', True))
                    justification = decision.get('justification', '')
                    exclusion_reason = decision.get('exclusion_reason')
                    checked_paths = decision.get('checked_paths', [])
                    call_chain_summary = decision.get('call_chain_summary', [])

                    stats.confidence_scores.append(confidence)

                    if not keep_finding:
                        excluded_claude.append({
                            "finding": finding,
                            "confidence_score": confidence,
                            "exclusion_reason": exclusion_reason or f"Low confidence score: {confidence}",
                            "justification": justification,
                            "checked_paths": checked_paths,
                            "call_chain_summary": call_chain_summary,
                            "filter_stage": "opencode_session_batch"
                        })
                        stats.claude_excluded += 1
                    else:
                        enriched_finding = finding.copy()
                        enriched_finding['_filter_metadata'] = {
                            'confidence_score': confidence,
                            'justification': justification,
                            'checked_paths': checked_paths,
                            'call_chain_summary': call_chain_summary,
                        }
                        findings_after_claude.append(enriched_finding)
                        stats.kept_findings += 1
            else:
                logger.warning(f"Batch finding analyzer call failed: {error_msg}")
                for _, finding in findings_after_hard:
                    enriched_finding = finding.copy()
                    enriched_finding['_filter_metadata'] = {
                        'confidence_score': 10.0,
                        'justification': f'OpenCode batch analysis failed: {error_msg}',
                    }
                    findings_after_claude.append(enriched_finding)
                    stats.kept_findings += 1
        else:
            # Filtering disabled or no analyzer - keep all findings from hard filter
            for orig_idx, finding in findings_after_hard:
                enriched_finding = finding.copy()
                enriched_finding['_filter_metadata'] = {
                    'confidence_score': 10.0,  # Default high confidence
                    'justification': 'OpenCode filtering disabled',
                }
                findings_after_claude.append(enriched_finding)
                stats.kept_findings += 1
        
        # Combine all excluded findings
        all_excluded = excluded_hard + excluded_claude
        
        # Calculate final statistics
        stats.runtime_seconds = time.time() - start_time
        
        # Build filtered results
        filtered_results = {
            "filtered_findings": findings_after_claude,
            "excluded_findings": all_excluded,
            "analysis_summary": {
                "total_findings": stats.total_findings,
                "kept_findings": stats.kept_findings,
                "excluded_findings": len(all_excluded),
                "hard_excluded": stats.hard_excluded,
                "claude_excluded": stats.claude_excluded,
                "exclusion_breakdown": stats.exclusion_breakdown,
                "average_confidence": sum(stats.confidence_scores) / len(stats.confidence_scores) if stats.confidence_scores else None,
                "runtime_seconds": stats.runtime_seconds
            }
        }
        
        logger.info(f"Filtering completed: {stats.kept_findings}/{stats.total_findings} findings kept "
                    f"({stats.runtime_seconds:.1f}s)")
        
        return True, filtered_results, stats
    
