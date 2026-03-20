"""Audit runner implementation for pipeline."""

import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from auditengine.constants import OPENCODE_SERVER_BIN, SUBPROCESS_TIMEOUT
from auditengine.json_parser import parse_json_with_fallbacks
from auditengine.logger import get_logger
from auditengine.phased_analyzer import PhasedSecurityAnalyzer
from auditengine.session_manager import OpenCodeServerRuntime, OpenCodeSessionManager
from auditengine.unified_output_manager import UnifiedOutputManager

logger = get_logger(__name__)


class SimpleAuditRunner:
    """Simplified security audit runner for CI environments."""

    def __init__(self, timeout_minutes: Optional[int] = None):
        if timeout_minutes is not None:
            self.timeout_seconds = timeout_minutes * 60
        else:
            self.timeout_seconds = SUBPROCESS_TIMEOUT

    def run_phased_security_audit_with_session(
        self,
        repo_dir: Path,
        pr_data: Dict[str, Any],
        session_manager: Optional[OpenCodeSessionManager] = None,
        output_manager: Optional[UnifiedOutputManager] = None,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        if not repo_dir.exists():
            return False, f"Repository directory does not exist: {repo_dir}", {}

        session_needs_close = False
        local_server_runtime = None
        if session_manager is None:
            try:
                local_server_runtime = OpenCodeServerRuntime(repo_path=str(repo_dir))
                local_server_runtime.start()
                session_manager = OpenCodeSessionManager(timeout_seconds=self.timeout_seconds)
                session_needs_close = True
                logger.info("为分阶段分析创建临时session")
            except Exception as e:
                error_msg = f"Failed to create session manager: {str(e)}"
                logger.error(error_msg)
                return False, error_msg, {}
        else:
            logger.info("使用外部传入的session进行分阶段分析")

        try:
            if session_manager.session_id is None:
                session_manager.create_session()
                logger.info("创建了session_id")

            phased_analyzer = PhasedSecurityAnalyzer(session_manager, output_manager=output_manager)
            try:
                analysis_results = phased_analyzer.execute_phased_analysis(
                    pr_data=pr_data,
                    repo_dir=repo_dir,
                )

                return True, "", analysis_results
            except Exception as e:
                error_msg = f"Phased analysis execution failed: {str(e)}"
                logger.error(error_msg)
                return False, error_msg, {}
        except Exception as e:
            error_msg = f"Phased security audit initialization failed: {str(e)}"
            logger.error(error_msg)
            return False, error_msg, {}
        finally:
            if session_needs_close and session_manager:
                try:
                    session_manager.close_session()
                    logger.info("已关闭临时创建的session")
                except Exception as e:
                    logger.warning(f"关闭临时session时出错: {str(e)}")
            if local_server_runtime:
                try:
                    local_server_runtime.stop()
                except Exception as e:
                    logger.warning(f"关闭临时server时出错: {str(e)}")

    def run_security_audit(self, repo_dir: Path, prompt: str) -> Tuple[bool, str, Dict[str, Any]]:
        if not repo_dir.exists():
            return False, f"Repository directory does not exist: {repo_dir}", {}

        prompt_size = len(prompt.encode("utf-8"))
        if prompt_size > 1024 * 1024:
            logger.warning(f"Large prompt size: {prompt_size / 1024 / 1024:.2f}MB")

        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False, suffix=".txt") as temp_prompt_file:
            temp_prompt_file.write(prompt)
            temp_prompt_path = temp_prompt_file.name

        try:
            cmd = [
                "opencode.cmd",
                "run",
                "Please review the attached security audit prompt.",
                "--format",
                "json",
                "-f",
                temp_prompt_path,
            ]

            num_retries = 3
            for attempt in range(num_retries):
                result = subprocess.run(
                    cmd,
                    cwd=repo_dir,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=self.timeout_seconds,
                )

                if result.returncode != 0:
                    if attempt == num_retries - 1:
                        error_details = f"Analysis runtime execution failed with return code {result.returncode}\n"
                        error_details += f"Stderr: {result.stderr}\n"
                        error_details += f"Stdout: {result.stdout[:500]}..."
                        return False, error_details, {}
                    time.sleep(5 * attempt)
                    continue

                success, parsed_result = parse_json_with_fallbacks(result.stdout, "analysis runtime output")

                if success:
                    if (
                        isinstance(parsed_result, dict)
                        and parsed_result.get("type") == "result"
                        and parsed_result.get("subtype") == "success"
                        and parsed_result.get("is_error")
                        and parsed_result.get("result") == "Prompt is too long"
                    ):
                        return False, "PROMPT_TOO_LONG", {}

                    if (
                        isinstance(parsed_result, dict)
                        and parsed_result.get("type") == "result"
                        and parsed_result.get("subtype") == "error_during_execution"
                        and attempt == 0
                    ):
                        continue

                    parsed_results = self._extract_security_findings(parsed_result)
                    return True, "", parsed_results

                if attempt == 0:
                    continue
                return False, "Failed to parse runtime output", {}

            return False, "Unexpected error in retry logic", {}
        except subprocess.TimeoutExpired:
            return False, f"Analysis runtime execution timed out after {self.timeout_seconds // 60} minutes", {}
        except Exception as e:
            return False, f"Analysis runtime execution error: {str(e)}", {}

    def _extract_security_findings(self, runtime_output: Any) -> Dict[str, Any]:
        if isinstance(runtime_output, dict):
            if "findings" in runtime_output:
                return runtime_output

            if "result" in runtime_output:
                result_text = runtime_output["result"]
                if isinstance(result_text, str):
                    success, result_json = parse_json_with_fallbacks(result_text, "runtime result text")
                    if success and result_json and "findings" in result_json:
                        return result_json
                elif isinstance(result_text, dict) and "findings" in result_text:
                    return result_text

            if runtime_output.get("type") == "text" and "part" in runtime_output:
                part = runtime_output["part"]
                if isinstance(part, dict) and part.get("type") == "text" and "text" in part:
                    success, result_json = parse_json_with_fallbacks(part["text"], "Opencode text part")
                    if success and result_json and "findings" in result_json:
                        return result_json

        return {
            "findings": [],
            "analysis_summary": {
                "files_reviewed": 0,
                "high_severity": 0,
                "medium_severity": 0,
                "low_severity": 0,
                "review_completed": False,
            },
        }

    def validate_runtime_available(self) -> Tuple[bool, str]:
        try:
            result = subprocess.run(
                [OPENCODE_SERVER_BIN, "--version"],
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode == 0:
                return True, ""

            error_msg = f"Runtime command returned exit code {result.returncode}"
            if result.stderr:
                error_msg += f". Stderr: {result.stderr}"
            if result.stdout:
                error_msg += f". Stdout: {result.stdout}"
            return False, error_msg
        except subprocess.TimeoutExpired:
            return False, "Runtime command timed out"
        except FileNotFoundError:
            return False, "Runtime command is not installed or not in PATH"
        except Exception as e:
            return False, f"Failed to check runtime command: {str(e)}"
