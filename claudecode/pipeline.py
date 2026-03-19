#!/usr/bin/env python3
"""
Simplified PR Security Audit for GitHub Actions
Runs Claude Code security audit on current working directory and outputs findings to stdout
"""

import os
import sys
import json
import subprocess
import requests
from typing import Dict, Any, List, Tuple, Optional
from pathlib import Path
import re
import time 
import tempfile
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["NO_PROXY"] = "127.0.0.1,7.185.124.169,7.192.168.161,localhost,*.huawei.com"

# Import existing components we can reuse
from claudecode.prompts_utils import get_security_audit_prompt
from claudecode.findings_filter import FindingsFilter
from claudecode.json_parser import parse_json_with_fallbacks
from claudecode.constants import (
    EXIT_CONFIGURATION_ERROR,
    EXIT_SUCCESS,
    EXIT_GENERAL_ERROR,
    SUBPROCESS_TIMEOUT
)
from claudecode.logger import get_logger

# Import phased analysis components
from claudecode.session_manager import OpenCodeSessionManager
from claudecode.phased_analyzer import PhasedSecurityAnalyzer
from claudecode.unified_output_manager import UnifiedOutputManager

logger = get_logger(__name__)

class ConfigurationError(ValueError):
    """Raised when configuration is invalid or missing."""
    pass

class AuditError(ValueError):
    """Raised when security audit operations fail."""
    pass

class GitHubActionClient:
    """Simplified GitHub API client for GitHub Actions environment."""
    
    def __init__(self):
        """Initialize GitHub client using environment variables."""
        self.github_token = os.environ.get('GITHUB_TOKEN')
        if not self.github_token:
            raise ValueError("GITHUB_TOKEN environment variable required")
            
        self.headers = {
            "PRIVATE-TOKEN": f'{self.github_token}',
        }
        
        # Get excluded directories from environment
        exclude_dirs = os.environ.get('EXCLUDE_DIRECTORIES', '')
        self.excluded_dirs = [d.strip() for d in exclude_dirs.split(',') if d.strip()] if exclude_dirs else []
        if self.excluded_dirs:
            logger.debug(f"Excluded directories: {self.excluded_dirs}")
    
    def get_pr_data(self, host: str, repo_name: str, pr_number: int) -> Dict[str, Any]:
        """Get PR metadata and files from GitHub API.
        
        Args:
            repo_name: Repository name in format "owner/repo"
            pr_number: Pull request number
            
        Returns:
            Dictionary containing PR data
        """
        # Get PR metadata
        project_path = repo_name.replace('/', '%2F')

        pr_url = f"https://{host}/api/v4/projects/{project_path}/merge_requests/{pr_number}/changes"
        response = requests.get(pr_url, headers=self.headers, verify=False)
        response.raise_for_status()
        pr_data = response.json()

        # 辅助函数：根据 GitLab 的布尔字段推断文件变更状态
        def get_file_status(f: Dict[str, Any]) -> str:
            if f.get('new_file'):
                return 'added'
            elif f.get('deleted_file'):
                return 'removed'
            elif f.get('renamed_file'):
                return 'renamed'
            return 'modified'
        
        return {
            'number': pr_data.get('iid'),
            'title': pr_data.get('title', ''),
            'body': pr_data.get('description', ''),
            'user': pr_data.get('author', {}).get('name_cn', 'Unknown'),
            'created_at': pr_data.get('created_at'),
            'updated_at': pr_data.get('updated_at'),
            'state': pr_data.get('state'),
            'head': {
                'ref': pr_data.get('source_branch', ''),
                'sha': pr_data.get('diff_refs', {}).get('head_sha', ''),
                'repo': {
                    'full_name': repo_name
                }
            },
            'base': {
                'ref': pr_data.get('target_branch', ''),
                'sha': pr_data.get('diff_refs', {}).get('base_sha', '')
            },
            'files':[
                {
                    'old_path': f.get('old_path', ''),
                    'new_path': f.get('new_path', ''),
                    'filename': f.get('file_path', ''),
                    'status': get_file_status(f),
                    'additions': f.get('added_lines', 0),
                    'deletions': f.get('removed_lines', 0),
                    'patch': f.get('diff', '')
                }
                for f in pr_data.get('changes', [])
                if not self._is_excluded(f.get('file_path', ''))
            ],
            'additions': pr_data.get('added_lines', 0),
            'deletions': pr_data.get('removed_lines', 0),
            'changed_files': len(pr_data.get('changes',[]))
        }
    
    def get_pr_diff(self, repo_name: str, pr_number: int) -> str:
        """Get complete PR diff in unified format.
        
        Args:
            repo_name: Repository name in format "owner/repo"
            pr_number: Pull request number
            
        Returns:
            Complete PR diff in unified format
        """
        url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}"
        headers = dict(self.headers)
        headers['Accept'] = 'application/vnd.github.diff'
        
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        return self._filter_generated_files(response.text)
    
    def _is_excluded(self, filepath: str) -> bool:
        """Check if a file should be excluded based on directory patterns."""
        for excluded_dir in self.excluded_dirs:
            # Normalize excluded directory (remove leading ./ if present)
            if excluded_dir.startswith('./'):
                normalized_excluded = excluded_dir[2:]
            else:
                normalized_excluded = excluded_dir
            
            # Check if file starts with excluded directory
            if filepath.startswith(excluded_dir + '/'):
                return True
            if filepath.startswith(normalized_excluded + '/'):
                return True
            
            # Check if excluded directory appears anywhere in the path
            if '/' + normalized_excluded + '/' in filepath:
                return True
            
        return False
    
    def _filter_generated_files(self, diff_text: str) -> str:
        """Filter out generated files and excluded directories from diff content."""
        
        file_sections = re.split(r'(?=^diff --git)', diff_text, flags=re.MULTILINE)
        filtered_sections = []
        
        for section in file_sections:
            if not section.strip():
                continue
                
            # Skip generated files
            if ('@generated by' in section or 
                '@generated' in section or 
                'Code generated by OpenAPI Generator' in section or
                'Code generated by protoc-gen-go' in section):
                continue
            
            # Extract filename from diff header
            match = re.match(r'^diff --git a/(.*?) b/', section)
            if match:
                filename = match.group(1)
                if self._is_excluded(filename):
                    logger.debug(f"Filtering out excluded file: {filename}")
                    continue
            
            filtered_sections.append(section)
        
        return ''.join(filtered_sections)


class RepositoryScopeClient:
    """Repository scanner and exclusion matcher for full-repo mode."""

    def __init__(self):
        exclude_dirs = os.environ.get('EXCLUDE_DIRECTORIES', '')
        self.excluded_dirs = [d.strip() for d in exclude_dirs.split(',') if d.strip()] if exclude_dirs else []
        if self.excluded_dirs:
            logger.info(f"Excluded directories: {self.excluded_dirs}")

    def _is_excluded(self, filepath: str) -> bool:
        for excluded_dir in self.excluded_dirs:
            normalized_excluded = excluded_dir[2:] if excluded_dir.startswith('./') else excluded_dir

            if filepath.startswith(excluded_dir + '/'):
                return True
            if filepath.startswith(normalized_excluded + '/'):
                return True
            if '/' + normalized_excluded + '/' in filepath:
                return True

        return False

    def get_full_repo_data(self, repo_dir: Path, repo_name: str) -> Dict[str, Any]:
        files: List[Dict[str, Any]] = []

        for root, _, filenames in os.walk(repo_dir):
            root_path = Path(root)
            for filename in filenames:
                abs_path = root_path / filename
                rel_path = abs_path.relative_to(repo_dir).as_posix()
                if self._is_excluded(rel_path):
                    continue
                if "/.git/" in f"/{rel_path}/":
                    continue
                files.append({
                    'filename': rel_path,
                    'old_path': rel_path,
                    'new_path': rel_path,
                    'status': 'existing',
                    'additions': 0,
                    'deletions': 0,
                    'patch': ''
                })

        return {
            'number': 0,
            'title': 'Full repository security scan',
            'body': 'Scan scope: full repository',
            'user': os.environ.get('USER', 'system'),
            'created_at': None,
            'updated_at': None,
            'state': 'full_scan',
            'head': {'ref': 'full-repo', 'sha': '', 'repo': {'full_name': repo_name}},
            'base': {'ref': '', 'sha': ''},
            'files': files,
            'additions': 0,
            'deletions': 0,
            'changed_files': len(files),
            'repository_path': str(repo_dir),
            'scan_scope': 'full_repository',
        }


class SimpleClaudeRunner:
    """Simplified Claude Code runner for GitHub Actions."""
    
    def __init__(self, timeout_minutes: Optional[int] = None):
        """Initialize Claude runner.
        
        Args:
            timeout_minutes: Timeout for Claude execution (defaults to SUBPROCESS_TIMEOUT)
        """
        if timeout_minutes is not None:
            self.timeout_seconds = timeout_minutes * 60
        else:
            self.timeout_seconds = SUBPROCESS_TIMEOUT
    
    def run_phased_security_audit_with_session(self, 
                                             repo_dir: Path, 
                                             pr_data: Dict[str, Any],
                                             pr_diff: Optional[str] = None,
                                             custom_scan_instructions: Optional[str] = None,
                                             include_diff: bool = True,
                                             session_manager: Optional[OpenCodeSessionManager] = None) -> Tuple[bool, str, Dict[str, Any]]:
        """Run phased security audit using the new OpenCode session-based workflow with external session.
        
        Args:
            repo_dir: Repository directory path
            pr_data: PR data dictionary
            pr_diff: Optional complete PR diff in unified format
            custom_scan_instructions: Optional custom security categories to append
            include_diff: Whether to include the diff in the analysis
            session_manager: External session manager to use (if None, creates new one)
            
        Returns:
            Tuple of (success, error_message, results)
        """
        if not repo_dir.exists():
            return False, f"Repository directory does not exist: {repo_dir}", {}
        
        # Create session if not provided
        session_needs_close = False
        if session_manager is None:
            try:
                session_manager = OpenCodeSessionManager(timeout_seconds=self.timeout_seconds, repo_path=str(repo_dir))
                session_needs_close = True
                logger.info("为分阶段分析创建临时session")
            except Exception as e:
                error_msg = f"Failed to create session manager: {str(e)}"
                logger.error(error_msg)
                return False, error_msg, {}
        else:
            logger.info("使用外部传入的session进行分阶段分析")
        
        try:
            # Ensure session has a session_id
            if session_manager.session_id is None:
                session_manager.create_session()
                logger.info("创建了session_id")
            
            # Initialize phased analyzer
            phased_analyzer = PhasedSecurityAnalyzer(session_manager, output_dir=str(repo_dir))
            
            # Execute phased analysis
            try:
                analysis_results = phased_analyzer.execute_phased_analysis(
                    pr_data=pr_data,
                    pr_diff=pr_diff,
                    custom_scan_instructions=custom_scan_instructions,
                    include_diff=include_diff,
                    repo_dir=repo_dir
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
            # Only close session if we created it
            if session_needs_close and session_manager:
                try:
                    session_manager.close_session()
                    logger.info("已关闭临时创建的session")
                except Exception as e:
                    logger.warning(f"关闭临时session时出错: {str(e)}")
    
    def run_security_audit(self, repo_dir: Path, prompt: str) -> Tuple[bool, str, Dict[str, Any]]:
        """Run Claude Code security audit.
        
        Args:
            repo_dir: Path to repository directory
            prompt: Security audit prompt
            
        Returns:
            Tuple of (success, error_message, parsed_results)
        """
        if not repo_dir.exists():
            return False, f"Repository directory does not exist: {repo_dir}", {}
        
        # Check prompt size
        prompt_size = len(prompt.encode('utf-8'))
        if prompt_size > 1024 * 1024:  # 1MB
            logger.warning(f"Large prompt size: {prompt_size / 1024 / 1024:.2f}MB")
        
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, suffix='.txt') as temp_prompt_file:
            temp_prompt_file.write(prompt)
            temp_prompt_path = temp_prompt_file.name

        try:
            # Construct Claude Code command
            cmd =[
                'opencode.cmd', 'run',
                'Please review the attached security audit prompt.', # 触发执行的一句话 message
                '--format', 'json',
                '-f', temp_prompt_path,
            ]
            
            # Run Claude Code with retry logic
            NUM_RETRIES = 3
            for attempt in range(NUM_RETRIES):
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
                    if attempt == NUM_RETRIES - 1:
                        error_details = f"Claude Code execution failed with return code {result.returncode}\n"
                        error_details += f"Stderr: {result.stderr}\n"
                        error_details += f"Stdout: {result.stdout[:500]}..."  # First 500 chars
                        return False, error_details, {}
                    else:
                        time.sleep(5*attempt)
                        # Note: We don't do exponential backoff here to keep the runtime reasonable
                        continue  # Retry
                
                # Parse JSON output
                success, parsed_result = parse_json_with_fallbacks(result.stdout, "Claude Code output")
                
                if success:
                    # Check for "Prompt is too long" error that should trigger retry without diff
                    if (isinstance(parsed_result, dict) and 
                        parsed_result.get('type') == 'result' and 
                        parsed_result.get('subtype') == 'success' and
                        parsed_result.get('is_error') and
                        parsed_result.get('result') == 'Prompt is too long'):
                        return False, "PROMPT_TOO_LONG", {}
                    
                    # Check for error_during_execution that should trigger retry
                    if (isinstance(parsed_result, dict) and 
                        parsed_result.get('type') == 'result' and 
                        parsed_result.get('subtype') == 'error_during_execution' and
                        attempt == 0):
                        continue  # Retry
                    
                    # Extract security findings
                    parsed_results = self._extract_security_findings(parsed_result)
                    return True, "", parsed_results
                else:
                    if attempt == 0:
                        continue  # Retry once
                    else:
                        return False, "Failed to parse Claude output", {}
            
            return False, "Unexpected error in retry logic", {}
            
        except subprocess.TimeoutExpired:
            return False, f"Claude Code execution timed out after {self.timeout_seconds // 60} minutes", {}
        except Exception as e:
            return False, f"Claude Code execution error: {str(e)}", {}
    
    def _extract_security_findings(self, claude_output: Any) -> Dict[str, Any]:
        """Extract security findings from Claude's JSON response."""
        if isinstance(claude_output, dict):
            # Only accept Claude Code wrapper with result field
            # Direct format without wrapper is not supported
            if 'findings' in claude_output:
                return claude_output

            if 'result' in claude_output:
                result_text = claude_output['result']
                if isinstance(result_text, str):
                    # Try to extract JSON from the result text
                    success, result_json = parse_json_with_fallbacks(result_text, "Claude result text")
                    if success and result_json and 'findings' in result_json:
                        return result_json
                elif isinstance(result_text, dict) and 'findings' in result_text:
                    return result_text
            if claude_output.get('type') == 'text' and 'part' in claude_output:
                part = claude_output['part']
                if isinstance(part, dict) and part.get('type') == 'text' and 'text' in part:
                    success, result_json = parse_json_with_fallbacks(part['text'], "Opencode text part")
                    if success and result_json and 'findings' in result_json:
                        return result_json
        # Return empty structure if no findings found
        return {
            'findings': [],
            'analysis_summary': {
                'files_reviewed': 0,
                'high_severity': 0,
                'medium_severity': 0,
                'low_severity': 0,
                'review_completed': False,
            }
        }
    
    
    def validate_claude_available(self) -> Tuple[bool, str]:
        """Validate that Claude Code is available."""
        try:
            result = subprocess.run(
                ['opencode', '--version'],
                # shell=True,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                return True, ""
            else:
                error_msg = f"Claude Code returned exit code {result.returncode}"
                if result.stderr:
                    error_msg += f". Stderr: {result.stderr}"
                if result.stdout:
                    error_msg += f". Stdout: {result.stdout}"
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            return False, "Claude Code command timed out"
        except FileNotFoundError:
            return False, "Claude Code is not installed or not in PATH"
        except Exception as e:
            return False, f"Failed to check Claude Code: {str(e)}"
      

def get_environment_config() -> Tuple[str, str, int]:
    """Get and validate PR environment configuration."""
    git_url = os.environ.get('GIT_URL')
    pr_number_str = os.environ.get('PR_NUMBER')

    if not git_url:
        raise ConfigurationError('GIT_URL environment variable required in PR mode')

    GIT_URL_REGEX = re.compile(r".+(://)([^/]+)/(.*)\.git")
    matcher = GIT_URL_REGEX.match(git_url)
    if not matcher:
        raise ConfigurationError(f"Invalid GIT_URL format: '{git_url}'")
    host = matcher.group(2)  # 提取主机名，例如 "xxx.huawei.com"
    repo_name = matcher.group(3)  # 提取路径，例如 "xxx/xxx"
    
    if not repo_name:
        raise ConfigurationError('GITHUB_REPOSITORY environment variable required')
    
    if not pr_number_str:
        raise ConfigurationError('PR_NUMBER environment variable required')
    
    try:
        pr_number = int(pr_number_str)
    except ValueError:
        raise ConfigurationError(f'Invalid PR_NUMBER: {pr_number_str}')
        
    return host, repo_name, pr_number


def get_scan_scope() -> str:
    """Return scan scope with backward-compatible inference."""
    scope_env = os.environ.get('ANALYSIS_SCOPE')
    if scope_env:
        scope = scope_env.strip().lower()
    else:
        has_pr_env = bool(os.environ.get('GIT_URL')) and bool(os.environ.get('PR_NUMBER'))
        scope = 'pr' if has_pr_env else 'full_repo'

    if scope not in {'full_repo', 'pr'}:
        raise ConfigurationError(f"Invalid ANALYSIS_SCOPE: {scope}. Use 'full_repo' or 'pr'")
    return scope


def get_repo_directory() -> Path:
    """Resolve repository directory for scanning."""
    repo_path = os.environ.get('REPO_PATH')
    repo_dir = Path(repo_path) if repo_path else Path.cwd()
    if not repo_dir.exists() or not repo_dir.is_dir():
        raise ConfigurationError(f"Invalid REPO_PATH directory: {repo_dir}")
    return repo_dir


def initialize_clients(scan_scope: str) -> Tuple[Any, SimpleClaudeRunner]:
    """Initialize scope client and Claude runner."""
    if scan_scope == 'pr':
        try:
            scope_client = GitHubActionClient()
        except Exception as e:
            raise ConfigurationError(f'Failed to initialize GitHub client: {str(e)}')
    else:
        scope_client = RepositoryScopeClient()

    try:
        claude_runner = SimpleClaudeRunner()
    except Exception as e:
        raise ConfigurationError(f'Failed to initialize Claude runner: {str(e)}')

    return scope_client, claude_runner


def initialize_findings_filter(custom_filtering_instructions: Optional[str] = None, 
                             external_session_manager: Optional[OpenCodeSessionManager] = None) -> FindingsFilter:
    """Initialize findings filter based on environment configuration.
    
    Args:
        custom_filtering_instructions: Optional custom filtering instructions
        external_session_manager: Optional external session manager to reuse
        
    Returns:
        FindingsFilter instance
        
    Raises:
        ConfigurationError: If filter initialization fails
    """
    try:
        # Check if we should use Claude API filtering
        use_claude_filtering = os.environ.get('ENABLE_OPENCODE_FILTERING', 'true').lower() == 'true'
        api_key = os.environ.get('ANTHROPIC_API_KEY')
        
        if use_claude_filtering and api_key:
            # Use full filtering with external session manager if provided
            return FindingsFilter(
                use_hard_exclusions=True,
                use_claude_filtering=True,
                api_key=api_key,
                custom_filtering_instructions=custom_filtering_instructions,
                external_session_manager=external_session_manager
            )
        else:
            # Fallback to filtering with hard rules only
            return FindingsFilter(
                use_hard_exclusions=False,
                use_claude_filtering=True,
                external_session_manager=external_session_manager
            )
    except Exception as e:
        raise ConfigurationError(f'Failed to initialize findings filter: {str(e)}')



def run_security_audit(claude_runner: SimpleClaudeRunner, prompt: str) -> Dict[str, Any]:
    """Run the security audit with Claude Code.
    
    Args:
        claude_runner: Claude runner instance
        prompt: The security audit prompt
        
    Returns:
        Audit results dictionary
        
    Raises:
        AuditError: If the audit fails
    """
    # Get repo directory from environment or use current directory
    repo_path = os.environ.get('REPO_PATH')
    repo_dir = Path(repo_path) if repo_path else Path.cwd()
    success, error_msg, results = claude_runner.run_security_audit(repo_dir, prompt)
    
    if not success:
        raise AuditError(f'Security audit failed: {error_msg}')
        
    return results


def apply_findings_filter(findings_filter, original_findings: List[Dict[str, Any]], 
                          pr_context: Dict[str, Any], github_client: GitHubActionClient) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """Apply findings filter to reduce false positives.
    
    Args:
        findings_filter: Filter instance
        original_findings: Original findings from audit
        pr_context: PR context information
        github_client: GitHub client with exclusion logic
        
    Returns:
        Tuple of (kept_findings, excluded_findings, analysis_summary)
    """
    # Apply FindingsFilter
    filter_success, filter_results, filter_stats = findings_filter.filter_findings(
        original_findings, pr_context
    )
    
    if filter_success:
        kept_findings = filter_results.get('filtered_findings', [])
        excluded_findings = filter_results.get('excluded_findings', [])
        analysis_summary = filter_results.get('analysis_summary', {})
    else:
        # Filtering failed, keep all findings
        kept_findings = original_findings
        excluded_findings = []
        analysis_summary = {}
    
    # Apply final directory exclusion filtering
    final_kept_findings = []
    directory_excluded_findings = []
    
    for finding in kept_findings:
        if _is_finding_in_excluded_directory(finding, github_client):
            directory_excluded_findings.append(finding)
        else:
            final_kept_findings.append(finding)
    
    # Update excluded findings list
    all_excluded_findings = excluded_findings + directory_excluded_findings
    
    # Update analysis summary with directory filtering stats
    analysis_summary['directory_excluded_count'] = len(directory_excluded_findings)
    
    return final_kept_findings, all_excluded_findings, analysis_summary

def apply_findings_filter_with_shared_session(original_findings: List[Dict[str, Any]], 
                                             pr_context: Dict[str, Any], github_client: Any,
                                             shared_session: Optional[OpenCodeSessionManager] = None,
                                             output_dir: str = None,
                                             custom_filtering_instructions: Optional[str] = None) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """Apply findings filter using shared session manager.
    
    Args:
        original_findings: Original findings from audit
        pr_context: PR context information
        github_client: GitHub client with exclusion logic
        shared_session: Optional shared session manager to use
        
    Returns:
        Tuple of (kept_findings, excluded_findings, analysis_summary)
    """
    # Determine filtering configuration from environment
    use_hard_exclusions = os.environ.get('ENABLE_HARD_EXCLUSIONS', 'true').lower() == 'true'
    use_claude_filtering = os.environ.get('ENABLE_OPENCODE_FILTERING', 'true').lower() == 'true'
    
    # Create filter based on availability
    try:
        if shared_session is not None and use_claude_filtering:
            logger.info("Creating filter with shared session")
            # Use shared session for filtering (session has already been created)
            active_filter = FindingsFilter(
                use_hard_exclusions=use_hard_exclusions,
                use_claude_filtering=use_claude_filtering,
                external_session_manager=shared_session,
                output_dir=str(output_dir),
                custom_filtering_instructions=custom_filtering_instructions
            )
        else:
            if shared_session is None:
                logger.info("Creating standalone filter (no shared session)")
            if not use_claude_filtering:
                logger.info("Creating filter with AI filtering disabled")
            # Create standalone filter with its own session
            active_filter = FindingsFilter(
                use_hard_exclusions=use_hard_exclusions,
                use_claude_filtering=use_claude_filtering,
                output_dir=str(output_dir),
                custom_filtering_instructions=custom_filtering_instructions
            )
            
        logger.info(f"Filter created successfully. Session available: {active_filter.session_manager is not None}")
            
    except Exception as e:
        logger.error(f"Failed to create filter: {str(e)}")
        # Fallback: keep all findings without filtering
        return original_findings.copy(), [], {'directory_excluded_count': 0, 'filter_error': str(e)}
    
    # Apply filtering
    try:
        filter_success, filter_results, filter_stats = active_filter.filter_findings(
            original_findings, pr_context
        )
    except Exception as error:
        logger.error(f"Filter application failed: {error}")
        filter_success = False
        filter_results = {'filtered_findings': original_findings, 'excluded_findings': []}
    
    # Process results
    if filter_success:
        kept_findings = filter_results.get('filtered_findings', [])
        excluded_findings = filter_results.get('excluded_findings', [])
        analysis_summary = filter_results.get('analysis_summary', {})
    else:
        kept_findings = original_findings
        excluded_findings = []
        analysis_summary = {}
    
    # Apply directory exclusion filtering
    final_kept_findings = []
    directory_excluded_findings = []
    
    for finding in kept_findings:
        if _is_finding_in_excluded_directory(finding, github_client):
            directory_excluded_findings.append(finding)
        else:
            final_kept_findings.append(finding)
    
    # Combine excluded findings
    all_excluded_findings = excluded_findings + directory_excluded_findings
    
    # Add directory filtering stats
    final_analysis = {
        **analysis_summary,
        'directory_excluded_count': len(directory_excluded_findings),
        'filter_applied': True
    }
    
    return final_kept_findings, all_excluded_findings, final_analysis


def _is_finding_in_excluded_directory(finding: Dict[str, Any], github_client: Any) -> bool:
    """Check if a finding references a file in an excluded directory.
    
    Args:
        finding: Security finding dictionary
        github_client: GitHub client with exclusion logic
        
    Returns:
        True if finding should be excluded, False otherwise
    """
    file_path = finding.get('file', '')
    if not file_path:
        return False
    
    if github_client is None or not hasattr(github_client, '_is_excluded'):
        return False

    return bool(github_client._is_excluded(file_path))


def main():
    """Main execution function for phased security analysis."""
    shared_session_manager = None
    try:
        scan_scope = get_scan_scope()
        use_phased_analysis = os.environ.get('USE_PHASED_ANALYSIS', 'true').lower() == 'true'
        repo_dir = get_repo_directory()

        # Load optional instructions
        custom_filtering_instructions = None
        filtering_file = os.environ.get('FALSE_POSITIVE_FILTERING_INSTRUCTIONS', '')
        if filtering_file and Path(filtering_file).exists():
            with open(filtering_file, 'r', encoding='utf-8') as f:
                custom_filtering_instructions = f.read()

        custom_scan_instructions = None
        scan_file = os.environ.get('CUSTOM_SECURITY_SCAN_INSTRUCTIONS', '')
        if scan_file and Path(scan_file).exists():
            with open(scan_file, 'r', encoding='utf-8') as f:
                custom_scan_instructions = f.read()

        scope_client, claude_runner = initialize_clients(scan_scope)

        claude_ok, claude_error = claude_runner.validate_claude_available()
        if not claude_ok:
            print(json.dumps({'error': f'Claude Code not available: {claude_error}'}))
            sys.exit(EXIT_GENERAL_ERROR)

        if scan_scope == 'pr':
            host, repo_name, pr_number = get_environment_config()
            pr_data = scope_client.get_pr_data(host, repo_name, pr_number)
        else:
            repo_name = os.environ.get('REPO_NAME', repo_dir.name)
            pr_number = 0
            pr_data = scope_client.get_full_repo_data(repo_dir, repo_name)

        try:
            shared_session_manager = OpenCodeSessionManager(
                timeout_seconds=claude_runner.timeout_seconds,
                repo_path=str(repo_dir)
            )
            shared_session_manager.create_session()
        except Exception as e:
            print(json.dumps({'error': f'Session manager initialization failed: {str(e)}'}))
            sys.exit(EXIT_GENERAL_ERROR)

        if use_phased_analysis:
            success, error_msg, results = claude_runner.run_phased_security_audit_with_session(
                repo_dir,
                pr_data,
                pr_diff=None,
                custom_scan_instructions=custom_scan_instructions,
                include_diff=(scan_scope == 'pr'),
                session_manager=shared_session_manager
            )
        else:
            prompt = get_security_audit_prompt(
                pr_data=pr_data,
                custom_scan_instructions=custom_scan_instructions,
                include_diff=(scan_scope == 'pr')
            )
            success, error_msg, results = claude_runner.run_security_audit(repo_dir, prompt)

        if not success:
            print(json.dumps({'error': f'Security audit failed: {error_msg}'}))
            sys.exit(EXIT_GENERAL_ERROR)

        phased_results = results.get('phased_results', {}) if use_phased_analysis else {}
        if use_phased_analysis:
            original_findings = phased_results.get('phase6', {}).get('all_defects', [])
        else:
            original_findings = results.get('findings', [])

        analysis_summary = results.get('analysis_summary', {})
        analysis_summary['analysis_workflow'] = 'phased' if use_phased_analysis else 'legacy'
        effective_scan_scope = 'full_repository' if use_phased_analysis else ('full_repository' if scan_scope == 'full_repo' else 'pr')
        analysis_summary['scan_scope'] = effective_scan_scope

        pr_context = {
            'repo_name': repo_name,
            'pr_number': pr_number,
            'title': pr_data.get('title', ''),
            'description': pr_data.get('body', ''),
            'scan_scope': analysis_summary['scan_scope'],
        }

        kept_findings, excluded_findings, filter_stats = apply_findings_filter_with_shared_session(
            original_findings,
            pr_context,
            scope_client,
            shared_session_manager,
            output_dir=str(repo_dir),
            custom_filtering_instructions=custom_filtering_instructions
        )

        output_manager = UnifiedOutputManager(
            session_id=shared_session_manager.session_id,
            base_output_dir=str(repo_dir)
        )

        final_defects = {
            'findings': kept_findings,
            'analysis_summary': {
                **analysis_summary,
                'total_original_findings': len(original_findings),
                'excluded_findings': len(excluded_findings),
                'kept_findings': len(kept_findings),
            },
            'filtering_summary': filter_stats,
        }
        output_manager.save_json('phase7_result.json', final_defects)

        if use_phased_analysis and isinstance(results, dict):
            results.setdefault('phased_results', {})['phase7'] = final_defects

        output = {
            'scan_scope': analysis_summary['scan_scope'],
            'repo': repo_name,
            'findings': kept_findings,
            'analysis_summary': analysis_summary,
            'filtering_summary': {
                'total_original_findings': len(original_findings),
                'excluded_findings': len(excluded_findings),
                'kept_findings': len(kept_findings),
                'filter_stats': filter_stats,
                'use_phased_analysis': use_phased_analysis,
                'analysis_workflow': analysis_summary.get('analysis_workflow', 'unknown')
            }
        }
        if scan_scope == 'pr':
            output['pr_number'] = pr_number

        output_manager.save_json('security_audit.json', output)

    except ConfigurationError as e:
        print(json.dumps({'error': str(e)}))
        sys.exit(EXIT_CONFIGURATION_ERROR)
    except Exception as e:
        print(json.dumps({'error': f'Unexpected error: {str(e)}'}))
        sys.exit(EXIT_CONFIGURATION_ERROR)
    finally:
        if shared_session_manager:
            try:
                shared_session_manager.close_session()
            except Exception as cleanup_error:
                logger.warning(f"Error closing shared session: {cleanup_error}")


if __name__ == '__main__':
    main()
