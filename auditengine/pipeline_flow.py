"""Workflow helpers for pipeline main."""

import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from auditengine.constants import (
    ANALYSIS_SCOPE,
    CUSTOM_SECURITY_SCAN_INSTRUCTIONS,
    ENABLE_HARD_EXCLUSIONS,
    ENABLE_OPENCODE_FILTERING,
    FALSE_POSITIVE_FILTERING_INSTRUCTIONS,
    GIT_URL,
    OUTPUT_DIR,
    PR_NUMBER,
    REPO_NAME,
    REPO_PATH,
)
from auditengine.findings_filter import FindingsFilter
from auditengine.logger import get_logger
from auditengine.prompts_utils import get_security_audit_prompt
from auditengine.session_manager import OpenCodeServerRuntime, OpenCodeSessionManager
from auditengine.unified_output_manager import UnifiedOutputManager

from auditengine.pipeline_clients import GitHubActionClient, RepositoryScopeClient
from auditengine.pipeline_runner import SimpleAuditRunner

logger = get_logger(__name__)


def load_optional_text(path: str) -> Optional[str]:
    if path and Path(path).exists():
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    return None


def load_custom_instructions() -> Tuple[Optional[str], Optional[str]]:
    return (
        load_optional_text(FALSE_POSITIVE_FILTERING_INSTRUCTIONS),
        load_optional_text(CUSTOM_SECURITY_SCAN_INSTRUCTIONS),
    )


def get_environment_config() -> Tuple[str, str, int]:
    git_url = GIT_URL
    pr_number_str = PR_NUMBER

    if not git_url:
        raise ValueError("GIT_URL environment variable required in PR mode")

    git_url_regex = re.compile(r".+(://)([^/]+)/(.*)\.git")
    matcher = git_url_regex.match(git_url)
    if not matcher:
        raise ValueError(f"Invalid GIT_URL format: '{git_url}'")
    host = matcher.group(2)
    repo_name = matcher.group(3)

    if not repo_name:
        raise ValueError("GITHUB_REPOSITORY environment variable required")

    if not pr_number_str:
        raise ValueError("PR_NUMBER environment variable required")

    try:
        pr_number = int(pr_number_str)
    except ValueError as exc:
        raise ValueError(f"Invalid PR_NUMBER: {pr_number_str}") from exc

    return host, repo_name, pr_number


def get_scan_scope() -> str:
    scope_env = ANALYSIS_SCOPE
    if scope_env:
        scope = scope_env.strip().lower()
    else:
        has_pr_env = bool(GIT_URL) and bool(PR_NUMBER)
        scope = "pr" if has_pr_env else "full_repo"

    if scope not in {"full_repo", "pr"}:
        raise ValueError(f"Invalid ANALYSIS_SCOPE: {scope}. Use 'full_repo' or 'pr'")
    return scope


def get_repo_directory() -> Path:
    repo_path = REPO_PATH
    repo_dir = Path(repo_path) if repo_path else Path.cwd()
    if not repo_dir.exists() or not repo_dir.is_dir():
        raise ValueError(f"Invalid REPO_PATH directory: {repo_dir}")
    return repo_dir


def initialize_clients(scan_scope: str) -> Tuple[Any, SimpleAuditRunner]:
    if scan_scope == "pr":
        try:
            scope_client = GitHubActionClient()
        except Exception as exc:
            raise ValueError(f"Failed to initialize GitHub client: {str(exc)}") from exc
    else:
        scope_client = RepositoryScopeClient()

    try:
        audit_runner = SimpleAuditRunner()
    except Exception as exc:
        raise ValueError(f"Failed to initialize audit runner: {str(exc)}") from exc

    return scope_client, audit_runner


def prepare_pr_data(scan_scope: str, scope_client: Any, repo_dir: Path) -> Tuple[str, int, Dict[str, Any]]:
    if scan_scope == "pr":
        host, repo_name, pr_number = get_environment_config()
        pr_data = scope_client.get_pr_data(host, repo_name, pr_number)
        return repo_name, pr_number, pr_data

    repo_name = REPO_NAME or repo_dir.name
    pr_number = 0
    pr_data = scope_client.get_full_repo_data(repo_dir, repo_name)
    return repo_name, pr_number, pr_data


def initialize_shared_runtime(repo_dir: Path, timeout_seconds: int) -> Tuple[OpenCodeServerRuntime, OpenCodeSessionManager, UnifiedOutputManager]:
    shared_server_runtime = OpenCodeServerRuntime(repo_path=str(repo_dir))
    shared_server_runtime.start()

    shared_session_manager = OpenCodeSessionManager(timeout_seconds=timeout_seconds)
    shared_session_manager.create_session()
    effective_output_dir = OUTPUT_DIR or str(repo_dir)
    logger.info(f"Using output directory: {effective_output_dir}")
    output_manager = UnifiedOutputManager(
        session_id=shared_session_manager.session_id,
        base_output_dir=effective_output_dir,
    )
    return shared_server_runtime, shared_session_manager, output_manager


def initialize_findings_filter(
    custom_filtering_instructions: Optional[str] = None,
    external_session_manager: Optional[OpenCodeSessionManager] = None,
) -> FindingsFilter:
    try:
        use_ai_filtering = ENABLE_OPENCODE_FILTERING

        if use_ai_filtering:
            return FindingsFilter(
                use_hard_exclusions=True,
                use_ai_filtering=True,
                custom_filtering_instructions=custom_filtering_instructions,
                external_session_manager=external_session_manager,
            )
        return FindingsFilter(
            use_hard_exclusions=False,
            use_ai_filtering=True,
            external_session_manager=external_session_manager,
        )
    except Exception as exc:
        raise ValueError(f"Failed to initialize findings filter: {str(exc)}") from exc


def _is_finding_in_excluded_directory(finding: Dict[str, Any], github_client: Any) -> bool:
    file_path = finding.get("file", "")
    if not file_path:
        return False

    if github_client is None or not hasattr(github_client, "_is_excluded"):
        return False

    return bool(github_client._is_excluded(file_path))


def apply_findings_filter_with_shared_session(
    original_findings: List[Dict[str, Any]],
    pr_context: Dict[str, Any],
    github_client: Any,
    shared_session: Optional[OpenCodeSessionManager] = None,
    output_manager: Optional[UnifiedOutputManager] = None,
    custom_filtering_instructions: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    use_hard_exclusions = ENABLE_HARD_EXCLUSIONS
    use_ai_filtering = ENABLE_OPENCODE_FILTERING

    try:
        if shared_session is not None and use_ai_filtering:
            logger.info("Creating filter with shared session")
            active_filter = FindingsFilter(
                use_hard_exclusions=use_hard_exclusions,
                use_ai_filtering=use_ai_filtering,
                external_session_manager=shared_session,
                output_manager=output_manager,
                custom_filtering_instructions=custom_filtering_instructions,
            )
        else:
            if shared_session is None:
                logger.info("Creating standalone filter (no shared session)")
            if not use_ai_filtering:
                logger.info("Creating filter with AI filtering disabled")
            active_filter = FindingsFilter(
                use_hard_exclusions=use_hard_exclusions,
                use_ai_filtering=use_ai_filtering,
                output_manager=output_manager,
                custom_filtering_instructions=custom_filtering_instructions,
            )

        logger.info(f"Filter created successfully. Session available: {active_filter.session_manager is not None}")
    except Exception as e:
        logger.error(f"Failed to create filter: {str(e)}")
        return original_findings.copy(), [], {"directory_excluded_count": 0, "filter_error": str(e)}

    try:
        filter_success, filter_results, filter_stats = active_filter.filter_findings(original_findings, pr_context)
    except Exception as error:
        logger.error(f"Filter application failed: {error}")
        filter_success = False
        filter_results = {"filtered_findings": original_findings, "excluded_findings": []}

    if filter_success:
        kept_findings = filter_results.get("filtered_findings", [])
        excluded_findings = filter_results.get("excluded_findings", [])
        analysis_summary = filter_results.get("analysis_summary", {})
    else:
        kept_findings = original_findings
        excluded_findings = []
        analysis_summary = {}

    final_kept_findings = []
    directory_excluded_findings = []
    for finding in kept_findings:
        if _is_finding_in_excluded_directory(finding, github_client):
            directory_excluded_findings.append(finding)
        else:
            final_kept_findings.append(finding)

    all_excluded_findings = excluded_findings + directory_excluded_findings
    final_analysis = {
        **analysis_summary,
        "directory_excluded_count": len(directory_excluded_findings),
        "filter_applied": True,
    }

    return final_kept_findings, all_excluded_findings, final_analysis


def run_audit_workflow(
    audit_runner: SimpleAuditRunner,
    use_phased_analysis: bool,
    repo_dir: Path,
    pr_data: Dict[str, Any],
    scan_scope: str,
    shared_session_manager: OpenCodeSessionManager,
    output_manager: UnifiedOutputManager,
    custom_scan_instructions: Optional[str],
) -> Tuple[bool, str, Dict[str, Any]]:
    if use_phased_analysis:
        return audit_runner.run_phased_security_audit_with_session(
            repo_dir,
            pr_data,
            session_manager=shared_session_manager,
            output_manager=output_manager,
        )

    prompt = get_security_audit_prompt(
        pr_data=pr_data,
        custom_scan_instructions=custom_scan_instructions,
        include_diff=(scan_scope == "pr"),
    )
    return audit_runner.run_security_audit(repo_dir, prompt)


def finalize_outputs(
    results: Dict[str, Any],
    use_phased_analysis: bool,
    scan_scope: str,
    repo_name: str,
    pr_number: int,
    pr_data: Dict[str, Any],
    scope_client: Any,
    shared_session_manager: OpenCodeSessionManager,
    output_manager: UnifiedOutputManager,
    workflow_started_at: str,
    workflow_start_time: float,
    custom_filtering_instructions: Optional[str],
) -> None:
    phased_results = results.get("phased_results", {}) if use_phased_analysis else {}
    if use_phased_analysis:
        original_findings = phased_results.get("phase6", {}).get("all_defects", [])
    else:
        original_findings = results.get("findings", [])

    analysis_summary = results.get("analysis_summary", {})
    analysis_summary["analysis_workflow"] = "phased" if use_phased_analysis else "legacy"
    effective_scan_scope = "full_repository" if use_phased_analysis else ("full_repository" if scan_scope == "full_repo" else "pr")
    analysis_summary["scan_scope"] = effective_scan_scope

    pr_context = {
        "repo_name": repo_name,
        "pr_number": pr_number,
        "title": pr_data.get("title", ""),
        "description": pr_data.get("body", ""),
        "scan_scope": analysis_summary["scan_scope"],
    }

    phase7_started_at = datetime.now().isoformat()
    phase7_start_time = time.time()
    phase7_model_id, phase7_provider_id = shared_session_manager.model, shared_session_manager.provider_id

    kept_findings, excluded_findings, filter_stats = apply_findings_filter_with_shared_session(
        original_findings,
        pr_context,
        scope_client,
        shared_session_manager,
        output_manager=output_manager,
        custom_filtering_instructions=custom_filtering_instructions,
    )

    final_defects = {
        "findings": kept_findings,
        "analysis_summary": {
            **analysis_summary,
            "total_original_findings": len(original_findings),
            "excluded_findings": len(excluded_findings),
            "kept_findings": len(kept_findings),
        },
        "filtering_summary": filter_stats,
    }
    output_manager.save_json("phase7_result.json", final_defects)

    phase7_metadata = {
        "phase": "phase7",
        "name": "findings_filtering",
        "status": "success",
        "started_at": phase7_started_at,
        "ended_at": datetime.now().isoformat(),
        "duration_seconds": time.time() - phase7_start_time,
        "prompt_file": None,
        "response_file": None,
        "result_file": "phase7_result.json",
        "error_message": None,
        "model_id": phase7_model_id,
        "provider_id": phase7_provider_id,
    }

    if use_phased_analysis and isinstance(results, dict):
        results.setdefault("phased_results", {})["phase7"] = final_defects
        results.setdefault("phase_metadata", {})["phase7"] = phase7_metadata

    consolidated_phase_metadata = {}
    if isinstance(results, dict):
        consolidated_phase_metadata = dict(results.get("phase_metadata", {}))
    if "phase7" not in consolidated_phase_metadata:
        consolidated_phase_metadata["phase7"] = phase7_metadata

    output_manager.save_json(
        "analysis_metadata.json",
        {
            "workflow": "phased" if use_phased_analysis else "legacy",
            "started_at": workflow_started_at,
            "ended_at": datetime.now().isoformat(),
            "duration_seconds": time.time() - workflow_start_time,
            "scan_scope": analysis_summary.get("scan_scope"),
            "phase_metadata": consolidated_phase_metadata,
        },
    )

    output = {
        "scan_scope": analysis_summary["scan_scope"],
        "repo": repo_name,
        "findings": kept_findings,
        "analysis_summary": analysis_summary,
        "filtering_summary": {
            "total_original_findings": len(original_findings),
            "excluded_findings": len(excluded_findings),
            "kept_findings": len(kept_findings),
            "filter_stats": filter_stats,
            "use_phased_analysis": use_phased_analysis,
            "analysis_workflow": analysis_summary.get("analysis_workflow", "unknown"),
        },
    }
    if scan_scope == "pr":
        output["pr_number"] = pr_number

    output_manager.save_json("security_audit.json", output)
