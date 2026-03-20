#!/usr/bin/env python3
"""Entry point for security audit pipeline workflow."""

import json
import os
import sys
import time
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auditengine.constants import EXIT_CONFIGURATION_ERROR, EXIT_GENERAL_ERROR, NO_PROXY, USE_PHASED_ANALYSIS
from auditengine.logger import get_logger
from auditengine.pipeline_flow import (
    finalize_outputs,
    get_repo_directory,
    get_scan_scope,
    initialize_clients,
    initialize_shared_runtime,
    load_custom_instructions,
    prepare_pr_data,
    run_audit_workflow,
)

os.environ["NO_PROXY"] = NO_PROXY

logger = get_logger(__name__)


def main():
    """Main execution function for phased security analysis."""
    shared_session_manager = None
    shared_server_runtime = None
    try:
        workflow_started_at = datetime.now().isoformat()
        workflow_start_time = time.time()
        scan_scope = get_scan_scope()
        use_phased_analysis = USE_PHASED_ANALYSIS
        repo_dir = get_repo_directory()

        custom_filtering_instructions, custom_scan_instructions = load_custom_instructions()
        scope_client, audit_runner = initialize_clients(scan_scope)

        runtime_ok, runtime_error = audit_runner.validate_runtime_available()
        if not runtime_ok:
            print(json.dumps({"error": f"Analysis runtime not available: {runtime_error}"}))
            sys.exit(EXIT_GENERAL_ERROR)

        repo_name, pr_number, pr_data = prepare_pr_data(scan_scope, scope_client, repo_dir)

        try:
            shared_server_runtime, shared_session_manager, output_manager = initialize_shared_runtime(
                repo_dir=repo_dir,
                timeout_seconds=audit_runner.timeout_seconds,
            )
        except Exception as e:
            print(json.dumps({"error": f"Session manager initialization failed: {str(e)}"}))
            sys.exit(EXIT_GENERAL_ERROR)

        success, error_msg, results = run_audit_workflow(
            audit_runner=audit_runner,
            use_phased_analysis=use_phased_analysis,
            repo_dir=repo_dir,
            pr_data=pr_data,
            scan_scope=scan_scope,
            shared_session_manager=shared_session_manager,
            output_manager=output_manager,
            custom_scan_instructions=custom_scan_instructions,
        )

        if not success:
            print(json.dumps({"error": f"Security audit failed: {error_msg}"}))
            sys.exit(EXIT_GENERAL_ERROR)

        finalize_outputs(
            results=results,
            use_phased_analysis=use_phased_analysis,
            scan_scope=scan_scope,
            repo_name=repo_name,
            pr_number=pr_number,
            pr_data=pr_data,
            scope_client=scope_client,
            shared_session_manager=shared_session_manager,
            output_manager=output_manager,
            workflow_started_at=workflow_started_at,
            workflow_start_time=workflow_start_time,
            custom_filtering_instructions=custom_filtering_instructions,
        )

    except ValueError as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(EXIT_CONFIGURATION_ERROR)
    except Exception as e:
        print(json.dumps({"error": f"Unexpected error: {str(e)}"}))
        sys.exit(EXIT_CONFIGURATION_ERROR)
    finally:
        if shared_session_manager:
            try:
                shared_session_manager.close_session()
            except Exception as cleanup_error:
                logger.warning(f"Error closing shared session: {cleanup_error}")
        if shared_server_runtime:
            try:
                shared_server_runtime.stop()
            except Exception as cleanup_error:
                logger.warning(f"Error stopping global server runtime: {cleanup_error}")


if __name__ == "__main__":
    main()
