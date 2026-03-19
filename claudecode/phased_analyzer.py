"""Phased security analyzer for full-repository multi-stage workflow."""

import json
import time
import os
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, Optional, Tuple, List
from concurrent.futures import ThreadPoolExecutor, as_completed

from claudecode.json_parser import parse_json_with_fallbacks
from claudecode.logger import get_logger
from claudecode.prompts import (
    get_phase1_skill_bootstrap_prompt,
    get_phase2_context_study_prompt,
    get_phase3_comparative_analysis_prompt,
    get_phase4_cwd_routing_prompt,
    get_phase5_vulnerability_assessment_prompt,
)
from claudecode.session_manager import OpenCodeSessionManager
from claudecode.unified_output_manager import UnifiedOutputManager

logger = get_logger(__name__)


class PhaseParseError(RuntimeError):
    """Raised when a phase response cannot be parsed into valid JSON."""


class PhasedSecurityAnalyzer:
    """Full-repository phased analyzer with intermediate JSON artifacts."""

    def __init__(self, session_manager: OpenCodeSessionManager, output_dir: Optional[Path] = None):
        self.session_manager = session_manager
        self.output_manager = UnifiedOutputManager(
            session_id=session_manager.session_id,
            base_output_dir=output_dir,
        )
        self.session_dir = self.output_manager.get_session_dir()

        self.phase1_skill_bootstrap_results: Dict[str, Any] = {}
        self.phase2_results: Dict[str, Any] = {}
        self.phase3_results: Dict[str, Any] = {}
        self.phase4_results: Dict[str, Any] = {}
        self.phase5_results: Dict[str, Any] = {}
        self.phase6_results: Dict[str, Any] = {}
        self.phase_metadata: Dict[str, Any] = {}
        self.repo_dir: Optional[Path] = None
        self.custom_scan_instructions: Optional[str] = None

        logger.info(f"Phased analyzer initialized. Session dir: {self.session_dir}")

    def _get_phase_parallelism(self) -> int:
        raw = os.environ.get("PHASE_PARALLELISM", "4")
        try:
            value = int(raw)
        except ValueError:
            value = 4
        return max(1, min(value, 16))

    @staticmethod
    def _pick_module_entry(entries: List[Dict[str, Any]], module_name: str) -> Dict[str, Any]:
        if not entries:
            return {}
        for entry in entries:
            if entry.get("module_name") == module_name:
                return entry
        if len(entries) == 1:
            return entries[0]
        return {}

    @staticmethod
    def _iter_tool_parts(payload: Any):
        stack = [payload]
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                if item.get("type") == "tool":
                    yield item
                for value in item.values():
                    if isinstance(value, (dict, list)):
                        stack.append(value)
            elif isinstance(item, list):
                for value in item:
                    if isinstance(value, (dict, list)):
                        stack.append(value)

    @staticmethod
    def _extract_skill_name_from_tool_part(tool_part: Dict[str, Any]) -> str:
        state = tool_part.get("state", {}) if isinstance(tool_part.get("state"), dict) else {}
        candidates = []
        for key in ("input", "args", "parameters", "result", "output", "data"):
            value = state.get(key)
            if isinstance(value, dict):
                candidates.append(value)

        for candidate in candidates:
            for skill_key in ("name", "skill_name", "skillName", "skill"):
                skill_name = candidate.get(skill_key)
                if isinstance(skill_name, str) and skill_name.strip():
                    return skill_name.strip()
        return ""

    def _audit_skill_usage(self, session_history: List[Dict[str, Any]], expected_skills: List[str]) -> Dict[str, Any]:
        expected = [s for s in expected_skills if isinstance(s, str) and s.strip()]
        tool_parts = [part for part in self._iter_tool_parts(session_history) if part.get("tool") == "skill"]

        attempted_skills = set()
        completed_skills = set()
        errored_skills = set()
        status_counts = {"completed": 0, "error": 0, "running": 0, "pending": 0, "unknown": 0}

        for part in tool_parts:
            state = part.get("state", {}) if isinstance(part.get("state"), dict) else {}
            status = str(state.get("status", "unknown")).lower()
            if status not in status_counts:
                status = "unknown"
            status_counts[status] += 1

            skill_name = self._extract_skill_name_from_tool_part(part)
            if skill_name:
                attempted_skills.add(skill_name)
                if status == "completed":
                    completed_skills.add(skill_name)
                if status == "error":
                    errored_skills.add(skill_name)

        return {
            "expected_skills": expected,
            "skill_tool_calls": len(tool_parts),
            "status_counts": status_counts,
            "attempted_skills": sorted(attempted_skills),
            "completed_skills": sorted(completed_skills),
            "errored_skills": sorted(errored_skills),
            "skill_tool_observed": len(tool_parts) > 0,
        }

    def _run_single_module_phase345(
        self,
        index: int,
        module: Dict[str, Any],
        pr_data: Dict[str, Any],
        cwd_catalog: Dict[str, Any],
    ) -> Tuple[int, Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
        module_name = module.get("module_name", f"module_{index}")
        module_context = {"modules": [module]}

        sub_session = OpenCodeSessionManager(
            host=self.session_manager.host,
            timeout_seconds=self.session_manager.timeout_seconds,
            model=self.session_manager.model,
            provider_id=self.session_manager.provider_id,
            port=self.session_manager.port,
        )

        try:
            sub_session.create_session()

            prompt3 = get_phase3_comparative_analysis_prompt(
                pr_data=pr_data,
                phase2_results=module_context,
                custom_scan_instructions=self.custom_scan_instructions,
            )
            self.output_manager.save_text(f"phase3_module_{index}_prompt.txt", prompt3)
            response3 = sub_session.send_message(prompt=prompt3)
            # self.output_manager.save_json(f"phase3_module_{index}_response.json", response3)
            ok3, parsed3 = self._parse_phase_response(response3, f"phase3_module_{index}")
            if not ok3:
                raise PhaseParseError(f"phase3 parse failed for module '{module_name}'")

            phase3_selected = self._pick_module_entry(parsed3.get("module_risk_analysis", []), module_name)
            if not phase3_selected:
                phase3_selected = {
                    "module_name": module_name,
                    "business_flow": [],
                    "key_functions": [],
                    "attack_surfaces": [],
                    "risks": [],
                }
            self.output_manager.save_json(f"phase3_module_{index}_result.json", phase3_selected)

            prompt4 = get_phase4_cwd_routing_prompt(
                pr_data=pr_data,
                phase2_results=module_context,
                phase3_results={"module_risk_analysis": [phase3_selected]},
                cwd_catalog=cwd_catalog,
                custom_scan_instructions=self.custom_scan_instructions,
            )
            self.output_manager.save_text(f"phase4_module_{index}_prompt.txt", prompt4)
            response4 = sub_session.send_message(prompt=prompt4)
            # self.output_manager.save_json(f"phase4_module_{index}_response.json", response4)
            ok4, parsed4 = self._parse_phase_response(response4, f"phase4_module_{index}")
            if not ok4:
                raise PhaseParseError(f"phase4 parse failed for module '{module_name}'")

            phase4_selected = self._pick_module_entry(parsed4.get("module_cwd_priorities", []), module_name)
            if not phase4_selected:
                phase4_selected = {
                    "module_name": module_name,
                    "cwd_rankings": [],
                }
            self.output_manager.save_json(f"phase4_module_{index}_result.json", phase4_selected)

            prompt5 = get_phase5_vulnerability_assessment_prompt(
                pr_data=pr_data,
                phase2_results=module_context,
                phase3_results={"module_risk_analysis": [phase3_selected]},
                phase4_results={"module_cwd_priorities": [phase4_selected]},
                custom_scan_instructions=self.custom_scan_instructions,
            )
            self.output_manager.save_text(f"phase5_module_{index}_prompt.txt", prompt5)
            response5 = sub_session.send_message(prompt=prompt5)
            # self.output_manager.save_json(f"phase5_module_{index}_response.json", response5)
            ok5, parsed5 = self._parse_phase_response(response5, f"phase5_module_{index}")
            if not ok5:
                raise PhaseParseError(f"phase5 parse failed for module '{module_name}'")

            session_history = sub_session.get_session_info()
            serializable_history = [x.model_dump(mode="json", warnings=False) for x in session_history]
            # self.output_manager.save_json(f"phase5_module_{index}_session_messages.json", serializable_history)

            expected_skills = [
                item.get("skill_name", "")
                for item in phase4_selected.get("cwd_rankings", [])
                if isinstance(item, dict)
            ]
            skill_audit = self._audit_skill_usage(serializable_history, expected_skills)
            # self.output_manager.save_json(f"phase5_module_{index}_skill_audit.json", skill_audit)

            phase5_selected = self._pick_module_entry(parsed5.get("module_defects", []), module_name)
            if not phase5_selected:
                phase5_selected = {
                    "module_name": module_name,
                    "defects": [],
                }

            attempted_skills = set(skill_audit.get("attempted_skills", []))
            completed_skills = set(skill_audit.get("completed_skills", []))
            skill_tool_observed = bool(skill_audit.get("skill_tool_observed", False))
            for defect in phase5_selected.get("defects", []):
                skill_name = str(defect.get("skill_name", "")).strip()
                if skill_name and skill_name in completed_skills:
                    defect["skill_load_status"] = "loaded_verified"
                elif skill_name and skill_name in attempted_skills:
                    defect["skill_load_status"] = "failed_verified"
                elif skill_tool_observed:
                    defect["skill_load_status"] = "unknown_unmatched_trace"
                else:
                    defect["skill_load_status"] = "unknown_no_trace"

            phase5_selected["skill_audit"] = {
                "skill_tool_observed": skill_audit.get("skill_tool_observed", False),
                "skill_tool_calls": skill_audit.get("skill_tool_calls", 0),
                "expected_skills": skill_audit.get("expected_skills", []),
                "attempted_skills": skill_audit.get("attempted_skills", []),
                "completed_skills": skill_audit.get("completed_skills", []),
                "errored_skills": skill_audit.get("errored_skills", []),
                "status_counts": skill_audit.get("status_counts", {}),
            }
            self.output_manager.save_json(f"phase5_module_{index}_result.json", phase5_selected)

            return index, phase3_selected, phase4_selected, phase5_selected
        finally:
            sub_session.close_session()

    def execute_phased_analysis(
        self,
        pr_data: Dict[str, Any],
        pr_diff: Optional[str] = None,
        custom_scan_instructions: Optional[str] = None,
        include_diff: bool = True,
        repo_dir: Optional[Path] = None,
        resume_from: int = 0,
    ) -> Dict[str, Any]:
        """Execute phases 1-6 and return aggregate data for phase-7 filtering."""
        del include_diff
        del pr_diff
        del resume_from

        self.repo_dir = repo_dir
        self.custom_scan_instructions = custom_scan_instructions

        logger.info("=" * 80)
        logger.info("Starting full-repository phased analysis")
        logger.info("=" * 80)
        logger.info("Starting _execute_phase1_skill_bootstrap")
        self.phase1_skill_bootstrap_results = self._execute_phase1_skill_bootstrap()
        logger.info("Starting _execute_phase2")
        self.phase2_results = self._execute_phase2(pr_data)
        logger.info("Starting _execute_module_pipeline_phase345")
        self.phase3_results, self.phase4_results, self.phase5_results = self._execute_module_pipeline_phase345(pr_data)
        logger.info("Starting _execute_phase6")
        self.phase6_results = self._execute_phase6()

        final_result = self._aggregate_phase_results()
        logger.info("Phased analysis completed")
        return final_result

    def _execute_phase1_skill_bootstrap(self) -> Dict[str, Any]:
        phase_key = "phase1"
        phase_name = "skill_bootstrap"
        started_at = datetime.now().isoformat()
        start_time = time.time()

        prompt = get_phase1_skill_bootstrap_prompt(
            cwd_catalog=self._get_default_cwd_catalog(),
            custom_scan_instructions=self.custom_scan_instructions,
        )
        self.output_manager.save_text("phase1_skill_bootstrap_prompt.txt", prompt)

        response = self.session_manager.send_message(prompt=prompt)
        # self.output_manager.save_json("phase1_skill_bootstrap_response.json", response)
        success, result = self._parse_phase_response(response, "phase1_skill_bootstrap")
        if not success:
            error_payload = {
                "phase": phase_key,
                "name": phase_name,
                "error": "Failed to parse phase response JSON",
                "response": response,
            }
            self.output_manager.save_json("phase1_parse_error.json", error_payload)
            self._save_phase_metadata(
                phase=phase_key,
                name=phase_name,
                status="parse_error",
                started_at=started_at,
                ended_at=datetime.now().isoformat(),
                duration_seconds=time.time() - start_time,
                prompt_file="phase1_skill_bootstrap_prompt.txt",
                response_file="phase1_skill_bootstrap_response.json",
                result_file=None,
                error_message="Failed to parse phase response JSON",
            )
            raise PhaseParseError("phase1 parse failed: invalid JSON response")

        self.output_manager.save_json("phase1_skill_bootstrap_result.json", result)
        self._save_phase_metadata(
            phase=phase_key,
            name=phase_name,
            status="success",
            started_at=started_at,
            ended_at=datetime.now().isoformat(),
            duration_seconds=time.time() - start_time,
            prompt_file="phase1_skill_bootstrap_prompt.txt",
            response_file="phase1_skill_bootstrap_response.json",
            result_file="phase1_skill_bootstrap_result.json",
        )
        return result

    def _execute_phase2(self, pr_data: Dict[str, Any]) -> Dict[str, Any]:
        phase_key = "phase2"
        phase_name = "context_study"
        started_at = datetime.now().isoformat()
        start_time = time.time()

        prompt = get_phase2_context_study_prompt(
            pr_data=pr_data,
            custom_scan_instructions=self.custom_scan_instructions,
        )
        self.output_manager.save_text("phase2_prompt.txt", prompt)

        response = self.session_manager.send_message(prompt=prompt)
        # self.output_manager.save_json("phase2_response.json", response)
        success, result = self._parse_phase_response(response, "phase2")
        if not success:
            error_payload = {
                "phase": phase_key,
                "name": phase_name,
                "error": "Failed to parse phase response JSON",
                "response": response,
            }
            self.output_manager.save_json("phase2_parse_error.json", error_payload)
            self._save_phase_metadata(
                phase=phase_key,
                name=phase_name,
                status="parse_error",
                started_at=started_at,
                ended_at=datetime.now().isoformat(),
                duration_seconds=time.time() - start_time,
                prompt_file="phase2_prompt.txt",
                response_file="phase2_response.json",
                result_file=None,
                error_message="Failed to parse phase response JSON",
            )
            raise PhaseParseError("phase2 parse failed: invalid JSON response")

        self.output_manager.save_json("phase2_result.json", result)
        self._save_phase_metadata(
            phase=phase_key,
            name=phase_name,
            status="success",
            started_at=started_at,
            ended_at=datetime.now().isoformat(),
            duration_seconds=time.time() - start_time,
            prompt_file="phase2_prompt.txt",
            response_file="phase2_response.json",
            result_file="phase2_result.json",
        )
        return result

    def _execute_module_pipeline_phase345(
        self,
        pr_data: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
        phase3_started_at = datetime.now().isoformat()
        phase3_start_time = time.time()
        modules = self.phase2_results.get("modules", [])
        parallelism = min(self._get_phase_parallelism(), max(1, len(modules)))
        cwd_catalog = self._get_default_cwd_catalog()

        if not modules:
            phase3_result = {
                "module_risk_analysis": [],
                "analysis_summary": {
                    "modules_analyzed": 0,
                    "high_risk_count": 0,
                    "medium_risk_count": 0,
                    "low_risk_count": 0,
                    "module_failures": 0,
                },
            }
            phase4_result = {
                "module_cwd_priorities": [],
                "analysis_summary": {
                    "modules_total": 0,
                    "cwd_types_considered": len(cwd_catalog.get("cwd_types", [])),
                    "pairs_selected": 0,
                    "module_failures": 0,
                },
            }
            phase5_result = {
                "module_defects": [],
                "analysis_summary": {
                    "modules_scanned": 0,
                    "total_defects": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "review_completed": True,
                    "module_failures": 0,
                    "modules_with_skill_tool_trace": 0,
                    "modules_without_skill_tool_trace": 0,
                    "defects_with_loaded_verified_skill": 0,
                },
            }
            self.output_manager.save_json("phase3_result.json", phase3_result)
            self.output_manager.save_json("phase4_result.json", phase4_result)
            self.output_manager.save_json("phase5_result.json", phase5_result)
            now = datetime.now().isoformat()
            duration = time.time() - phase3_start_time
            details = {"parallel_workers": 0, "total_modules": 0, "successful_modules": 0, "failed_modules": 0}
            self._save_phase_metadata("phase3", "comparative_analysis", "success", phase3_started_at, now, duration, None, None, "phase3_result.json", details=details)
            self._save_phase_metadata("phase4", "cwd_routing", "success", phase3_started_at, now, duration, None, None, "phase4_result.json", details=details)
            self._save_phase_metadata("phase5", "vulnerability_assessment", "success", phase3_started_at, now, duration, None, None, "phase5_result.json", details=details)
            return phase3_result, phase4_result, phase5_result

        successes: List[Tuple[int, Dict[str, Any], Dict[str, Any], Dict[str, Any]]] = []
        failures: List[Dict[str, Any]] = []

        with ThreadPoolExecutor(max_workers=parallelism) as executor:
            future_map = {
                executor.submit(self._run_single_module_phase345, idx, module, pr_data, cwd_catalog): (idx, module)
                for idx, module in enumerate(modules)
            }
            for future in as_completed(future_map):
                idx, module = future_map[future]
                module_name = module.get("module_name", f"module_{idx}")
                try:
                    successes.append(future.result())
                except Exception as exc:
                    failure = {"index": idx, "module_name": module_name, "error": str(exc)}
                    failures.append(failure)
                    self.output_manager.save_json(f"module_{idx}_phase345_error.json", failure)

        if not successes:
            error_payload = {
                "phase": "phase3",
                "name": "comparative_analysis",
                "error": "All module pipeline tasks failed",
                "module_failures": failures,
            }
            self.output_manager.save_json("phase3_parse_error.json", error_payload)
            duration = time.time() - phase3_start_time
            now = datetime.now().isoformat()
            details = {
                "parallel_workers": parallelism,
                "total_modules": len(modules),
                "successful_modules": 0,
                "failed_modules": len(failures),
            }
            self._save_phase_metadata("phase3", "comparative_analysis", "parse_error", phase3_started_at, now, duration, None, None, None, "All module pipeline tasks failed", details)
            self._save_phase_metadata("phase4", "cwd_routing", "parse_error", phase3_started_at, now, duration, None, None, None, "All module pipeline tasks failed", details)
            self._save_phase_metadata("phase5", "vulnerability_assessment", "parse_error", phase3_started_at, now, duration, None, None, None, "All module pipeline tasks failed", details)
            raise PhaseParseError("phase3-5 failed: all module pipeline tasks failed")

        ordered = sorted(successes, key=lambda x: x[0])
        phase3_items = [item[1] for item in ordered]
        phase4_items = [item[2] for item in ordered]
        phase5_items = [item[3] for item in ordered]

        high_risk = medium_risk = low_risk = 0
        for entry in phase3_items:
            for risk in entry.get("risks", []):
                level = str(risk.get("risk_level", "")).upper()
                if level == "HIGH":
                    high_risk += 1
                elif level == "MEDIUM":
                    medium_risk += 1
                elif level == "LOW":
                    low_risk += 1

        pairs_selected = sum(len(entry.get("cwd_rankings", [])) for entry in phase4_items)

        high = medium = low = total_defects = 0
        modules_with_skill_tool_trace = 0
        modules_without_skill_tool_trace = 0
        defects_with_loaded_verified_skill = 0
        for entry in phase5_items:
            defects = entry.get("defects", [])
            total_defects += len(defects)
            for defect in defects:
                level = str(defect.get("severity", "")).upper()
                if level == "HIGH":
                    high += 1
                elif level == "MEDIUM":
                    medium += 1
                elif level == "LOW":
                    low += 1

                if str(defect.get("skill_load_status", "")) == "loaded_verified":
                    defects_with_loaded_verified_skill += 1

            audit = entry.get("skill_audit", {}) if isinstance(entry, dict) else {}
            if audit.get("skill_tool_observed", False):
                modules_with_skill_tool_trace += 1
            else:
                modules_without_skill_tool_trace += 1

        phase3_result = {
            "module_risk_analysis": phase3_items,
            "analysis_summary": {
                "modules_analyzed": len(phase3_items),
                "high_risk_count": high_risk,
                "medium_risk_count": medium_risk,
                "low_risk_count": low_risk,
                "module_failures": len(failures),
            },
        }
        phase4_result = {
            "module_cwd_priorities": phase4_items,
            "analysis_summary": {
                "modules_total": len(modules),
                "cwd_types_considered": len(cwd_catalog.get("cwd_types", [])),
                "pairs_selected": pairs_selected,
                "module_failures": len(failures),
            },
        }
        phase5_result = {
            "module_defects": phase5_items,
            "analysis_summary": {
                "modules_scanned": len(phase5_items),
                "total_defects": total_defects,
                "high": high,
                "medium": medium,
                "low": low,
                "review_completed": True,
                "module_failures": len(failures),
                "modules_with_skill_tool_trace": modules_with_skill_tool_trace,
                "modules_without_skill_tool_trace": modules_without_skill_tool_trace,
                "defects_with_loaded_verified_skill": defects_with_loaded_verified_skill,
            },
        }

        if failures:
            phase3_result["module_errors"] = failures
            phase4_result["module_errors"] = failures
            phase5_result["module_errors"] = failures

        self.output_manager.save_json("phase3_result.json", phase3_result)
        self.output_manager.save_json("phase4_result.json", phase4_result)
        self.output_manager.save_json("phase5_result.json", phase5_result)

        status = "partial_success" if failures else "success"
        now = datetime.now().isoformat()
        duration = time.time() - phase3_start_time
        details = {
            "parallel_workers": parallelism,
            "total_modules": len(modules),
            "successful_modules": len(phase3_items),
            "failed_modules": len(failures),
        }
        self._save_phase_metadata("phase3", "comparative_analysis", status, phase3_started_at, now, duration, None, None, "phase3_result.json", details=details)
        self._save_phase_metadata("phase4", "cwd_routing", status, phase3_started_at, now, duration, None, None, "phase4_result.json", details=details)
        self._save_phase_metadata("phase5", "vulnerability_assessment", status, phase3_started_at, now, duration, None, None, "phase5_result.json", details=details)

        return phase3_result, phase4_result, phase5_result

    def _execute_phase6(self) -> Dict[str, Any]:
        """Aggregate all module defects into a deduplicated raw list."""
        phase_key = "phase6"
        phase_name = "deduplicate_aggregate"
        started_at = datetime.now().isoformat()
        start_time = time.time()

        module_defects = self.phase5_results.get("module_defects", [])

        all_defects = []
        seen = set()
        for module_entry in module_defects:
            module_name = module_entry.get("module_name", "unknown")
            defects = module_entry.get("defects", [])
            for defect in defects:
                merged = defect.copy()
                merged.setdefault("module_name", module_name)
                merged.setdefault("category", merged.get("defect_type", "unknown"))
                merged.setdefault("severity", str(merged.get("severity", "MEDIUM")).upper())
                merged.setdefault("description", "")
                merged.setdefault("file", "")
                merged.setdefault("line", 0)

                dedup_key = (
                    merged.get("file", ""),
                    merged.get("line", 0),
                    merged.get("defect_type", ""),
                    merged.get("description", ""),
                )
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                all_defects.append(merged)

        phase6 = {
            "all_defects": all_defects,
            "analysis_summary": {
                "total_raw_defects": len(all_defects),
                "deduplicated": True,
            },
        }
        self.output_manager.save_json("phase6_result.json", phase6)
        self._save_phase_metadata(
            phase=phase_key,
            name=phase_name,
            status="success",
            started_at=started_at,
            ended_at=datetime.now().isoformat(),
            duration_seconds=time.time() - start_time,
            prompt_file=None,
            response_file=None,
            result_file="phase6_result.json",
        )
        return phase6

    def _save_phase_metadata(
        self,
        phase: str,
        name: str,
        status: str,
        started_at: str,
        ended_at: str,
        duration_seconds: float,
        prompt_file: Optional[str],
        response_file: Optional[str],
        result_file: Optional[str],
        error_message: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        metadata = {
            "phase": phase,
            "name": name,
            "status": status,
            "started_at": started_at,
            "ended_at": ended_at,
            "duration_seconds": duration_seconds,
            "prompt_file": prompt_file,
            "response_file": response_file,
            "result_file": result_file,
            "error_message": error_message,
        }
        if details is not None:
            metadata["details"] = details
        self.phase_metadata[phase] = metadata
        self.output_manager.save_json(f"{phase}_metadata.json", metadata)

    def _parse_phase_response(self, response: Dict[str, Any], phase_name: str) -> Tuple[bool, Dict[str, Any]]:
        try:
            response_text = ""
            parts = response.get("parts", []) if isinstance(response, dict) else []
            for part in parts:
                if part.get("type") == "text":
                    response_text += part.get("text", "")

            if not response_text:
                logger.warning(f"{phase_name}: empty response")
                return False, {}

            success, result = parse_json_with_fallbacks(response_text, f"{phase_name} response")
            if success and isinstance(result, dict):
                return True, result
            logger.warning(f"{phase_name}: failed to parse JSON")
            return False, {}
        except Exception as exc:
            logger.error(f"{phase_name}: parse error: {exc}")
            return False, {}

    def _aggregate_phase_results(self) -> Dict[str, Any]:
        raw_defects = self.phase6_results.get("all_defects", [])
        high = len([d for d in raw_defects if str(d.get("severity", "")).upper() == "HIGH"])
        medium = len([d for d in raw_defects if str(d.get("severity", "")).upper() == "MEDIUM"])
        low = len([d for d in raw_defects if str(d.get("severity", "")).upper() == "LOW"])

        analysis_summary = {
            "files_reviewed": self.phase5_results.get("analysis_summary", {}).get("modules_scanned", 0),
            "high_severity": high,
            "medium_severity": medium,
            "low_severity": low,
            "total_findings": len(raw_defects),
            "review_completed": True,
            "scan_scope": "full_repository",
            "analysis_session_path": str(self.session_dir),
        }

        final_result = {
            "findings": raw_defects,
            "analysis_summary": analysis_summary,
            "phased_results": {
                "phase1": self.phase1_skill_bootstrap_results,
                "phase2": self.phase2_results,
                "phase3": self.phase3_results,
                "phase4": self.phase4_results,
                "phase5": self.phase5_results,
                "phase6": self.phase6_results,
            },
            "phase_metadata": self.phase_metadata,
        }

        self.output_manager.save_json("final_result.json", final_result)
        return final_result

    def _get_phase2_fallback(self) -> Dict[str, Any]:
        result = {
            "modules": [],
            "analysis_summary": {
                "repository_type": "unknown",
                "primary_languages": [],
                "architecture_style": "unknown",
                "total_modules": 0,
                "notes": ["phase2 parsing failed; fallback used"],
            },
        }
        self.output_manager.save_json("phase2_fallback.json", result)
        return result

    def _get_phase1_skill_bootstrap_fallback(self) -> Dict[str, Any]:
        result = {
            "skill_bootstrap_status": "fallback",
            "skills_requested": [],
            "skills_loaded": [],
            "skills_missing": [],
            "notes": ["phase1 skill bootstrap parsing failed; fallback used"],
        }
        self.output_manager.save_json("phase1_skill_bootstrap_fallback.json", result)
        return result

    def _get_phase3_fallback(self) -> Dict[str, Any]:
        result = {
            "module_risk_analysis": [],
            "analysis_summary": {
                "modules_analyzed": 0,
                "high_risk_count": 0,
                "medium_risk_count": 0,
                "low_risk_count": 0,
            },
        }
        self.output_manager.save_json("phase3_fallback.json", result)
        return result

    def _get_phase4_fallback(self) -> Dict[str, Any]:
        result = {
            "module_cwd_priorities": [],
            "analysis_summary": {
                "modules_total": 0,
                "cwd_types_considered": 0,
                "pairs_selected": 0,
            },
        }
        self.output_manager.save_json("phase4_fallback.json", result)
        return result

    def _get_phase5_fallback(self) -> Dict[str, Any]:
        result = {
            "module_defects": [],
            "analysis_summary": {
                "modules_scanned": 0,
                "total_defects": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "review_completed": True,
            },
        }
        self.output_manager.save_json("phase5_fallback.json", result)
        return result

    def get_session_info(self) -> Dict[str, Any]:
        return {
            "session_path": str(self.session_dir),
            "phase1_completed": bool(self.phase1_skill_bootstrap_results),
            "phase2_completed": bool(self.phase2_results),
            "phase3_completed": bool(self.phase3_results),
            "phase4_completed": bool(self.phase4_results),
            "phase5_completed": bool(self.phase5_results),
            "phase6_completed": bool(self.phase6_results),
            "session_files": [
                f.name for f in self.session_dir.glob("*") if f.is_file()
            ] if self.session_dir.exists() else [],
        }

    def _get_default_cwd_catalog(self) -> Dict[str, Any]:
        """Load CWD catalog from file with fallback."""
        catalog_path = Path(__file__).with_name("cwd_catalog.json")
        try:
            with open(catalog_path, "r", encoding="utf-8") as f:
                parsed = json.load(f)
            if isinstance(parsed, dict) and isinstance(parsed.get("cwd_types"), list):
                return parsed
            logger.warning(f"Invalid cwd catalog format in {catalog_path}, using fallback")
        except Exception as exc:
            logger.warning(f"Failed to load cwd catalog from {catalog_path}: {exc}. Using fallback")

        return {
            "version": "fallback-v1",
            "cwd_types": [
                {
                    "cwd_id": "CWD-1030",
                    "name": "访问未初始化的指针",
                    "skill_name": "CWD-1030",
                },
                {
                    "cwd_id": "CWD-1031",
                    "name": "空指针解引用",
                    "skill_name": "CWD-1031",
                },
            ],
        }
