"""Phased security analyzer for full-repository multi-stage workflow."""

import json
import time
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

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
        logger.info("Starting _execute_phase3")
        self.phase3_results = self._execute_phase3(pr_data)
        logger.info("Starting _execute_phase4")
        self.phase4_results = self._execute_phase4(pr_data)
        logger.info("Starting _execute_phase5")
        self.phase5_results = self._execute_phase5(pr_data)
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
        self.output_manager.save_json("phase1_skill_bootstrap_response.json", response)
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
        self.output_manager.save_json("phase2_response.json", response)
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

    def _execute_phase3(self, pr_data: Dict[str, Any]) -> Dict[str, Any]:
        phase_key = "phase3"
        phase_name = "comparative_analysis"
        started_at = datetime.now().isoformat()
        start_time = time.time()
        phase2_modules_context = {
            "modules": self.phase2_results.get("modules", [])
        }

        prompt = get_phase3_comparative_analysis_prompt(
            pr_data=pr_data,
            phase2_results=phase2_modules_context,
            custom_scan_instructions=self.custom_scan_instructions,
        )
        self.output_manager.save_text("phase3_prompt.txt", prompt)

        response = self.session_manager.send_message(prompt=prompt)
        self.output_manager.save_json("phase3_response.json", response)
        success, result = self._parse_phase_response(response, "phase3")
        if not success:
            error_payload = {
                "phase": phase_key,
                "name": phase_name,
                "error": "Failed to parse phase response JSON",
                "response": response,
            }
            self.output_manager.save_json("phase3_parse_error.json", error_payload)
            self._save_phase_metadata(
                phase=phase_key,
                name=phase_name,
                status="parse_error",
                started_at=started_at,
                ended_at=datetime.now().isoformat(),
                duration_seconds=time.time() - start_time,
                prompt_file="phase3_prompt.txt",
                response_file="phase3_response.json",
                result_file=None,
                error_message="Failed to parse phase response JSON",
            )
            raise PhaseParseError("phase3 parse failed: invalid JSON response")

        self.output_manager.save_json("phase3_result.json", result)
        self._save_phase_metadata(
            phase=phase_key,
            name=phase_name,
            status="success",
            started_at=started_at,
            ended_at=datetime.now().isoformat(),
            duration_seconds=time.time() - start_time,
            prompt_file="phase3_prompt.txt",
            response_file="phase3_response.json",
            result_file="phase3_result.json",
        )
        return result

    def _execute_phase4(self, pr_data: Dict[str, Any]) -> Dict[str, Any]:
        phase_key = "phase4"
        phase_name = "cwd_routing"
        started_at = datetime.now().isoformat()
        start_time = time.time()
        phase2_modules_context = {
            "modules": self.phase2_results.get("modules", [])
        }
        phase3_risks_context = {
            "module_risk_analysis": self.phase3_results.get("module_risk_analysis", [])
        }

        prompt = get_phase4_cwd_routing_prompt(
            pr_data=pr_data,
            phase2_results=phase2_modules_context,
            phase3_results=phase3_risks_context,
            cwd_catalog=self._get_default_cwd_catalog(),
            custom_scan_instructions=self.custom_scan_instructions,
        )
        self.output_manager.save_text("phase4_prompt.txt", prompt)

        response = self.session_manager.send_message(prompt=prompt)
        self.output_manager.save_json("phase4_response.json", response)
        success, result = self._parse_phase_response(response, "phase4")
        if not success:
            error_payload = {
                "phase": phase_key,
                "name": phase_name,
                "error": "Failed to parse phase response JSON",
                "response": response,
            }
            self.output_manager.save_json("phase4_parse_error.json", error_payload)
            self._save_phase_metadata(
                phase=phase_key,
                name=phase_name,
                status="parse_error",
                started_at=started_at,
                ended_at=datetime.now().isoformat(),
                duration_seconds=time.time() - start_time,
                prompt_file="phase4_prompt.txt",
                response_file="phase4_response.json",
                result_file=None,
                error_message="Failed to parse phase response JSON",
            )
            raise PhaseParseError("phase4 parse failed: invalid JSON response")

        self.output_manager.save_json("phase4_result.json", result)
        self._save_phase_metadata(
            phase=phase_key,
            name=phase_name,
            status="success",
            started_at=started_at,
            ended_at=datetime.now().isoformat(),
            duration_seconds=time.time() - start_time,
            prompt_file="phase4_prompt.txt",
            response_file="phase4_response.json",
            result_file="phase4_result.json",
        )
        return result

    def _execute_phase5(self, pr_data: Dict[str, Any]) -> Dict[str, Any]:
        phase_key = "phase5"
        phase_name = "vulnerability_assessment"
        started_at = datetime.now().isoformat()
        start_time = time.time()
        phase2_modules_context = {
            "modules": self.phase2_results.get("modules", [])
        }
        phase3_risks_context = {
            "module_risk_analysis": self.phase3_results.get("module_risk_analysis", [])
        }
        phase4_routing_context = {
            "module_cwd_priorities": self.phase4_results.get("module_cwd_priorities", [])
        }

        prompt = get_phase5_vulnerability_assessment_prompt(
            pr_data=pr_data,
            phase2_results=phase2_modules_context,
            phase3_results=phase3_risks_context,
            phase4_results=phase4_routing_context,
            custom_scan_instructions=self.custom_scan_instructions,
        )
        self.output_manager.save_text("phase5_prompt.txt", prompt)

        response = self.session_manager.send_message(prompt=prompt)
        self.output_manager.save_json("phase5_response.json", response)
        success, result = self._parse_phase_response(response, "phase5")
        if not success:
            error_payload = {
                "phase": phase_key,
                "name": phase_name,
                "error": "Failed to parse phase response JSON",
                "response": response,
            }
            self.output_manager.save_json("phase5_parse_error.json", error_payload)
            self._save_phase_metadata(
                phase=phase_key,
                name=phase_name,
                status="parse_error",
                started_at=started_at,
                ended_at=datetime.now().isoformat(),
                duration_seconds=time.time() - start_time,
                prompt_file="phase5_prompt.txt",
                response_file="phase5_response.json",
                result_file=None,
                error_message="Failed to parse phase response JSON",
            )
            raise PhaseParseError("phase5 parse failed: invalid JSON response")

        self.output_manager.save_json("phase5_result.json", result)
        self._save_phase_metadata(
            phase=phase_key,
            name=phase_name,
            status="success",
            started_at=started_at,
            ended_at=datetime.now().isoformat(),
            duration_seconds=time.time() - start_time,
            prompt_file="phase5_prompt.txt",
            response_file="phase5_response.json",
            result_file="phase5_result.json",
        )
        return result

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
