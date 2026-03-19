"""Phased security analyzer for full-repository multi-stage workflow."""

import json
from pathlib import Path
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
        prompt = get_phase1_skill_bootstrap_prompt(
            cwd_catalog=self._get_default_cwd_catalog(),
            custom_scan_instructions=self.custom_scan_instructions,
        )
        self.output_manager.save_text("phase1_skill_bootstrap_prompt.txt", prompt)

        response = self.session_manager.send_message(prompt=prompt)
        success, result = self._parse_phase_response(response, "phase1_skill_bootstrap")
        if not success:
            result = self._get_phase1_skill_bootstrap_fallback()

        self.output_manager.save_json("phase1_skill_bootstrap_response.json", response)
        self.output_manager.save_json("phase1_skill_bootstrap_result.json", result)
        return result

    def _execute_phase2(self, pr_data: Dict[str, Any]) -> Dict[str, Any]:
        prompt = get_phase2_context_study_prompt(
            pr_data=pr_data,
            custom_scan_instructions=self.custom_scan_instructions,
        )
        self.output_manager.save_text("phase2_prompt.txt", prompt)

        response = self.session_manager.send_message(prompt=prompt)
        success, result = self._parse_phase_response(response, "phase2")
        if not success:
            result = self._get_phase2_fallback()

        self.output_manager.save_json("phase2_response.json", response)
        self.output_manager.save_json("phase2_result.json", result)
        return result

    def _execute_phase3(self, pr_data: Dict[str, Any]) -> Dict[str, Any]:
        prompt = get_phase3_comparative_analysis_prompt(
            pr_data=pr_data,
            phase2_results=self.phase2_results,
            custom_scan_instructions=self.custom_scan_instructions,
        )
        self.output_manager.save_text("phase3_prompt.txt", prompt)

        response = self.session_manager.send_message(prompt=prompt)
        success, result = self._parse_phase_response(response, "phase3")
        if not success:
            result = self._get_phase3_fallback()

        self.output_manager.save_json("phase3_response.json", response)
        self.output_manager.save_json("phase3_result.json", result)
        return result

    def _execute_phase4(self, pr_data: Dict[str, Any]) -> Dict[str, Any]:
        prompt = get_phase4_cwd_routing_prompt(
            pr_data=pr_data,
            phase2_results=self.phase2_results,
            phase3_results=self.phase3_results,
            cwd_catalog=self._get_default_cwd_catalog(),
            custom_scan_instructions=self.custom_scan_instructions,
        )
        self.output_manager.save_text("phase4_prompt.txt", prompt)

        response = self.session_manager.send_message(prompt=prompt)
        success, result = self._parse_phase_response(response, "phase4")
        if not success:
            result = self._get_phase4_fallback()

        self.output_manager.save_json("phase4_response.json", response)
        self.output_manager.save_json("phase4_result.json", result)
        return result

    def _execute_phase5(self, pr_data: Dict[str, Any]) -> Dict[str, Any]:
        prompt = get_phase5_vulnerability_assessment_prompt(
            pr_data=pr_data,
            phase2_results=self.phase2_results,
            phase3_results=self.phase3_results,
            phase4_results=self.phase4_results,
            custom_scan_instructions=self.custom_scan_instructions,
        )
        self.output_manager.save_text("phase5_prompt.txt", prompt)

        response = self.session_manager.send_message(prompt=prompt)
        success, result = self._parse_phase_response(response, "phase5")
        if not success:
            result = self._get_phase5_fallback()

        self.output_manager.save_json("phase5_response.json", response)
        self.output_manager.save_json("phase5_result.json", result)
        return result

    def _execute_phase6(self) -> Dict[str, Any]:
        """Aggregate all module defects into a deduplicated raw list."""
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
        return phase6

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
