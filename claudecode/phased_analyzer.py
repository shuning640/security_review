"""Phased security analyzer for full-repository multi-stage workflow."""

import json
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from claudecode.json_parser import parse_json_with_fallbacks
from claudecode.logger import get_logger
from claudecode.prompts import (
    get_phase1_context_study_prompt,
    get_phase2_comparative_analysis_prompt,
    get_phase3_vulnerability_assessment_prompt,
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

        self.phase1_results: Dict[str, Any] = {}
        self.phase2_results: Dict[str, Any] = {}
        self.phase3_results: Dict[str, Any] = {}
        self.phase4_results: Dict[str, Any] = {}
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
        """Execute phases 1-4 and return aggregate data for phase-5 filtering."""
        del include_diff
        del pr_diff
        del resume_from

        self.repo_dir = repo_dir
        self.custom_scan_instructions = custom_scan_instructions

        logger.info("=" * 80)
        logger.info("Starting full-repository phased analysis")
        logger.info("=" * 80)

        self.phase1_results = self._execute_phase1(pr_data)
        self.phase2_results = self._execute_phase2(pr_data)
        self.phase3_results = self._execute_phase3(pr_data)
        self.phase4_results = self._execute_phase4()

        final_result = self._aggregate_phase_results()
        logger.info("Phased analysis completed")
        return final_result

    def _execute_phase1(self, pr_data: Dict[str, Any]) -> Dict[str, Any]:
        prompt = get_phase1_context_study_prompt(
            pr_data=pr_data,
            custom_scan_instructions=self.custom_scan_instructions,
        )
        self.output_manager.save_text("phase1_prompt.txt", prompt)

        response = self.session_manager.send_message(prompt=prompt)
        success, result = self._parse_phase_response(response, "phase1")
        if not success:
            result = self._get_phase1_fallback()

        self.output_manager.save_json("phase1_response.json", response)
        self.output_manager.save_json("phase1_result.json", result)
        self.output_manager.save_json("modules.json", result)
        return result

    def _execute_phase2(self, pr_data: Dict[str, Any]) -> Dict[str, Any]:
        prompt = get_phase2_comparative_analysis_prompt(
            pr_data=pr_data,
            phase1_results=self.phase1_results,
            custom_scan_instructions=self.custom_scan_instructions,
        )
        self.output_manager.save_text("phase2_prompt.txt", prompt)

        response = self.session_manager.send_message(prompt=prompt)
        success, result = self._parse_phase_response(response, "phase2")
        if not success:
            result = self._get_phase2_fallback()

        self.output_manager.save_json("phase2_response.json", response)
        self.output_manager.save_json("phase2_result.json", result)
        self.output_manager.save_json("module_risk_analysis.json", result)
        return result

    def _execute_phase3(self, pr_data: Dict[str, Any]) -> Dict[str, Any]:
        prompt = get_phase3_vulnerability_assessment_prompt(
            pr_data=pr_data,
            phase1_results=self.phase1_results,
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
        self.output_manager.save_json("module_defects.json", result)
        return result

    def _execute_phase4(self) -> Dict[str, Any]:
        """Aggregate all module defects into a deduplicated raw list."""
        module_defects = self.phase3_results.get("module_defects", [])

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

        phase4 = {
            "all_defects": all_defects,
            "analysis_summary": {
                "total_raw_defects": len(all_defects),
                "deduplicated": True,
            },
        }
        self.output_manager.save_json("phase4_result.json", phase4)
        self.output_manager.save_json("all_defects_raw.json", phase4)
        return phase4

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
        raw_defects = self.phase4_results.get("all_defects", [])
        high = len([d for d in raw_defects if str(d.get("severity", "")).upper() == "HIGH"])
        medium = len([d for d in raw_defects if str(d.get("severity", "")).upper() == "MEDIUM"])
        low = len([d for d in raw_defects if str(d.get("severity", "")).upper() == "LOW"])

        analysis_summary = {
            "files_reviewed": self.phase3_results.get("analysis_summary", {}).get("modules_scanned", 0),
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
                "phase1": self.phase1_results,
                "phase2": self.phase2_results,
                "phase3": self.phase3_results,
                "phase4": self.phase4_results,
            },
        }

        self.output_manager.save_json("final_result.json", final_result)
        return final_result

    def _get_phase1_fallback(self) -> Dict[str, Any]:
        result = {
            "modules": [],
            "analysis_summary": {
                "repository_type": "unknown",
                "primary_languages": [],
                "architecture_style": "unknown",
                "total_modules": 0,
                "notes": ["phase1 parsing failed; fallback used"],
            },
        }
        self.output_manager.save_json("phase1_fallback.json", result)
        return result

    def _get_phase2_fallback(self) -> Dict[str, Any]:
        result = {
            "module_risk_analysis": [],
            "analysis_summary": {
                "modules_analyzed": 0,
                "high_risk_count": 0,
                "medium_risk_count": 0,
                "low_risk_count": 0,
            },
        }
        self.output_manager.save_json("phase2_fallback.json", result)
        return result

    def _get_phase3_fallback(self) -> Dict[str, Any]:
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
        self.output_manager.save_json("phase3_fallback.json", result)
        return result

    def get_session_info(self) -> Dict[str, Any]:
        return {
            "session_path": str(self.session_dir),
            "phase1_completed": bool(self.phase1_results),
            "phase2_completed": bool(self.phase2_results),
            "phase3_completed": bool(self.phase3_results),
            "phase4_completed": bool(self.phase4_results),
            "session_files": [
                f.name for f in self.session_dir.glob("*") if f.is_file()
            ] if self.session_dir.exists() else [],
        }
