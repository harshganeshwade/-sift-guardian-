"""Analysis Planner

Plans the sequence of forensic tools to execute based on:
- Case description
- Evidence types available
- Senior analyst thinking patterns
- Self-correction feedback
"""

from typing import Any, Dict, List, Optional
from pathlib import Path
from enum import Enum


class AnalysisPhase(Enum):
    """Analysis phases in order of execution."""
    TRIAGE = "triage"
    EVIDENCE_COLLECTION = "evidence_collection"
    DEEP_ANALYSIS = "deep_analysis"
    CORRELATION = "correlation"
    VALIDATION = "validation"
    REPORTING = "reporting"


class AnalysisPlanner:
    """
    Plans forensic analysis workflow like a senior analyst.
    
    Senior analyst thinking patterns:
    1. Start with broad triage to understand scope
    2. Collect evidence systematically
    3. Deep dive into specific areas of concern
    4. Correlate findings across multiple sources
    5. Validate findings before reporting
    """
    
    def __init__(self):
        # Define tool sequences for each phase
        self.phase_tools = {
            AnalysisPhase.TRIAGE: [
                {"tool": "get_system_info", "priority": 1, "category": "system"},
                {"tool": "calculate_file_hash", "priority": 2, "category": "file_analysis"},
            ],
            AnalysisPhase.EVIDENCE_COLLECTION: [
                {"tool": "volatility_processes", "priority": 1, "category": "memory"},
                {"tool": "volatility_network", "priority": 2, "category": "memory"},
                {"tool": "mft_timeline", "priority": 3, "category": "disk"},
                {"tool": "extract_amcache", "priority": 4, "category": "disk"},
                {"tool": "extract_prefetch", "priority": 5, "category": "disk"},
                {"tool": "parse_event_logs", "priority": 6, "category": "logs"},
            ],
            AnalysisPhase.DEEP_ANALYSIS: [
                {"tool": "volatility_dlls", "priority": 1, "category": "memory"},
                {"tool": "volatility_handles", "priority": 2, "category": "memory"},
                {"tool": "extract_registry", "priority": 3, "category": "disk"},
                {"tool": "extract_usn_journal", "priority": 4, "category": "disk"},
                {"tool": "parse_powershell_logs", "priority": 5, "category": "logs"},
                {"tool": "analyze_browser_history", "priority": 6, "category": "logs"},
            ],
            AnalysisPhase.CORRELATION: [
                {"tool": "create_super_timeline", "priority": 1, "category": "timeline"},
                {"tool": "query_timeline", "priority": 2, "category": "timeline"},
            ],
            AnalysisPhase.VALIDATION: [
                {"tool": "analyze_pcap", "priority": 1, "category": "network"},
                {"tool": "extract_dns_from_pcap", "priority": 2, "category": "network"},
                {"tool": "extract_http_from_pcap", "priority": 3, "category": "network"},
                {"tool": "bulk_extract", "priority": 4, "category": "file_analysis"},
            ],
            AnalysisPhase.REPORTING: []  # No tools needed for reporting
        }
        
        # Tool category mapping
        self.tool_categories = {
            "memory": ["volatility_processes", "volatility_network", "volatility_dlls", "volatility_handles"],
            "disk": ["mft_timeline", "extract_amcache", "extract_prefetch", "extract_registry", "extract_usn_journal"],
            "logs": ["parse_event_logs", "parse_powershell_logs", "analyze_browser_history"],
            "network": ["analyze_pcap", "extract_dns_from_pcap", "extract_http_from_pcap"],
            "timeline": ["create_super_timeline", "query_timeline"],
            "file_analysis": ["bulk_extract", "calculate_file_hash"],
            "system": ["get_system_info"]
        }
    
    def create_plan(self, case_description: str, evidence_path: Path) -> Dict[str, Any]:
        """
        Create an analysis plan based on case description and evidence.
        
        Args:
            case_description: Description of the case or analysis request
            evidence_path: Path to evidence directory
            
        Returns:
            Analysis plan with phases and tools
        """
        # Detect evidence types from path
        evidence_types = self._detect_evidence_types(evidence_path)
        
        # Create phase-based plan
        plan = {
            "case_description": case_description,
            "evidence_path": str(evidence_path),
            "evidence_types": evidence_types,
            "current_phase": AnalysisPhase.TRIAGE.value,
            "remaining_phases": [p.value for p in AnalysisPhase],
            "phases": {}
        }
        
        # Generate tools for each phase based on evidence
        for phase in AnalysisPhase:
            phase_tools = self._select_tools_for_phase(phase, evidence_types, case_description)
            plan["phases"][phase.value] = {
                "tools": phase_tools,
                "completed": False
            }
        
        return plan
    
    def _detect_evidence_types(self, evidence_path: Path) -> List[str]:
        """Detect evidence types from the evidence directory."""
        evidence_types = []
        
        if not evidence_path.exists():
            return ["unknown"]
        
        # Check for common evidence files
        for item in evidence_path.rglob("*"):
            name = item.name.lower()
            
            # Memory images
            if any(ext in name for ext in [".raw", ".mem", ".vmem", ".dmp"]):
                evidence_types.append("memory")
            
            # Disk images
            if any(ext in name for ext in [".e01", ".dd", ".img", ".iso", ".vmdk", ".vhd"]):
                evidence_types.append("disk")
            
            # MFT
            if "$mft" in name:
                evidence_types.append("mft")
            
            # Registry hives
            if any(hive in name for hive in ["system", "software", "sam", "security", "ntuser"]):
                evidence_types.append("registry")
            
            # Event logs
            if name.endswith(".evtx"):
                evidence_types.append("event_logs")
            
            # Network captures
            if any(ext in name for ext in [".pcap", ".pcapng"]):
                evidence_types.append("network")
            
            # Prefetch
            if name.endswith(".pf"):
                evidence_types.append("prefetch")
        
        return list(set(evidence_types)) if evidence_types else ["unknown"]
    
    def _select_tools_for_phase(self, phase: AnalysisPhase, 
                                 evidence_types: List[str],
                                 case_description: str) -> List[Dict[str, Any]]:
        """Select appropriate tools for a phase based on evidence and case."""
        base_tools = self.phase_tools.get(phase, [])
        selected_tools = []
        
        for tool_def in base_tools:
            # Check if tool category matches evidence types
            if self._tool_category_relevant(tool_def["category"], evidence_types):
                # Build arguments based on evidence
                arguments = self._build_tool_arguments(tool_def, evidence_types, case_description)
                selected_tools.append({
                    "tool": tool_def["tool"],
                    "arguments": arguments,
                    "priority": tool_def["priority"]
                })
        
        # Sort by priority
        selected_tools.sort(key=lambda x: x["priority"])
        
        return selected_tools
    
    def _tool_category_relevant(self, category: str, evidence_types: List[str]) -> bool:
        """Check if a tool category is relevant given the evidence types."""
        # Map evidence types to relevant tool categories
        relevance_map = {
            "memory": ["memory"],
            "disk": ["disk", "file_analysis"],
            "mft": ["disk"],
            "registry": ["disk"],
            "event_logs": ["logs"],
            "network": ["network"],
            "prefetch": ["disk"],
            "unknown": ["memory", "disk", "logs", "network", "file_analysis", "timeline"]
        }
        
        relevant_categories = set()
        for evidence_type in evidence_types:
            relevant_categories.update(relevance_map.get(evidence_type, []))
        
        return category in relevant_categories
    
    def _build_tool_arguments(self, tool_def: Dict[str, Any],
                              evidence_types: List[str],
                              case_description: str) -> Dict[str, Any]:
        """Build arguments for a tool based on evidence and case."""
        arguments = {}
        tool_name = tool_def["tool"]
        
        # Memory tools
        if tool_name.startswith("volatility"):
            arguments["memory_image"] = "/evidence/memory.raw"
            arguments["profile"] = "Win7SP1x64"  # Default profile
        
        # Disk tools
        elif tool_name == "mft_timeline":
            arguments["mft_path"] = "/evidence/$MFT"
        elif tool_name == "extract_amcache":
            arguments["amcache_path"] = "/evidence/Amcache.hve"
        elif tool_name == "extract_prefetch":
            arguments["prefetch_path"] = "/evidence/Windows/Prefetch"
        elif tool_name == "extract_registry":
            arguments["registry_path"] = "/evidence/Windows/System32/config/SYSTEM"
            arguments["hive_type"] = "system"
        elif tool_name == "extract_usn_journal":
            arguments["usn_path"] = "/evidence/$UsnJrnl"
        
        # Log tools
        elif tool_name == "parse_event_logs":
            arguments["evtx_path"] = "/evidence/Windows/System32/winevt/Logs"
        elif tool_name == "parse_powershell_logs":
            arguments["log_path"] = "/evidence/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx"
        elif tool_name == "analyze_browser_history":
            arguments["browser_path"] = "/evidence/Users"
        
        # Network tools
        elif tool_name in ["analyze_pcap", "extract_dns_from_pcap", "extract_http_from_pcap"]:
            arguments["pcap_path"] = "/evidence/capture.pcap"
        
        # Timeline tools
        elif tool_name == "create_super_timeline":
            arguments["source_path"] = "/evidence"
            arguments["output_path"] = "/output/timeline.plaso"
        elif tool_name == "query_timeline":
            arguments["storage_path"] = "/output/timeline.plaso"
        
        # File analysis tools
        elif tool_name == "bulk_extract":
            arguments["input_path"] = "/evidence"
            arguments["output_dir"] = "/output/bulk"
        elif tool_name == "calculate_file_hash":
            arguments["file_path"] = "/evidence"
        
        # System tools
        elif tool_name == "get_system_info":
            arguments["hive_path"] = "/evidence/Windows/System32/config/SYSTEM"
        
        return arguments
    
    def revise_plan(self, plan: Dict[str, Any], 
                   corrections: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Revise analysis plan based on self-correction feedback.
        
        This implements senior analyst thinking:
        - When something doesn't add up, dig deeper
        - When a tool fails, try alternative approaches
        - When findings conflict, investigate further
        """
        current_phase = plan.get("current_phase")
        
        for correction in corrections:
            issue_type = correction.get("type")
            
            if issue_type == "tool_failure":
                # Add alternative tool
                alternative = correction.get("alternative")
                if alternative:
                    plan["phases"][current_phase]["tools"].append({
                        "tool": alternative,
                        "arguments": correction.get("arguments", {}),
                        "priority": 99  # High priority for alternatives
                    })
            
            elif issue_type == "missing_evidence":
                # Add evidence collection step
                evidence_type = correction.get("evidence_type")
                plan["phases"][current_phase]["tools"].insert(0, {
                    "tool": f"extract_{evidence_type}",
                    "arguments": correction.get("arguments", {}),
                    "priority": 0  # Highest priority
                })
            
            elif issue_type == "inconsistency":
                # Add validation step
                plan["phases"]["validation"]["tools"].append({
                    "tool": correction.get("validation_tool", "calculate_file_hash"),
                    "arguments": correction.get("arguments", {}),
                    "priority": 0
                })
        
        return plan
    
    def get_phase_tools(self, phase: AnalysisPhase) -> List[Dict[str, Any]]:
        """Get tools for the current phase."""
        return self.phase_tools.get(phase, [])
    
    def add_validation_steps(self, plan: Dict[str, Any], 
                            gaps: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Add validation steps to address gaps in findings."""
        for gap in gaps:
            missing_type = gap.get("missing")
            
            if missing_type == "corroborating evidence":
                # Add cross-reference tools
                plan["phases"]["validation"]["tools"].append({
                    "tool": "bulk_extract",
                    "arguments": {"input_path": "/evidence"},
                    "priority": 0
                })
        
        return plan
