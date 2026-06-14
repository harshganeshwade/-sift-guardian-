"""Self-Correction Engine

Implements senior analyst thinking patterns for self-correction:
- Recognizes when findings don't add up
- Identifies gaps in analysis
- Suggests alternative approaches when tools fail
- Detects potential hallucinations
"""

from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime
import logging

from ..validation.accuracy import Finding

logger = logging.getLogger(__name__)


class SelfCorrectionEngine:
    """
    Implements self-correction based on senior analyst thinking patterns.
    
    A senior analyst:
    1. Questions their own assumptions
    2. Looks for inconsistencies in findings
    3. When something doesn't add up, digs deeper
    4. Validates findings against multiple sources
    5. Recognizes when they're wrong and adjusts
    """
    
    def __init__(self):
        self.correction_history: List[Dict[str, Any]] = []
        
        # Define consistency rules
        self.consistency_rules = {
            # Memory and disk should corroborate each other
            ("suspicious_process", "file_system_activity"): {
                "description": "Suspicious process should have corresponding file activity",
                "validation_tool": "mft_timeline",
                "severity": "high"
            },
            # Network activity should have DNS/HTTP evidence
            ("network_activity", "dns_activity"): {
                "description": "Network connections should have DNS resolution",
                "validation_tool": "extract_dns_from_pcap",
                "severity": "medium"
            },
            # PowerShell execution should have process evidence
            ("powershell_activity", "suspicious_process"): {
                "description": "PowerShell commands should appear in process list",
                "validation_tool": "volatility_processes",
                "severity": "high"
            },
            # Application execution should have prefetch evidence
            ("application_execution", "file_system_activity"): {
                "description": "Executed applications should have prefetch files",
                "validation_tool": "extract_prefetch",
                "severity": "medium"
            }
        }
        
        # Define hallucination indicators
        self.hallucination_indicators = [
            "finding not supported by evidence",
            "confidence too high without corroboration",
            "conflicting evidence ignored",
            "timestamp inconsistencies",
            "impossible file system state"
        ]
    
    def analyze_results(self, phase_result: Dict[str, Any], 
                       current_findings: List[Finding]) -> List[Dict[str, Any]]:
        """
        Analyze phase results and findings for issues requiring correction.
        
        Returns list of corrections needed.
        """
        corrections = []
        
        # Check for tool failures
        tool_failures = phase_result.get("errors", [])
        for failure in tool_failures:
            correction = self._handle_tool_failure(failure)
            if correction:
                corrections.append(correction)
        
        # Check for inconsistencies in findings
        inconsistencies = self._check_consistency(current_findings)
        corrections.extend(inconsistencies)
        
        # Check for potential hallucinations
        hallucinations = self._detect_hallucinations(current_findings)
        corrections.extend(hallucinations)
        
        # Check for gaps in analysis
        gaps = self._identify_gaps(current_findings)
        corrections.extend(gaps)
        
        # Log corrections
        if corrections:
            self._log_corrections(corrections)
        
        return corrections
    
    def _handle_tool_failure(self, failure: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle tool execution failures with alternative approaches."""
        tool_name = failure.get("tool")
        error = failure.get("error", "")
        
        # Define alternative tools for common failures
        alternatives = {
            "volatility_processes": {
                "alternative": "volatility_dlls",
                "reason": "Process listing failed, trying DLL list instead",
                "arguments": {"memory_image": "/evidence/memory.raw", "profile": "Win7SP1x64"}
            },
            "mft_timeline": {
                "alternative": "extract_usn_journal",
                "reason": "MFT parsing failed, trying USN Journal",
                "arguments": {"usn_path": "/evidence/$UsnJrnl"}
            },
            "parse_event_logs": {
                "alternative": "parse_powershell_logs",
                "reason": "Event log parsing failed, focusing on PowerShell logs",
                "arguments": {"log_path": "/evidence/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx"}
            },
            "analyze_pcap": {
                "alternative": "extract_dns_from_pcap",
                "reason": "Full PCAP analysis failed, extracting DNS only",
                "arguments": {"pcap_path": "/evidence/capture.pcap"}
            }
        }
        
        alt = alternatives.get(tool_name)
        if alt:
            return {
                "type": "tool_failure",
                "tool": tool_name,
                "error": error,
                "alternative": alt["alternative"],
                "arguments": alt["arguments"],
                "reason": alt["reason"]
            }
        
        return None
    
    def _check_consistency(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Check findings for consistency across sources."""
        corrections = []
        
        for i, finding1 in enumerate(findings):
            for j, finding2 in enumerate(findings):
                if i >= j:
                    continue
                
                # Check if findings should corroborate each other
                rule_key = (finding1.category, finding2.category)
                reverse_key = (finding2.category, finding1.category)
                
                rule = self.consistency_rules.get(rule_key) or self.consistency_rules.get(reverse_key)
                
                if rule:
                    # Check if corroboration exists
                    if not self._are_findings_corroborated(finding1, finding2, findings):
                        corrections.append({
                            "type": "inconsistency",
                            "description": rule["description"],
                            "finding1": finding1.category,
                            "finding2": finding2.category,
                            "validation_tool": rule["validation_tool"],
                            "severity": rule["severity"],
                            "arguments": self._get_validation_arguments(rule["validation_tool"])
                        })
        
        return corrections
    
    def _are_findings_corroborated(self, finding1: Finding, finding2: Finding,
                                   all_findings: List[Finding]) -> bool:
        """Check if two findings are corroborated by evidence."""
        # Simple heuristic: findings are corroborated if they share evidence sources
        # or if there are other findings linking them
        
        # Check for direct corroboration
        if finding1.evidence_source == finding2.evidence_source:
            return True
        
        # Check for indirect corroboration through other findings
        for other in all_findings:
            if other.finding_id in [finding1.finding_id, finding2.finding_id]:
                continue
            
            # If another finding references both, consider them corroborated
            if (other.category == finding1.category or 
                other.category == finding2.category):
                if other.confidence > 0.7:
                    return True
        
        return False
    
    def _detect_hallucinations(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Detect potential hallucinations in findings."""
        corrections = []
        
        for finding in findings:
            # Check for unsupported findings
            if not finding.raw_evidence or len(finding.raw_evidence) < 10:
                corrections.append({
                    "type": "hallucination",
                    "description": f"Finding '{finding.category}' lacks supporting evidence",
                    "finding": finding.category,
                    "severity": "high",
                    "suggestion": "Re-run analysis with different tool or verify evidence"
                })
            
            # Check for unrealistic confidence
            if finding.confidence > 0.9 and not self._has_strong_corroboration(finding, findings):
                corrections.append({
                    "type": "hallucination",
                    "description": f"Finding '{finding.category}' has unrealistically high confidence without corroboration",
                    "finding": finding.category,
                    "severity": "medium",
                    "suggestion": "Lower confidence or find corroborating evidence"
                })
            
            # Check for temporal inconsistencies
            if finding.timestamp and self._has_temporal_anomaly(finding, findings):
                corrections.append({
                    "type": "hallucination",
                    "description": f"Finding '{finding.category}' has temporal inconsistency",
                    "finding": finding.category,
                    "severity": "medium",
                    "suggestion": "Verify timestamps against other evidence"
                })
        
        return corrections
    
    def _has_strong_corroboration(self, finding: Finding, 
                                  all_findings: List[Finding]) -> bool:
        """Check if a finding has strong corroboration."""
        corroborating_count = 0
        
        for other in all_findings:
            if other == finding:
                continue
            
            if (other.category == finding.category or
                self._categories_corroborate(finding.category, other.category)):
                corroborating_count += 1
        
        return corroborating_count >= 2
    
    def _categories_corroborate(self, cat1: str, cat2: str) -> bool:
        """Check if two categories can corroborate each other."""
        corroboration_pairs = [
            ("suspicious_process", "powershell_activity"),
            ("network_activity", "dns_activity"),
            ("file_system_activity", "application_execution"),
            ("system_events", "powershell_activity")
        ]
        
        return (cat1, cat2) in corroboration_pairs or (cat2, cat1) in corroboration_pairs
    
    def _has_temporal_anomaly(self, finding: Finding, 
                              all_findings: List[Finding]) -> bool:
        """Check for temporal inconsistencies in findings."""
        if not finding.timestamp:
            return False
        
        # Check for findings with impossible time ordering
        for other in all_findings:
            if other == finding or not other.timestamp:
                continue
            
            # Simple check: if process creation is before file creation, that's suspicious
            if (finding.category == "suspicious_process" and 
                other.category == "file_system_activity"):
                if finding.timestamp > other.timestamp:
                    return True  # Process after file is suspicious
        
        return False
    
    def _identify_gaps(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Identify gaps in the analysis."""
        corrections = []
        
        # Check for missing analysis categories
        expected_categories = [
            "memory", "disk", "logs", "network"
        ]
        
        analyzed_categories = set(f.evidence_source for f in findings)
        
        for category in expected_categories:
            if not any(category in source for source in analyzed_categories):
                corrections.append({
                    "type": "missing_evidence",
                    "description": f"No analysis performed for {category} evidence",
                    "evidence_type": category,
                    "severity": "medium",
                    "arguments": self._get_evidence_arguments(category)
                })
        
        # Check for missing correlation
        if len(findings) > 2:
            has_correlation = any("correlation" in f.category.lower() for f in findings)
            if not has_correlation:
                corrections.append({
                    "type": "missing_analysis",
                    "description": "No correlation analysis performed across findings",
                    "analysis_type": "correlation",
                    "severity": "low",
                    "arguments": {}
                })
        
        return corrections
    
    def _get_validation_arguments(self, tool_name: str) -> Dict[str, Any]:
        """Get arguments for validation tools."""
        args_map = {
            "mft_timeline": {"mft_path": "/evidence/$MFT"},
            "extract_dns_from_pcap": {"pcap_path": "/evidence/capture.pcap"},
            "volatility_processes": {"memory_image": "/evidence/memory.raw", "profile": "Win7SP1x64"},
            "extract_prefetch": {"prefetch_path": "/evidence/Windows/Prefetch"}
        }
        return args_map.get(tool_name, {})
    
    def _get_evidence_arguments(self, evidence_type: str) -> Dict[str, Any]:
        """Get arguments for evidence collection tools."""
        args_map = {
            "memory": {"memory_image": "/evidence/memory.raw", "profile": "Win7SP1x64"},
            "disk": {"mft_path": "/evidence/$MFT"},
            "logs": {"evtx_path": "/evidence/Windows/System32/winevt/Logs"},
            "network": {"pcap_path": "/evidence/capture.pcap"}
        }
        return args_map.get(evidence_type, {})
    
    def _log_corrections(self, corrections: List[Dict[str, Any]]):
        """Log corrections for audit trail."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "corrections_count": len(corrections),
            "corrections": corrections
        }
        self.correction_history.append(log_entry)
        logger.info(f"Self-correction: {len(corrections)} issues identified")
    
    def get_correction_history(self) -> List[Dict[str, Any]]:
        """Return full correction history."""
        return self.correction_history
    
    def get_correction_summary(self) -> Dict[str, Any]:
        """Return summary of all corrections made."""
        total_corrections = sum(
            len(entry["corrections"]) for entry in self.correction_history
        )
        
        correction_types = {}
        for entry in self.correction_history:
            for correction in entry["corrections"]:
                ctype = correction.get("type", "unknown")
                correction_types[ctype] = correction_types.get(ctype, 0) + 1
        
        return {
            "total_corrections": total_corrections,
            "correction_types": correction_types,
            "iterations": len(self.correction_history)
        }
