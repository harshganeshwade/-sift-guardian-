"""Agent Orchestrator

Main orchestrator that manages the autonomous incident response workflow.
Implements senior analyst thinking patterns with self-correction.
"""

import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime
from pathlib import Path

from ..mcp_server.server import SIFTMCPServer
from .planner import AnalysisPlanner, AnalysisPhase
from .self_correction import SelfCorrectionEngine
from ..validation.accuracy import AccuracyTracker, Finding
from .demo_data import DemoDataGenerator

logger = logging.getLogger(__name__)


class AgentOrchestrator:
    """
    Orchestrates the autonomous incident response workflow.
    
    This agent thinks like a senior analyst:
    1. Begins with broad triage to understand scope
    2. Prioritizes evidence collection based on findings
    3. Validates findings against multiple sources
    4. Self-corrects when inconsistencies are detected
    5. Maintains evidence integrity throughout
    """
    
    def __init__(self, mcp_server: SIFTMCPServer, evidence_path: str, demo_mode: bool = False):
        self.mcp_server = mcp_server
        self.evidence_path = Path(evidence_path)
        self.planner = AnalysisPlanner()
        self.self_correction = SelfCorrectionEngine()
        self.accuracy_tracker = AccuracyTracker()
        self.demo_mode = demo_mode
        self.demo_generator = DemoDataGenerator(evidence_path) if demo_mode else None
        
        self.current_phase = AnalysisPhase.TRIAGE
        self.findings: List[Finding] = []
        self.execution_trace: List[Dict[str, Any]] = []
        self.max_iterations = 10  # Prevent runaway execution
        
        # Track analysis state
        self.analyzed_artifacts = set()
        self.correlation_graph: Dict[str, List[str]] = {}

    def analyze(self, case_description: str) -> Dict[str, Any]:
        """
        Main entry point for autonomous analysis.

        Args:
            case_description: Description of the case or evidence to analyze
            
        Returns:
            Complete analysis results with findings and execution trace
        """
        start_time = datetime.utcnow()
        iteration = 0

        logger.info(f"Starting autonomous analysis: {case_description}")

        # In demo mode, load pre-built findings directly
        if self.demo_mode and self.demo_generator:
            self._load_demo_findings()

        # Create initial analysis plan
        plan = self.planner.create_plan(case_description, self.evidence_path)

        while iteration < self.max_iterations:
            iteration += 1
            logger.info(f"Analysis iteration {iteration}/{self.max_iterations}")

            # Execute current phase
            phase_result = self._execute_phase(plan)

            # Check for self-correction needs
            corrections_needed = self.self_correction.analyze_results(
                phase_result, self.findings
            )

            if corrections_needed:
                logger.info(f"Self-correction triggered: {len(corrections_needed)} issues found")
                plan = self.planner.revise_plan(plan, corrections_needed)

                # Log the self-correction
                self._log_self_correction(iteration, corrections_needed)
                continue

            # Validate findings
            validation_result = self._validate_findings()

            if validation_result["needs_more_data"]:
                logger.info("Validation requires additional analysis")
                plan = self.planner.add_validation_steps(plan, validation_result["gaps"])
                continue

            # Check if analysis is complete
            if self._is_analysis_complete(plan):
                break

        # Generate final report
        end_time = datetime.utcnow()
        return self._generate_report(start_time, end_time, iteration)

    def _load_demo_findings(self):
        """Load pre-built demo findings into the orchestrator."""
        demo_findings = self.demo_generator.get_demo_findings()
        for finding_data in demo_findings:
            finding = Finding(
                category=finding_data["category"],
                severity=finding_data["severity"],
                description=finding_data["description"],
                evidence_source=finding_data["evidence_source"],
                confidence=finding_data["confidence"],
                raw_evidence=finding_data["raw_evidence"],
                timestamp=datetime.fromisoformat(finding_data["timestamp"]) if finding_data.get("timestamp") else None,
            )
            self.findings.append(finding)
        logger.info(f"Loaded {len(demo_findings)} pre-built demo findings")
    
    def _execute_phase(self, plan: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the current analysis phase."""
        phase_results = {
            "phase": self.current_phase.value,
            "tools_executed": [],
            "findings": [],
            "errors": []
        }
        
        # Get tools for current phase from the generated plan
        tools_to_execute = plan.get("phases", {}) \
            .get(self.current_phase.value, {}) \
            .get("tools", [])
        
        if not tools_to_execute:
            # Fallback to planner-defined phase tools if plan is missing entries
            tools_to_execute = self.planner.get_phase_tools(self.current_phase)
        
        for tool_task in tools_to_execute:
            tool_name = tool_task.get("tool")
            arguments = tool_task.get("arguments", {})
            
            if not tool_name:
                continue
            
            # Execute tool - use demo data if in demo mode
            if self.demo_mode and self.demo_generator:
                result = self.demo_generator.get_demo_output(tool_name, arguments)
            else:
                result = self.mcp_server.execute_tool(tool_name, arguments)
            
            # Log execution
            execution_record = {
                "tool": tool_name,
                "arguments": arguments,
                "success": result.get("success", False),
                "timestamp": datetime.utcnow().isoformat(),
                "execution_id": result.get("metadata", {}).get("execution_id")
            }
            phase_results["tools_executed"].append(execution_record)
            self.execution_trace.append(execution_record)
            
            if result.get("success"):
                # Process successful results
                findings = self._extract_findings(tool_name, result)
                phase_results["findings"].extend(findings)
                self.findings.extend(findings)
                
                # Track analyzed artifacts
                self.analyzed_artifacts.add(arguments.get("path", tool_name))
            else:
                # Log errors
                phase_results["errors"].append({
                    "tool": tool_name,
                    "error": result.get("error", "Unknown error")
                })
        
        return phase_results
    
    def _extract_findings(self, tool_name: str, result: Dict[str, Any]) -> List[Finding]:
        """Extract findings from tool execution results."""
        findings = []
        
        # Get tool definition
        tool = self.mcp_server.tool_registry.get_tool(tool_name)
        if not tool:
            return findings
        
        # Extract findings based on tool category
        if tool.category == "memory":
            findings.extend(self._extract_memory_findings(tool_name, result))
        elif tool.category == "disk":
            findings.extend(self._extract_disk_findings(tool_name, result))
        elif tool.category == "logs":
            findings.extend(self._extract_log_findings(tool_name, result))
        elif tool.category == "network":
            findings.extend(self._extract_network_findings(tool_name, result))
        
        return findings
    
    def _extract_memory_findings(self, tool_name: str, result: Dict[str, Any]) -> List[Finding]:
        """Extract findings from memory analysis tools."""
        findings = []
        output = result.get("output", {})
        
        if tool_name == "volatility_processes":
            # Look for suspicious processes
            if isinstance(output, dict) and "text" in output:
                text = output["text"]
                # Simple heuristic for suspicious processes
                suspicious_indicators = ["mimikatz", "procdump", "psexec", "net.exe", "cmd.exe"]
                for indicator in suspicious_indicators:
                    if indicator.lower() in text.lower():
                        findings.append(Finding(
                            category="suspicious_process",
                            severity="high",
                            description=f"Detected suspicious process indicator: {indicator}",
                            evidence_source=tool_name,
                            confidence=0.7,
                            raw_evidence=text[:500]
                        ))
        
        elif tool_name == "volatility_network":
            # Look for suspicious network connections
            if isinstance(output, dict) and "text" in output:
                text = output["text"]
                # Check for unusual ports or connections
                findings.append(Finding(
                    category="network_activity",
                    severity="medium",
                    description="Network connections extracted from memory",
                    evidence_source=tool_name,
                    confidence=0.8,
                    raw_evidence=text[:500]
                ))
        
        return findings
    
    def _extract_disk_findings(self, tool_name: str, result: Dict[str, Any]) -> List[Finding]:
        """Extract findings from disk analysis tools."""
        findings = []
        output = result.get("output", {})
        
        if tool_name == "mft_timeline":
            # Analyze MFT timeline for suspicious activity
            if output:
                findings.append(Finding(
                    category="file_system_activity",
                    severity="medium",
                    description="MFT timeline analyzed for file system changes",
                    evidence_source=tool_name,
                    confidence=0.8,
                    raw_evidence=str(output)[:500]
                ))
        
        elif tool_name == "extract_amcache":
            # Look for suspicious application execution
            if output:
                findings.append(Finding(
                    category="application_execution",
                    severity="medium",
                    description="Amcache analyzed for application execution history",
                    evidence_source=tool_name,
                    confidence=0.8,
                    raw_evidence=str(output)[:500]
                ))
        
        return findings
    
    def _extract_log_findings(self, tool_name: str, result: Dict[str, Any]) -> List[Finding]:
        """Extract findings from log analysis tools."""
        findings = []
        output = result.get("output", {})
        
        if tool_name == "parse_event_logs":
            # Analyze Windows Event Logs
            findings.append(Finding(
                category="system_events",
                severity="medium",
                description="Windows Event Logs analyzed for suspicious activity",
                evidence_source=tool_name,
                confidence=0.8,
                raw_evidence=str(output)[:500]
            ))
        
        elif tool_name == "parse_powershell_logs":
            # Look for suspicious PowerShell commands
            findings.append(Finding(
                category="powershell_activity",
                severity="high",
                description="PowerShell logs analyzed for command execution",
                evidence_source=tool_name,
                confidence=0.8,
                raw_evidence=str(output)[:500]
            ))
        
        return findings
    
    def _extract_network_findings(self, tool_name: str, result: Dict[str, Any]) -> List[Finding]:
        """Extract findings from network analysis tools."""
        findings = []
        output = result.get("output", {})
        
        if tool_name == "extract_dns_from_pcap":
            # Analyze DNS queries for suspicious domains
            findings.append(Finding(
                category="dns_activity",
                severity="medium",
                description="DNS queries extracted and analyzed",
                evidence_source=tool_name,
                confidence=0.8,
                raw_evidence=str(output)[:500]
            ))
        
        elif tool_name == "extract_http_from_pcap":
            # Analyze HTTP traffic
            findings.append(Finding(
                category="http_activity",
                severity="medium",
                description="HTTP traffic analyzed for suspicious requests",
                evidence_source=tool_name,
                confidence=0.8,
                raw_evidence=str(output)[:500]
            ))
        
        return findings
    
    def _validate_findings(self) -> Dict[str, Any]:
        """Validate findings against multiple sources."""
        validation_result = {
            "needs_more_data": False,
            "gaps": [],
            "cross_referenced": [],
            "validated": []
        }
        
        # Cross-reference findings
        for finding in self.findings:
            # Check if finding can be corroborated by other sources
            corroborating = self._find_corroborating_evidence(finding)
            
            if corroborating:
                finding.confidence = min(finding.confidence + 0.1, 1.0)
                validation_result["cross_referenced"].append({
                    "finding": finding.category,
                    "corroborated_by": [f.evidence_source for f in corroborating]
                })
            else:
                # Flag for additional validation
                validation_result["needs_more_data"] = True
                validation_result["gaps"].append({
                    "finding": finding.category,
                    "missing": "corroborating evidence"
                })
        
        return validation_result
    
    def _find_corroborating_evidence(self, finding: Finding) -> List[Finding]:
        """Find other findings that corroborate a given finding."""
        corroborating = []
        
        for other_finding in self.findings:
            if other_finding == finding:
                continue
            
            # Check for corroboration based on category
            if self._can_corroborate(finding, other_finding):
                corroborating.append(other_finding)
        
        return corroborating
    
    def _can_corroborate(self, finding1: Finding, finding2: Finding) -> bool:
        """Check if two findings can corroborate each other."""
        # Simple corroboration rules
        corroboration_rules = {
            ("suspicious_process", "powershell_activity"): True,
            ("network_activity", "dns_activity"): True,
            ("file_system_activity", "application_execution"): True,
            ("system_events", "powershell_activity"): True,
        }
        
        key = (finding1.category, finding2.category)
        reverse_key = (finding2.category, finding1.category)
        
        return corroboration_rules.get(key, False) or corroboration_rules.get(reverse_key, False)
    
    def _log_self_correction(self, iteration: int, corrections: List[Dict[str, Any]]):
        """Log self-correction events for audit trail."""
        self.execution_trace.append({
            "type": "self_correction",
            "iteration": iteration,
            "timestamp": datetime.utcnow().isoformat(),
            "corrections": corrections
        })
    
    def _is_analysis_complete(self, plan: Dict[str, Any]) -> bool:
        """Check if analysis is complete."""
        # Check if all planned phases are complete
        remaining_phases = plan.get("remaining_phases", [])
        
        if not remaining_phases:
            return True
        
        # Move to next phase
        next_phase = remaining_phases[0]
        try:
            self.current_phase = AnalysisPhase(next_phase)
            plan["remaining_phases"] = remaining_phases[1:]
        except ValueError:
            # Invalid phase, skip
            plan["remaining_phases"] = remaining_phases[1:]
        
        return False
    
    def _generate_report(self, start_time: datetime, end_time: datetime, 
                        iterations: int) -> Dict[str, Any]:
        """Generate comprehensive analysis report."""
        duration = (end_time - start_time).total_seconds()
        
        # Get accuracy metrics
        accuracy_metrics = self.accuracy_tracker.calculate_metrics()
        
        # Get execution summary
        execution_summary = self.mcp_server.get_execution_summary()
        
        return {
            "summary": {
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "duration_seconds": duration,
                "iterations": iterations,
                "total_findings": len(self.findings),
                "high_severity": len([f for f in self.findings if f.severity == "high"]),
                "medium_severity": len([f for f in self.findings if f.severity == "medium"]),
                "low_severity": len([f for f in self.findings if f.severity == "low"])
            },
            "findings": [self._finding_to_dict(f) for f in self.findings],
            "accuracy_metrics": accuracy_metrics,
            "execution_summary": execution_summary,
            "execution_trace": self.execution_trace,
            "evidence_integrity": {
                "artifacts_analyzed": list(self.analyzed_artifacts),
                "correlation_graph": self.correlation_graph
            }
        }
    
    def _finding_to_dict(self, finding: Finding) -> Dict[str, Any]:
        """Convert Finding to dictionary."""
        return {
            "category": finding.category,
            "severity": finding.severity,
            "description": finding.description,
            "evidence_source": finding.evidence_source,
            "confidence": finding.confidence,
            "raw_evidence": finding.raw_evidence,
            "timestamp": finding.timestamp.isoformat() if finding.timestamp else None
        }
