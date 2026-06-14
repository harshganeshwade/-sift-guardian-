"""Audit Trail Logger

Provides structured logging of all agent operations for:
- Full traceability of findings to tool executions
- Agent-to-agent communication logs (for multi-agent)
- Timestamp and token usage tracking
- Iteration-over-iteration traces
"""

from typing import Any, Dict, List, Optional
from datetime import datetime
from pathlib import Path
import json
import hashlib


class AuditTrailLogger:
    """
    Structured audit trail logger for agent execution.
    
    Logs:
    - Tool executions with inputs/outputs
    - Agent decisions and reasoning
    - Self-correction events
    - Finding creation and verification
    - Token usage estimates
    """
    
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.execution_log: List[Dict[str, Any]] = []
        self.agent_communication_log: List[Dict[str, Any]] = []
        self.finding_log: List[Dict[str, Any]] = []
        self.correction_log: List[Dict[str, Any]] = []
        
        # Session tracking
        self.session_id = self._generate_session_id()
        self.session_start = datetime.utcnow()
        
    def log_tool_execution(self, tool_name: str, arguments: Dict[str, Any],
                          result: Dict[str, Any], execution_time: float,
                          tokens_used: Optional[int] = None) -> str:
        """Log a tool execution event."""
        execution_id = self._generate_execution_id(tool_name)
        
        log_entry = {
            "execution_id": execution_id,
            "timestamp": datetime.utcnow().isoformat(),
            "session_id": self.session_id,
            "event_type": "tool_execution",
            "tool": tool_name,
            "arguments": arguments,
            "success": result.get("success", False),
            "execution_time_seconds": execution_time,
            "tokens_used": tokens_used,
            "output_summary": self._summarize_output(result.get("output")),
            "metadata": result.get("metadata", {}),
            "output_hash": self._hash_output(result.get("output"))
        }
        
        self.execution_log.append(log_entry)
        self._save_log("tool_executions", self.execution_log)
        
        return execution_id
    
    def log_agent_decision(self, decision_type: str, reasoning: str,
                          inputs: Dict[str, Any], outputs: Dict[str, Any],
                          confidence: float = 0.0) -> str:
        """Log an agent decision with reasoning."""
        decision_id = self._generate_decision_id(decision_type)
        
        log_entry = {
            "decision_id": decision_id,
            "timestamp": datetime.utcnow().isoformat(),
            "session_id": self.session_id,
            "event_type": "agent_decision",
            "decision_type": decision_type,
            "reasoning": reasoning,
            "inputs": inputs,
            "outputs": outputs,
            "confidence": confidence,
            "tokens_used": self._estimate_tokens(reasoning)
        }
        
        self.execution_log.append(log_entry)
        self._save_log("agent_decisions", self.execution_log)
        
        return decision_id
    
    def log_finding(self, finding_id: str, category: str, severity: str,
                   description: str, evidence_source: str, confidence: float,
                   raw_evidence: Optional[str] = None) -> str:
        """Log a finding creation event."""
        log_entry = {
            "finding_log_id": self._generate_finding_log_id(finding_id),
            "timestamp": datetime.utcnow().isoformat(),
            "session_id": self.session_id,
            "event_type": "finding_created",
            "finding_id": finding_id,
            "category": category,
            "severity": severity,
            "description": description,
            "evidence_source": evidence_source,
            "confidence": confidence,
            "evidence_hash": self._hash_output(raw_evidence) if raw_evidence else None
        }
        
        self.finding_log.append(log_entry)
        self._save_log("findings", self.finding_log)
        
        return log_entry["finding_log_id"]
    
    def log_self_correction(self, iteration: int, corrections: List[Dict[str, Any]],
                           original_findings: List[str], 
                           revised_findings: List[str]) -> str:
        """Log a self-correction event."""
        correction_id = self._generate_correction_id(iteration)
        
        log_entry = {
            "correction_id": correction_id,
            "timestamp": datetime.utcnow().isoformat(),
            "session_id": self.session_id,
            "event_type": "self_correction",
            "iteration": iteration,
            "corrections": corrections,
            "original_findings_count": len(original_findings),
            "revised_findings_count": len(revised_findings),
            "findings_added": list(set(revised_findings) - set(original_findings)),
            "findings_removed": list(set(original_findings) - set(revised_findings))
        }
        
        self.correction_log.append(log_entry)
        self._save_log("self_corrections", self.correction_log)
        
        return correction_id
    
    def log_agent_communication(self, sender: str, receiver: str,
                               message_type: str, content: Dict[str, Any],
                               tokens_used: Optional[int] = None) -> str:
        """Log agent-to-agent communication (for multi-agent systems)."""
        communication_id = self._generate_communication_id(sender, receiver)
        
        log_entry = {
            "communication_id": communication_id,
            "timestamp": datetime.utcnow().isoformat(),
            "session_id": self.session_id,
            "event_type": "agent_communication",
            "sender": sender,
            "receiver": receiver,
            "message_type": message_type,
            "content_summary": self._summarize_content(content),
            "content_hash": self._hash_output(content),
            "tokens_used": tokens_used
        }
        
        self.agent_communication_log.append(log_entry)
        self._save_log("agent_communications", self.agent_communication_log)
        
        return communication_id
    
    def log_iteration(self, iteration: int, phase: str,
                     tools_executed: List[str], findings_created: int,
                     corrections_made: int) -> str:
        """Log iteration summary for persistent learning loops."""
        iteration_id = self._generate_iteration_id(iteration)
        
        log_entry = {
            "iteration_id": iteration_id,
            "timestamp": datetime.utcnow().isoformat(),
            "session_id": self.session_id,
            "event_type": "iteration_summary",
            "iteration": iteration,
            "phase": phase,
            "tools_executed": tools_executed,
            "tools_count": len(tools_executed),
            "findings_created": findings_created,
            "corrections_made": corrections_made
        }
        
        self.execution_log.append(log_entry)
        self._save_log("iterations", self.execution_log)
        
        return iteration_id
    
    def generate_full_audit_trail(self) -> Dict[str, Any]:
        """Generate complete audit trail for submission."""
        return {
            "audit_trail": {
                "session_id": self.session_id,
                "session_start": self.session_start.isoformat(),
                "generated_at": datetime.utcnow().isoformat(),
                "summary": {
                    "total_tool_executions": len([e for e in self.execution_log 
                                                 if e.get("event_type") == "tool_execution"]),
                    "total_decisions": len([e for e in self.execution_log 
                                          if e.get("event_type") == "agent_decision"]),
                    "total_findings": len(self.finding_log),
                    "total_corrections": len(self.correction_log),
                    "total_communications": len(self.agent_communication_log)
                }
            },
            "tool_executions": [
                e for e in self.execution_log 
                if e.get("event_type") == "tool_execution"
            ],
            "agent_decisions": [
                e for e in self.execution_log 
                if e.get("event_type") == "agent_decision"
            ],
            "findings": self.finding_log,
            "self_corrections": self.correction_log,
            "agent_communications": self.agent_communication_log,
            "iteration_summaries": [
                e for e in self.execution_log 
                if e.get("event_type") == "iteration_summary"
            ]
        }
    
    def _summarize_output(self, output: Any) -> str:
        """Create summary of tool output for logging."""
        if output is None:
            return "No output"
        
        if isinstance(output, dict):
            if "text" in output:
                return output["text"][:200] + "..." if len(output["text"]) > 200 else output["text"]
            return json.dumps(output)[:200]
        
        if isinstance(output, list):
            return f"List with {len(output)} items"
        
        return str(output)[:200]
    
    def _summarize_content(self, content: Dict[str, Any]) -> str:
        """Create summary of communication content."""
        return json.dumps(content)[:200]
    
    def _hash_output(self, output: Any) -> str:
        """Hash output for integrity verification."""
        if output is None:
            return ""
        
        content = json.dumps(output, sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _estimate_tokens(self, text: str) -> int:
        """Estimate token count for text."""
        # Rough estimation: 1 token ≈ 4 characters
        return len(text) // 4
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID."""
        timestamp = datetime.utcnow().isoformat()
        return hashlib.md5(timestamp.encode()).hexdigest()[:12]
    
    def _generate_execution_id(self, tool_name: str) -> str:
        """Generate unique execution ID."""
        timestamp = datetime.utcnow().isoformat()
        content = f"{tool_name}:{timestamp}"
        return hashlib.md5(content.encode()).hexdigest()[:12]
    
    def _generate_decision_id(self, decision_type: str) -> str:
        """Generate unique decision ID."""
        timestamp = datetime.utcnow().isoformat()
        content = f"{decision_type}:{timestamp}"
        return hashlib.md5(content.encode()).hexdigest()[:12]
    
    def _generate_finding_log_id(self, finding_id: str) -> str:
        """Generate unique finding log ID."""
        timestamp = datetime.utcnow().isoformat()
        return f"finding_{finding_id}_{timestamp.replace(':', '-')}"
    
    def _generate_correction_id(self, iteration: int) -> str:
        """Generate unique correction ID."""
        timestamp = datetime.utcnow().isoformat()
        return f"correction_{iteration}_{timestamp.replace(':', '-')}"
    
    def _generate_communication_id(self, sender: str, receiver: str) -> str:
        """Generate unique communication ID."""
        timestamp = datetime.utcnow().isoformat()
        content = f"{sender}:{receiver}:{timestamp}"
        return hashlib.md5(content.encode()).hexdigest()[:12]
    
    def _generate_iteration_id(self, iteration: int) -> str:
        """Generate unique iteration ID."""
        timestamp = datetime.utcnow().isoformat()
        return f"iteration_{iteration}_{timestamp.replace(':', '-')}"
    
    def _save_log(self, log_type: str, log_data: List[Dict[str, Any]]):
        """Save log data to file."""
        log_file = self.log_dir / f"{log_type}_{self.session_id}.json"
        
        with open(log_file, "w") as f:
            json.dump(log_data, f, indent=2, default=str)
    
    def save_all_logs(self):
        """Save all logs to files."""
        self._save_log("tool_executions", 
                      [e for e in self.execution_log 
                       if e.get("event_type") == "tool_execution"])
        self._save_log("agent_decisions",
                      [e for e in self.execution_log 
                       if e.get("event_type") == "agent_decision"])
        self._save_log("findings", self.finding_log)
        self._save_log("self_corrections", self.correction_log)
        self._save_log("agent_communications", self.agent_communication_log)
        self._save_log("iterations",
                      [e for e in self.execution_log 
                       if e.get("event_type") == "iteration_summary"])
