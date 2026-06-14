"""Protocol SIFT Enhanced MCP Server

A purpose-built MCP server that wraps SIFT's forensic tools as structured,
type-safe functions. The agent physically cannot run destructive commands
because the server doesn't expose them.
"""

import json
import subprocess
import logging
import hashlib
from typing import Any, Dict, List, Optional, Union
from datetime import datetime
from pathlib import Path
import shlex

from .tools import ForensicToolRegistry, ToolDefinition
from .validation import ToolInputValidator

logger = logging.getLogger(__name__)


class SIFTMCPServer:
    """
    MCP Server that exposes typed forensic functions instead of generic
    shell commands. This architecture:
    
    1. Prevents destructive commands (not exposed in tool registry)
    2. Validates all inputs before execution
    3. Parses and summarizes output to prevent context overflow
    4. Maintains evidence integrity through hash verification
    """
    
    def __init__(self, evidence_base_path: str = "/evidence"):
        self.evidence_base = Path(evidence_base_path)
        self.tool_registry = ForensicToolRegistry()
        self.validator = ToolInputValidator(self.evidence_base)
        self.execution_log: List[Dict[str, Any]] = []
        
    def get_tools(self) -> List[ToolDefinition]:
        """Return all available forensic tools with their schemas."""
        return self.tool_registry.get_all_tools()
    
    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a forensic tool with validation and logging.
        
        Returns structured output with:
        - success: bool
        - output: parsed results
        - metadata: execution details
        - evidence_hash: hash of raw output for integrity
        """
        start_time = datetime.utcnow()
        
        # Get tool definition
        tool = self.tool_registry.get_tool(tool_name)
        if not tool:
            return {
                "success": False,
                "error": f"Unknown tool: {tool_name}",
                "available_tools": [t.name for t in self.tool_registry.get_all_tools()]
            }
        
        # Validate inputs
        validation_result = self.validator.validate(tool, arguments)
        if not validation_result["valid"]:
            return {
                "success": False,
                "error": "Input validation failed",
                "details": validation_result["errors"]
            }
        
        # Build command
        command = self._build_command(tool, arguments)
        
        # Log execution attempt
        execution_id = self._generate_execution_id(tool_name, arguments)
        self._log_execution(execution_id, tool_name, arguments, "started")
        
        try:
            # Execute with timeout and capture
            result = subprocess.run(
                command,
                shell=False,
                capture_output=True,
                text=True,
                timeout=tool.timeout_seconds,
                cwd=str(self.evidence_base)
            )
            
            # Calculate evidence hash
            output_hash = hashlib.sha256(result.stdout.encode()).hexdigest()
            
            # Parse output based on tool type
            parsed_output = self._parse_output(tool, result.stdout, result.stderr)
            
            execution_time = (datetime.utcnow() - start_time).total_seconds()
            
            # Log successful execution
            self._log_execution(
                execution_id, tool_name, arguments, "completed",
                output_hash=output_hash,
                execution_time=execution_time,
                return_code=result.returncode
            )
            
            return {
                "success": result.returncode == 0,
                "output": parsed_output,
                "metadata": {
                    "execution_id": execution_id,
                    "tool": tool_name,
                    "command": " ".join(command),
                    "execution_time_seconds": execution_time,
                    "return_code": result.returncode,
                    "output_hash": output_hash
                },
                "raw_output_available": True,
                "truncated": len(result.stdout) > tool.max_output_chars
            }
            
        except subprocess.TimeoutExpired:
            self._log_execution(execution_id, tool_name, arguments, "timeout")
            return {
                "success": False,
                "error": f"Tool execution timed out after {tool.timeout_seconds} seconds",
                "metadata": {"execution_id": execution_id, "tool": tool_name}
            }
        except Exception as e:
            self._log_execution(execution_id, tool_name, arguments, "error", error=str(e))
            return {
                "success": False,
                "error": str(e),
                "metadata": {"execution_id": execution_id, "tool": tool_name}
            }
    
    def _build_command(self, tool: ToolDefinition, arguments: Dict[str, Any]) -> List[str]:
        """Build command list from tool definition and arguments."""
        cmd = [tool.executable]
        
        for param_name, param_value in arguments.items():
            param_def = tool.parameters.get(param_name)
            if param_def:
                if param_def.get("type") == "boolean":
                    if param_value:
                        cmd.append(param_def.get("flag", f"--{param_name}"))
                elif param_def.get("type") == "list":
                    for item in param_value:
                        cmd.extend([param_def.get("flag", f"--{param_name}"), str(item)])
                else:
                    cmd.extend([param_def.get("flag", f"--{param_name}"), str(param_value)])
        
        return cmd
    
    def _parse_output(self, tool: ToolDefinition, stdout: str, stderr: str) -> Any:
        """Parse tool output based on tool type and format."""
        if tool.output_format == "json":
            try:
                return json.loads(stdout)
            except json.JSONDecodeError:
                return {"text": stdout[:tool.max_output_chars]}
        elif tool.output_format == "csv":
            return self._parse_csv(stdout)
        elif tool.output_format == "timeline":
            return self._parse_timeline(stdout)
        else:
            # Truncate large outputs
            if len(stdout) > tool.max_output_chars:
                return {
                    "text": stdout[:tool.max_output_chars] + "\n[OUTPUT TRUNCATED]",
                    "truncated": True,
                    "original_length": len(stdout)
                }
            return {"text": stdout}
    
    def _parse_csv(self, output: str) -> List[Dict[str, str]]:
        """Parse CSV output into list of dictionaries."""
        lines = output.strip().split('\n')
        if len(lines) < 2:
            return []
        
        headers = lines[0].split(',')
        rows = []
        for line in lines[1:]:
            values = line.split(',')
            row = dict(zip(headers, values))
            rows.append(row)
        
        return rows
    
    def _parse_timeline(self, output: str) -> Dict[str, Any]:
        """Parse timeline output into structured format."""
        events = []
        for line in output.strip().split('\n'):
            if line.strip():
                events.append({"event": line})
        
        return {
            "event_count": len(events),
            "events": events[:100]  # Limit to prevent context overflow
        }
    
    def _generate_execution_id(self, tool_name: str, arguments: Dict[str, Any]) -> str:
        """Generate unique execution ID for audit trail."""
        timestamp = datetime.utcnow().isoformat()
        args_hash = hashlib.md5(json.dumps(arguments, sort_keys=True).encode()).hexdigest()[:8]
        return f"{tool_name}_{args_hash}_{timestamp.replace(':', '-')}"
    
    def _log_execution(self, execution_id: str, tool_name: str, 
                       arguments: Dict[str, Any], status: str, **kwargs):
        """Log tool execution for audit trail."""
        log_entry = {
            "execution_id": execution_id,
            "timestamp": datetime.utcnow().isoformat(),
            "tool": tool_name,
            "arguments": arguments,
            "status": status,
            **kwargs
        }
        self.execution_log.append(log_entry)
        logger.info(f"Tool execution: {execution_id} - {status}")
    
    def get_execution_log(self) -> List[Dict[str, Any]]:
        """Return full execution log for audit trail."""
        return self.execution_log
    
    def get_execution_summary(self) -> Dict[str, Any]:
        """Return summary of all tool executions."""
        return {
            "total_executions": len(self.execution_log),
            "successful": len([e for e in self.execution_log if e["status"] == "completed"]),
            "failed": len([e for e in self.execution_log if e["status"] in ["error", "timeout"]]),
            "tools_used": list(set([e["tool"] for e in self.execution_log])),
            "execution_ids": [e["execution_id"] for e in self.execution_log]
        }
