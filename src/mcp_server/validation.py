"""Tool Input Validation

Validates all tool inputs before execution to ensure:
1. Required parameters are present
2. File paths exist and are within evidence directory
3. Parameter types match expected types
4. No path traversal or injection attempts
"""

import os
import re
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path

from .tools import ToolDefinition


class ToolInputValidator:
    """
    Validates tool inputs to prevent:
    - Path traversal attacks
    - Command injection
    - Invalid parameter types
    - Access to files outside evidence directory
    """
    
    def __init__(self, evidence_base_path: Path):
        self.evidence_base = evidence_base_path.resolve()
        
    def validate(self, tool: ToolDefinition, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate all inputs for a tool execution.
        
        Returns:
            {
                "valid": bool,
                "errors": List[str],
                "warnings": List[str]
            }
        """
        errors = []
        warnings = []
        
        # Check required parameters
        for param_name, param_def in tool.parameters.items():
            if param_def.get("required", False):
                if param_name not in arguments:
                    errors.append(f"Missing required parameter: {param_name}")
        
        # Validate each provided parameter
        for param_name, param_value in arguments.items():
            param_def = tool.parameters.get(param_name)
            if not param_def:
                errors.append(f"Unknown parameter: {param_name}")
                continue
            
            # Type validation
            type_error = self._validate_type(param_name, param_value, param_def)
            if type_error:
                errors.append(type_error)
                continue
            
            # Path validation for path parameters
            if param_def.get("type") == "path":
                path_error = self._validate_path(param_name, param_value)
                if path_error:
                    errors.append(path_error)
            
            # Choice validation
            if param_def.get("choices"):
                if param_value not in param_def["choices"]:
                    errors.append(f"Invalid choice for {param_name}: {param_value}. Must be one of: {param_def['choices']}")
            
            # Injection detection
            if self._detect_injection(param_value):
                errors.append(f"Potential injection detected in parameter: {param_name}")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings
        }
    
    def _validate_type(self, param_name: str, value: Any, param_def: Dict[str, Any]) -> Optional[str]:
        """Validate parameter type matches expected type."""
        expected_type = param_def.get("type", "string")
        
        if expected_type == "string":
            if not isinstance(value, str):
                return f"Parameter {param_name} must be a string"
        elif expected_type == "integer":
            if not isinstance(value, (int, str)):
                return f"Parameter {param_name} must be an integer"
            if isinstance(value, str) and not value.isdigit():
                return f"Parameter {param_name} must be a valid integer"
        elif expected_type == "boolean":
            if not isinstance(value, bool):
                return f"Parameter {param_name} must be a boolean"
        elif expected_type == "list":
            if not isinstance(value, list):
                return f"Parameter {param_name} must be a list"
        elif expected_type == "path":
            if not isinstance(value, str):
                return f"Parameter {param_name} must be a string (path)"
        
        return None
    
    def _validate_path(self, param_name: str, path_value: str) -> Optional[str]:
        """Validate path is safe and within evidence directory."""
        try:
            # Check for path traversal BEFORE resolving (catch .. patterns)
            if '..' in path_value:
                return f"Path traversal detected in {param_name}: {path_value}"
            
            # Resolve path and check for symlink-based traversal
            path = Path(path_value).resolve()
            
            # Check if resolved path is within evidence directory
            if not str(path).startswith(str(self.evidence_base)):
                return f"Path {param_name} must be within evidence directory: {self.evidence_base}"
            
            # Check if path exists (warning, not error - file might be created)
            if not path.exists():
                return None  # Allow non-existent paths for output directories
            
            return None
            
        except Exception as e:
            return f"Invalid path for {param_name}: {e}"
    
    def _detect_injection(self, value: Any) -> bool:
        """Detect potential command injection attempts."""
        if not isinstance(value, str):
            return False
        
        # Common injection patterns - comprehensive check
        injection_patterns = [
            r'[;&|`$]',  # Shell metacharacters
            r'\$\(',  # Command substitution
            r'\$\{',  # Variable expansion
            r'>\s*/',  # Redirect to absolute path
            r'<\s*/',  # Redirect from absolute path
            r'\\x[0-9a-fA-F]{2}',  # Hex encoded characters
            r'\.\./',  # Path traversal
            r'\.\.\\',  # Path traversal Windows
            r'\bexec\b',  # exec command
            r'\beval\b',  # eval command
        ]
        
        for pattern in injection_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        
        return False
    
    def sanitize_path(self, path: str) -> str:
        """Sanitize a path for safe use."""
        # Remove any null bytes
        path = path.replace('\0', '')
        
        # Normalize path
        path = os.path.normpath(path)
        
        # Remove any leading slashes that might bypass checks
        path = path.lstrip('/')
        
        return path
