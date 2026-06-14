"""Tests for MCP Server"""

import pytest
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from src.mcp_server.server import SIFTMCPServer
from src.mcp_server.tools import ForensicToolRegistry
from src.mcp_server.validation import ToolInputValidator


class TestForensicToolRegistry:
    """Tests for the forensic tool registry."""
    
    def test_registry_initialization(self):
        """Test that registry initializes with tools."""
        registry = ForensicToolRegistry()
        tools = registry.get_all_tools()
        assert len(tools) > 0
    
    def test_get_tool_by_name(self):
        """Test getting a specific tool by name."""
        registry = ForensicToolRegistry()
        tool = registry.get_tool("volatility_processes")
        assert tool is not None
        assert tool.name == "volatility_processes"
        assert tool.category == "memory"
    
    def test_get_tools_by_category(self):
        """Test getting tools by category."""
        registry = ForensicToolRegistry()
        memory_tools = registry.get_tools_by_category("memory")
        assert len(memory_tools) > 0
        assert all(t.category == "memory" for t in memory_tools)
    
    def test_get_categories(self):
        """Test getting all categories."""
        registry = ForensicToolRegistry()
        categories = registry.get_categories()
        assert "memory" in categories
        assert "disk" in categories
        assert "logs" in categories
        assert "network" in categories
    
    def test_tool_parameters_defined(self):
        """Test that tools have parameters defined."""
        registry = ForensicToolRegistry()
        tool = registry.get_tool("volatility_processes")
        assert "profile" in tool.parameters
        assert "memory_image" in tool.parameters
        assert tool.parameters["profile"]["required"] is True


class TestToolInputValidator:
    """Tests for tool input validation."""
    
    def test_validator_initialization(self, tmp_path):
        """Test validator initialization."""
        validator = ToolInputValidator(tmp_path)
        assert validator.evidence_base == tmp_path
    
    def test_validate_required_parameters(self, tmp_path):
        """Test validation of required parameters."""
        validator = ToolInputValidator(tmp_path)
        registry = ForensicToolRegistry()
        tool = registry.get_tool("volatility_processes")
        
        # Missing required parameter
        result = validator.validate(tool, {})
        assert result["valid"] is False
        assert any("profile" in e for e in result["errors"])
        
        # With required parameters
        result = validator.validate(tool, {
            "profile": "Win7SP1x64",
            "memory_image": str(tmp_path / "memory.raw")
        })
        assert result["valid"] is True
    
    def test_validate_path_traversal(self, tmp_path):
        """Test path traversal detection."""
        validator = ToolInputValidator(tmp_path)
        
        # Path traversal attempt
        assert validator._detect_injection("../../../etc/passwd") is True
        assert validator._detect_injection("normal/path/file.txt") is False
    
    def test_validate_injection_detection(self, tmp_path):
        """Test command injection detection."""
        validator = ToolInputValidator(tmp_path)
        
        # Injection attempts
        assert validator._detect_injection("file; rm -rf /") is True
        assert validator._detect_injection("file && cat /etc/passwd") is True
        assert validator._detect_injection("normal file name") is False


class TestSIFTMCPServer:
    """Tests for the MCP Server."""
    
    def test_server_initialization(self, tmp_path):
        """Test server initialization."""
        server = SIFTMCPServer(str(tmp_path))
        assert server.evidence_base == tmp_path
        assert len(server.tool_registry.get_all_tools()) > 0
    
    def test_get_tools(self, tmp_path):
        """Test getting available tools."""
        server = SIFTMCPServer(str(tmp_path))
        tools = server.get_tools()
        assert len(tools) > 0
        assert all(hasattr(t, 'name') for t in tools)
    
    def test_execution_log(self, tmp_path):
        """Test execution log tracking."""
        server = SIFTMCPServer(str(tmp_path))
        log = server.get_execution_log()
        assert isinstance(log, list)
        
        summary = server.get_execution_summary()
        assert "total_executions" in summary
        assert "successful" in summary
        assert "failed" in summary
    
    def test_unknown_tool_returns_error(self, tmp_path):
        """Test that unknown tool returns error."""
        server = SIFTMCPServer(str(tmp_path))
        result = server.execute_tool("nonexistent_tool", {})
        assert result["success"] is False
        assert "Unknown tool" in result["error"]
