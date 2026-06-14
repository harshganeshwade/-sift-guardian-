"""Forensic Tool Registry

Defines all available forensic tools as structured, type-safe functions.
Only read-only, non-destructive tools are exposed.
"""

from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class ToolParameter:
    """Definition of a tool parameter."""
    name: str
    type: str  # string, integer, boolean, list, path
    description: str
    required: bool = False
    default: Any = None
    flag: Optional[str] = None
    choices: Optional[List[str]] = None


@dataclass
class ToolDefinition:
    """Complete definition of a forensic tool."""
    name: str
    description: str
    category: str
    executable: str
    parameters: Dict[str, Dict[str, Any]]
    output_format: str  # json, csv, text, timeline
    timeout_seconds: int = 300
    max_output_chars: int = 50000
    examples: List[Dict[str, Any]] = field(default_factory=list)


class ForensicToolRegistry:
    """
    Registry of all available forensic tools.
    
    Design Principles:
    1. Only read-only tools are registered
    2. Each tool has typed parameters with validation
    3. Output formats are standardized for parsing
    4. Timeouts prevent runaway processes
    """
    
    def __init__(self):
        self._tools: Dict[str, ToolDefinition] = {}
        self._register_all_tools()
    
    def _register_all_tools(self):
        """Register all available forensic tools."""
        
        # Memory Analysis Tools
        self._register_tool(ToolDefinition(
            name="volatility_processes",
            description="Extract process list from memory dump using Volatility",
            category="memory",
            executable="vol.py",
            parameters={
                "profile": {"type": "string", "required": True, "flag": "--profile",
                           "choices": ["Win7SP1x64", "Win10x64", "WinXPSP3x86"]},
                "memory_image": {"type": "path", "required": True, "flag": ""},
                "plugin": {"type": "string", "default": "pslist", 
                          "choices": ["pslist", "pstree", "psxview"]}
            },
            output_format="text",
            timeout_seconds=120,
            examples=[
                {"description": "List processes in memory image",
                 "arguments": {"profile": "Win7SP1x64", "memory_image": "/evidence/memory.raw", "plugin": "pslist"}}
            ]
        ))
        
        self._register_tool(ToolDefinition(
            name="volatility_network",
            description="Extract network connections from memory dump",
            category="memory",
            executable="vol.py",
            parameters={
                "profile": {"type": "string", "required": True, "flag": "--profile"},
                "memory_image": {"type": "path", "required": True, "flag": ""},
                "plugin": {"type": "string", "default": "netscan", 
                          "choices": ["netscan", "connections"]}
            },
            output_format="text",
            timeout_seconds=120
        ))
        
        self._register_tool(ToolDefinition(
            name="volatility_dlls",
            description="List loaded DLLs from memory dump",
            category="memory",
            executable="vol.py",
            parameters={
                "profile": {"type": "string", "required": True, "flag": "--profile"},
                "memory_image": {"type": "path", "required": True, "flag": ""},
                "plugin": {"type": "string", "default": "dlllist"}
            },
            output_format="text",
            timeout_seconds=120
        ))
        
        self._register_tool(ToolDefinition(
            name="volatility_handles",
            description="List open handles from memory dump",
            category="memory",
            executable="vol.py",
            parameters={
                "profile": {"type": "string", "required": True, "flag": "--profile"},
                "memory_image": {"type": "path", "required": True, "flag": ""},
                "plugin": {"type": "string", "default": "handles"}
            },
            output_format="text",
            timeout_seconds=120
        ))
        
        # Disk Analysis Tools
        self._register_tool(ToolDefinition(
            name="mft_timeline",
            description="Parse MFT and create timeline of file system activity",
            category="disk",
            executable="MFTECmd.py",
            parameters={
                "mft_path": {"type": "path", "required": True, "flag": "--f"},
                "output_dir": {"type": "path", "flag": "--o"},
                "json_output": {"type": "boolean", "flag": "--json", "default": True}
            },
            output_format="json",
            timeout_seconds=180,
            examples=[
                {"description": "Parse MFT from evidence drive",
                 "arguments": {"mft_path": "/evidence/$MFT"}}
            ]
        ))
        
        self._register_tool(ToolDefinition(
            name="extract_amcache",
            description="Parse Amcache.hve for application execution artifacts",
            category="disk",
            executable="AmcacheParser.py",
            parameters={
                "amcache_path": {"type": "path", "required": True, "flag": "--f"},
                "output_dir": {"type": "path", "flag": "--o"},
                "json_output": {"type": "boolean", "flag": "--json", "default": True}
            },
            output_format="json",
            timeout_seconds=120
        ))
        
        self._register_tool(ToolDefinition(
            name="extract_prefetch",
            description="Parse Windows Prefetch files for application execution history",
            category="disk",
            executable="PECmd.py",
            parameters={
                "prefetch_path": {"type": "path", "required": True, "flag": "--f"},
                "output_dir": {"type": "path", "flag": "--o"},
                "json_output": {"type": "boolean", "flag": "--json", "default": True}
            },
            output_format="json",
            timeout_seconds=120
        ))
        
        self._register_tool(ToolDefinition(
            name="extract_registry",
            description="Parse Windows Registry hives using RegRipper",
            category="disk",
            executable="rip.py",
            parameters={
                "registry_path": {"type": "path", "required": True, "flag": "-r"},
                "hive_type": {"type": "string", "flag": "-a",
                            "choices": ["system", "software", "sam", "security", "ntuser", "usrclass"]},
                "output_format": {"type": "string", "flag": "-f", "default": "json",
                                "choices": ["json", "text", "csv"]}
            },
            output_format="json",
            timeout_seconds=180
        ))
        
        self._register_tool(ToolDefinition(
            name="extract_usn_journal",
            description="Parse USN Journal for file system change tracking",
            category="disk",
            executable="USNJrnlParser.py",
            parameters={
                "usn_path": {"type": "path", "required": True, "flag": "--f"},
                "output_dir": {"type": "path", "flag": "--o"},
                "json_output": {"type": "boolean", "flag": "--json", "default": True}
            },
            output_format="json",
            timeout_seconds=180
        ))
        
        # Log Analysis Tools
        self._register_tool(ToolDefinition(
            name="parse_event_logs",
            description="Parse Windows Event Logs (EVTX files)",
            category="logs",
            executable="evtx_export.py",
            parameters={
                "evtx_path": {"type": "path", "required": True, "flag": "--csv_path"},
                "output_dir": {"type": "path", "flag": "--output_dir"},
                "json_output": {"type": "boolean", "flag": "--json", "default": True}
            },
            output_format="json",
            timeout_seconds=120
        ))
        
        self._register_tool(ToolDefinition(
            name="analyze_browser_history",
            description="Parse web browser history databases",
            category="logs",
            executable="BrowserHistory.py",
            parameters={
                "browser_path": {"type": "path", "required": True, "flag": "--browser_path"},
                "browser_type": {"type": "string", "flag": "--browser_type",
                               "choices": ["chrome", "firefox", "edge"]},
                "json_output": {"type": "boolean", "flag": "--json", "default": True}
            },
            output_format="json",
            timeout_seconds=120
        ))
        
        self._register_tool(ToolDefinition(
            name="parse_powershell_logs",
            description="Parse PowerShell script block logs for command history",
            category="logs",
            executable="Parse-PowerShellLog.py",
            parameters={
                "log_path": {"type": "path", "required": True, "flag": "--f"},
                "output_dir": {"type": "path", "flag": "--o"},
                "json_output": {"type": "boolean", "flag": "--json", "default": True}
            },
            output_format="json",
            timeout_seconds=120
        ))
        
        # Network Analysis Tools
        self._register_tool(ToolDefinition(
            name="analyze_pcap",
            description="Analyze network capture file for connections and protocols",
            category="network",
            executable="tshark",
            parameters={
                "pcap_path": {"type": "path", "required": True, "flag": "-r"},
                "display_filter": {"type": "string", "flag": "-Y"},
                "fields": {"type": "list", "flag": "-T", "items": ["fields", "json", "psml"]},
                "max_packets": {"type": "integer", "flag": "-c", "default": 10000}
            },
            output_format="json",
            timeout_seconds=180
        ))
        
        self._register_tool(ToolDefinition(
            name="extract_dns_from_pcap",
            description="Extract DNS queries from network capture",
            category="network",
            executable="tshark",
            parameters={
                "pcap_path": {"type": "path", "required": True, "flag": "-r"},
                "display_filter": {"type": "string", "flag": "-Y", "default": "dns"},
                "fields": {"type": "list", "flag": "-T", "items": ["fields"]},
                "max_packets": {"type": "integer", "flag": "-c", "default": 50000}
            },
            output_format="text",
            timeout_seconds=120
        ))
        
        self._register_tool(ToolDefinition(
            name="extract_http_from_pcap",
            description="Extract HTTP requests and responses from network capture",
            category="network",
            executable="tshark",
            parameters={
                "pcap_path": {"type": "path", "required": True, "flag": "-r"},
                "display_filter": {"type": "string", "flag": "-Y", "default": "http"},
                "max_packets": {"type": "integer", "flag": "-c", "default": 10000}
            },
            output_format="json",
            timeout_seconds=120
        ))
        
        # Timeline and Correlation Tools
        self._register_tool(ToolDefinition(
            name="create_super_timeline",
            description="Create comprehensive timeline from multiple sources using Plaso",
            category="timeline",
            executable="log2timeline.py",
            parameters={
                "source_path": {"type": "path", "required": True, "flag": ""},
                "output_path": {"type": "path", "required": True, "flag": "-o"},
                "storage_format": {"type": "string", "flag": "--storage_file", "default": "plaso"},
                "parsers": {"type": "list", "flag": "--parsers"}
            },
            output_format="text",
            timeout_seconds=600,
            max_output_chars=100000
        ))
        
        self._register_tool(ToolDefinition(
            name="query_timeline",
            description="Query and filter Plaso timeline database",
            category="timeline",
            executable="psort.py",
            parameters={
                "storage_path": {"type": "path", "required": True, "flag": ""},
                "output_format": {"type": "string", "flag": "-o", "default": "json",
                                "choices": ["json", "dynamic", "l2tcsv"]},
                "query": {"type": "string", "flag": "-q"},
                "date_filter": {"type": "string", "flag": "-d"}
            },
            output_format="json",
            timeout_seconds=120
        ))
        
        # File Analysis Tools
        self._register_tool(ToolDefinition(
            name="bulk_extract",
            description="Extract specific data types (emails, IPs, URLs) from raw data",
            category="file_analysis",
            executable="bulk_extractor",
            parameters={
                "input_path": {"type": "path", "required": True, "flag": ""},
                "output_dir": {"type": "path", "required": True, "flag": "-o"},
                "extractors": {"type": "list", "flag": "-e",
                             "items": ["email", "ip", "url", "phone"]}
            },
            output_format="text",
            timeout_seconds=300
        ))
        
        self._register_tool(ToolDefinition(
            name="calculate_file_hash",
            description="Calculate cryptographic hashes for evidence files",
            category="file_analysis",
            executable="md5sum",
            parameters={
                "file_path": {"type": "path", "required": True, "flag": ""},
                "hash_type": {"type": "string", "flag": "", "default": "sha256",
                            "choices": ["md5", "sha1", "sha256"]}
            },
            output_format="text",
            timeout_seconds=60
        ))
        
        # System Information Tools
        self._register_tool(ToolDefinition(
            name="get_system_info",
            description="Extract basic system information from registry",
            category="system",
            executable="reg_lookup.py",
            parameters={
                "hive_path": {"type": "path", "required": True, "flag": "-r"},
                "key_path": {"type": "string", "flag": "-k", 
                           "default": "ControlSet001\\Control\\ComputerName"},
                "value_name": {"type": "string", "flag": "-v"}
            },
            output_format="text",
            timeout_seconds=60
        ))
    
    def _register_tool(self, tool: ToolDefinition):
        """Register a tool in the registry."""
        self._tools[tool.name] = tool
    
    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        """Get a tool by name."""
        return self._tools.get(name)
    
    def get_all_tools(self) -> List[ToolDefinition]:
        """Get all registered tools."""
        return list(self._tools.values())
    
    def get_tools_by_category(self, category: str) -> List[ToolDefinition]:
        """Get all tools in a specific category."""
        return [t for t in self._tools.values() if t.category == category]
    
    def get_categories(self) -> List[str]:
        """Get all available tool categories."""
        return list(set(t.category for t in self._tools.values()))
