# Protocol SIFT Enhanced - Autonomous Incident Response Agent

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

A fully autonomous incident response agent that extends Protocol SIFT with enhanced accuracy, self-correction, and evidence integrity. Built for the **Find Evil! Hackathon** by SANS Institute.

## 🎯 Overview

Protocol SIFT Enhanced is a purpose-built autonomous IR agent that:

- **Thinks like a senior analyst** - Sequences analysis logically, recognizes inconsistencies, and self-corrects
- **Enforces evidence integrity** - Architectural guardrails prevent evidence tampering
- **Minimizes hallucinations** - Multi-source validation and confidence tracking
- **Provides complete audit trails** - Every finding traceable to its source

### Architecture: Hybrid MCP Server + Agent Orchestration

This submission combines two architectural approaches:

1. **Custom MCP Server** - Typed forensic functions instead of generic shell commands
2. **Agent Orchestration Layer** - Self-correcting analysis with senior analyst thinking patterns

This hybrid architecture provides:
- ✅ Structural guardrails (agent cannot run destructive commands)
- ✅ Intelligent self-correction (detects and fixes analysis errors)
- ✅ Evidence integrity (hash verification, chain of custody)
- ✅ Hallucination detection (confidence tracking, corroboration checks)

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- SIFT Workstation (for actual forensic tools)
- Evidence files (disk images, memory captures, etc.)

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/protocol-sift-enhanced.git
cd protocol-sift-enhanced

# No external dependencies required!
# The system uses Python standard library only for maximum compatibility.
```

### Running the Agent

```bash
# Basic usage - analyze evidence in a directory
python main.py /path/to/evidence

# With options
python main.py /path/to/evidence \
    --case-description "Investigate potential ransomware incident" \
    --output-dir ./results \
    --max-iterations 10 \
    --generate-report \
    --log-level INFO
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `evidence_path` | Path to evidence directory | Required |
| `--case-description, -c` | Description of the case | "Full forensic analysis..." |
| `--output-dir, -o` | Output directory | `output` |
| `--log-level, -l` | Logging level | `INFO` |
| `--max-iterations, -m` | Max analysis iterations | `10` |
| `--generate-report, -r` | Generate accuracy report | `False` |

## 📁 Project Structure

```
protocol-sift-enhanced/
├── main.py                    # Main entry point
├── src/
│   ├── __init__.py
│   ├── mcp_server/           # Custom MCP Server
│   │   ├── __init__.py
│   │   ├── server.py         # MCP server with typed functions
│   │   ├── tools.py          # Forensic tool registry
│   │   └── validation.py     # Input validation
│   ├── agent/                # Agent Orchestration
│   │   ├── __init__.py
│   │   ├── orchestrator.py   # Main agent orchestrator
│   │   ├── planner.py        # Analysis planning
│   │   └── self_correction.py # Self-correction engine
│   ├── validation/           # Validation Systems
│   │   ├── __init__.py
│   │   ├── accuracy.py       # Accuracy tracking
│   │   └── integrity.py      # Evidence integrity
│   └── logging/              # Audit Trail
│       ├── __init__.py
│       └── audit.py          # Structured logging
├── tests/                    # Test Suite
│   ├── test_mcp_server.py
│   ├── test_agent.py
│   └── test_validation.py
├── docs/                     # Documentation
│   └── architecture.md
├── output/                   # Generated outputs
├── requirements.txt
├── pyproject.toml
└── README.md
```

## 🔧 Available Forensic Tools

The MCP Server exposes 20+ typed forensic functions:

### Memory Analysis
- `volatility_processes` - Extract process list from memory dump
- `volatility_network` - Extract network connections from memory
- `volatility_dlls` - List loaded DLLs
- `volatility_handles` - List open handles

### Disk Analysis
- `mft_timeline` - Parse MFT and create file system timeline
- `extract_amcache` - Parse Amcache.hve for application execution
- `extract_prefetch` - Parse Windows Prefetch files
- `extract_registry` - Parse Windows Registry hives
- `extract_usn_journal` - Parse USN Journal

### Log Analysis
- `parse_event_logs` - Parse Windows Event Logs
- `parse_powershell_logs` - Parse PowerShell script block logs
- `analyze_browser_history` - Parse web browser history

### Network Analysis
- `analyze_pcap` - Analyze network capture files
- `extract_dns_from_pcap` - Extract DNS queries
- `extract_http_from_pcap` - Extract HTTP requests

### Timeline Analysis
- `create_super_timeline` - Create comprehensive timeline with Plaso
- `query_timeline` - Query and filter Plaso timeline

## 🛡️ Security & Evidence Integrity

### Architectural Guardrails

The MCP Server enforces security at the architectural level:

1. **Read-Only Tools Only** - Only non-destructive tools are exposed
2. **Path Validation** - All file paths validated against evidence directory
3. **Input Sanitization** - Injection detection prevents command injection
4. **Hash Verification** - Evidence files tracked with SHA-256 hashes

### Evidence Integrity Workflow

```
1. Register Evidence → Compute initial hash
2. Analysis Execution → Log all access
3. Integrity Verification → Compare hashes
4. Tamper Detection → Alert on mismatch
```

### Audit Trail

Every action is logged with:
- Tool execution with inputs/outputs
- Agent decisions with reasoning
- Finding creation with confidence scores
- Self-correction events

## 📊 Self-Correction System

The agent implements senior analyst thinking patterns:

### Consistency Rules
- Memory findings should correlate with disk evidence
- Network activity should have DNS/HTTP corroboration
- PowerShell execution should appear in process list

### Hallucination Detection
- Flags findings without supporting evidence
- Detects unrealistic confidence levels
- Identifies temporal inconsistencies

### Automatic Correction
- Suggests alternative tools when failures occur
- Adds validation steps for inconsistencies
- Re-runs analysis with adjusted parameters

## 📈 Output Files

After analysis, the agent generates:

| File | Description |
|------|-------------|
| `analysis_results.json` | Complete findings and metrics |
| `audit_trail.json` | Full execution log |
| `integrity_report.json` | Evidence integrity verification |
| `accuracy_report.json` | Accuracy metrics (optional) |
| `logs/*.json` | Detailed execution logs |

## 🧪 Testing

```bash
# Run all tests
python -m pytest tests/

# Run with coverage
python -m pytest tests/ --cov=src

# Run specific test file
python -m pytest tests/test_mcp_server.py
```

## 📋 Competition Submission Components

### 1. Code Repository ✅
This repository contains all source code, tests, and documentation.

### 2. Demo Video
See `demo_video.mp4` for a 5-minute screencast demonstrating:
- Autonomous analysis of forensic evidence
- Self-correction sequence
- Complete audit trail generation

### 3. Architecture Diagram
See `docs/architecture.md` for detailed architecture documentation.

### 4. Written Project Description
See `docs/project_description.md` for:
- What it does
- How it was built
- Challenges faced
- Lessons learned
- Next steps

### 5. Dataset Documentation
See `docs/dataset_documentation.md` for:
- Test datasets used
- Data sources
- Findings summary

### 6. Accuracy Report
Generated by `--generate-report` flag:
- False positive analysis
- Missed artifacts
- Hallucination frequency
- Evidence integrity approach

### 7. Try-It-Out Instructions
See [Quick Start](#-quick-start) section above.

### 8. Agent Execution Logs
Complete audit trail in `output/audit_trail.json` with:
- Tool execution sequences
- Timestamps and token usage
- Finding traceability

## 🎯 Judging Criteria Alignment

| Criterion | Our Approach |
|-----------|--------------|
| **Autonomous Execution** | Self-correcting agent with gap detection |
| **IR Accuracy** | Multi-source validation, hallucination detection |
| **Breadth/Depth** | 20+ tools across 6 categories |
| **Constraint Implementation** | Architectural guardrails (not just prompts) |
| **Audit Trail** | Complete traceability from finding to tool |
| **Documentation** | Comprehensive README, architecture docs |

## 🔄 How Self-Correction Works

```
1. Execute analysis phase
2. Evaluate results for consistency
3. Check findings against rules:
   - Are there corroborating sources?
   - Do timestamps make sense?
   - Is confidence realistic?
4. If issues found:
   a. Log the correction
   b. Revise analysis plan
   c. Re-run with adjustments
5. Repeat until:
   - All findings validated
   - Max iterations reached
   - No more corrections needed
```

## 📚 Learn More

- [Protocol SIFT Documentation](https://www.sans.org/tools/sift-workstation/)
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [Find Evil! Hackathon](https://findevil.devpost.com/)

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- SANS Institute for Protocol SIFT
- Find Evil! Hackathon organizers
- Open source forensic tool maintainers

---

**Built with ❤️ for the Find Evil! Hackathon**
