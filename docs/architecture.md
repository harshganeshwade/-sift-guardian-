# Architecture Document

## System Overview

Protocol SIFT Enhanced is a hybrid autonomous incident response agent combining a Custom MCP Server with Agent Orchestration Layer.

## Architecture Pattern

**Hybrid: Custom MCP Server + Agent Orchestration**

This combines the structural safety of typed MCP functions with intelligent self-correcting agent behavior.

## Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        USER INTERFACE                           │
│                    (Command Line / CLI)                         │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      MAIN ENTRY POINT                           │
│                        (main.py)                               │
└─────────────────────────────┬───────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
              ▼               ▼               ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│   MCP SERVER     │ │  AGENT ORCHESTR. │ │  AUDIT LOGGER    │
│  (Typed Funcs)   │ │  (Self-Correct)  │ │  (Traceability)  │
└────────┬─────────┘ └────────┬─────────┘ └────────┬─────────┘
         │                    │                    │
         │    ┌───────────────┼───────────────┐    │
         │    │               │               │    │
         ▼    ▼               ▼               ▼    ▼
┌─────────────────────────────────────────────────────────────────┐
│                    VALIDATION LAYER                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │ Tool Validation  │  │  Accuracy Track │  │ Evidence Integ. │ │
│  │  (Input Sanit.)  │  │ (Hallucinat.)   │  │ (Hash Verify)   │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   SIFT WORKSTATION TOOLS                        │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐          │
│  │Volatility│ │ MFTECmd  │ │ EvtxExp  │ │  tshark  │   ...    │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     EVIDENCE SOURCE                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐          │
│  │  Memory  │ │   Disk   │ │   Logs   │ │ Network  │   ...    │
│  │  Images  │ │  Images  │ │  (EVTX)  │ │ (PCAP)   │          │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘          │
└─────────────────────────────────────────────────────────────────┘
```

## Security Boundaries

### Prompt-Based Guardrails (Soft)
- Analysis phase sequencing
- Tool selection heuristics
- Confidence thresholds

### Architectural Guardrails (Hard)
- **MCP Server** - Only exposes typed, read-only functions
- **Input Validation** - Path traversal prevention, injection detection
- **Evidence Integrity** - Hash verification, tamper detection

### Trust Boundary Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         UNTRUSTED                               │
│                    (User Input/Commands)                        │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼ [INPUT VALIDATION]
┌─────────────────────────────────────────────────────────────────┐
│                    SEMI-TRUSTED                                 │
│              (Agent Orchestration Layer)                        │
│         • Can request tool execution                           │
│         • Cannot directly access evidence                      │
│         • Decisions logged for audit                           │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼ [MCP SERVER]
┌─────────────────────────────────────────────────────────────────┐
│                       TRUSTED                                   │
│                  (MCP Server Layer)                             │
│         • Validates all inputs                                 │
│         • Enforces read-only access                            │
│         • Logs all operations                                  │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼ [HASH VERIFICATION]
┌─────────────────────────────────────────────────────────────────┐
│                    PROTECTED                                    │
│                  (Evidence Storage)                             │
│         • SHA-256 hash verification                            │
│         • Chain of custody tracking                            │
│         • Tamper detection alerts                              │
└─────────────────────────────────────────────────────────────────┘
```

## Data Flow

### 1. Triage Phase
```
User Request → Agent Orchestrator → System Info Tools → Initial Assessment
```

### 2. Evidence Collection Phase
```
Assessment → Tool Selection → MCP Execution → Finding Extraction
```

### 3. Self-Correction Phase
```
Findings → Consistency Check → Gap Detection → Plan Revision
```

### 4. Validation Phase
```
Cross-Reference → Confidence Update → Hallucination Check → Verified Findings
```

### 5. Reporting Phase
```
Verified Findings → Audit Trail → Reports → Output Files
```

## Key Design Decisions

### 1. Hybrid Architecture
**Decision**: Combine MCP Server with Agent Orchestration

**Rationale**: 
- MCP provides structural safety (hard guardrails)
- Agent provides intelligence (soft guardrails)
- Best of both worlds

### 2. Senior Analyst Thinking Patterns
**Decision**: Model analysis after senior analyst workflows

**Rationale**:
- Senior analysts are better at catching inconsistencies
- They know when to dig deeper
- They validate before reporting

### 3. Evidence Integrity First
**Decision**: Hash verification for all evidence

**Rationale**:
- Forensic soundness requires integrity
- Court admissibility depends on it
- Trust but verify principle

### 4. Self-Correction Engine
**Decision**: Build explicit self-correction system

**Rationale**:
- LLMs can hallucinate
- Single-pass analysis misses things
- Iterative improvement catches errors

## Token Usage Optimization

The system minimizes context window usage:

1. **Output Parsing** - Tool outputs parsed to extract relevant data only
2. **Summarization** - Large outputs summarized before storage
3. **Selective Tool Execution** - Only relevant tools run per phase
4. **Finding Deduplication** - Similar findings merged

## Extensibility

### Adding New Tools
1. Add tool definition to `tools.py`
2. Implement execution in `server.py`
3. Add findings extraction in `orchestrator.py`

### Adding New Validation Rules
1. Add consistency rule to `self_correction.py`
2. Update confidence calculation in `accuracy.py`

### Adding New Phases
1. Add phase to `AnalysisPhase` enum
2. Add tool selection in `planner.py`
3. Update orchestrator phase handling
