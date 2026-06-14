"""Tests for Agent Orchestrator and Self-Correction"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from src.agent.orchestrator import AgentOrchestrator, AnalysisPhase
from src.agent.planner import AnalysisPlanner
from src.agent.self_correction import SelfCorrectionEngine
from src.validation.accuracy import AccuracyTracker, Finding


class TestAnalysisPlanner:
    """Tests for the analysis planner."""
    
    def test_planner_initialization(self):
        """Test planner initialization."""
        planner = AnalysisPlanner()
        assert len(planner.phase_tools) > 0
    
    def test_create_plan(self, tmp_path):
        """Test plan creation."""
        planner = AnalysisPlanner()
        plan = planner.create_plan("Test case", tmp_path)
        
        assert "case_description" in plan
        assert "phases" in plan
        assert "current_phase" in plan
        assert "remaining_phases" in plan
    
    def test_detect_evidence_types(self, tmp_path):
        """Test evidence type detection."""
        planner = AnalysisPlanner()
        
        # Create test evidence files
        (tmp_path / "memory.raw").touch()
        (tmp_path / "$MFT").touch()
        (tmp_path / "test.pcap").touch()
        
        evidence_types = planner._detect_evidence_types(tmp_path)
        assert "memory" in evidence_types
        assert "mft" in evidence_types
        assert "network" in evidence_types
    
    def test_select_tools_for_phase(self, tmp_path):
        """Test tool selection for phases."""
        planner = AnalysisPlanner()
        evidence_types = ["memory", "disk"]
        
        tools = planner._select_tools_for_phase(
            AnalysisPhase.EVIDENCE_COLLECTION,
            evidence_types,
            "Test case"
        )
        
        assert len(tools) > 0
        assert all("tool" in t for t in tools)


class TestSelfCorrectionEngine:
    """Tests for self-correction engine."""
    
    def test_engine_initialization(self):
        """Test engine initialization."""
        engine = SelfCorrectionEngine()
        assert len(engine.consistency_rules) > 0
        assert len(engine.hallucination_indicators) > 0
    
    def test_analyze_results(self):
        """Test result analysis."""
        engine = SelfCorrectionEngine()
        
        phase_result = {
            "phase": "evidence_collection",
            "tools_executed": [],
            "findings": [],
            "errors": []
        }
        
        findings = []
        corrections = engine.analyze_results(phase_result, findings)
        
        assert isinstance(corrections, list)
    
    def test_handle_tool_failure(self):
        """Test tool failure handling."""
        engine = SelfCorrectionEngine()
        
        failure = {
            "tool": "volatility_processes",
            "error": "Profile not found"
        }
        
        correction = engine._handle_tool_failure(failure)
        assert correction is not None
        assert correction["type"] == "tool_failure"
        assert "alternative" in correction
    
    def test_detect_hallucinations(self):
        """Test hallucination detection."""
        engine = SelfCorrectionEngine()
        
        # Finding without evidence
        finding = Finding(
            category="test",
            severity="high",
            description="Test finding",
            evidence_source="test_tool",
            confidence=0.9,
            raw_evidence=""
        )
        
        corrections = engine._detect_hallucinations([finding])
        assert len(corrections) > 0
        assert any(c["type"] == "hallucination" for c in corrections)


class TestAccuracyTracker:
    """Tests for accuracy tracking."""
    
    def test_tracker_initialization(self):
        """Test tracker initialization."""
        tracker = AccuracyTracker()
        assert len(tracker.findings) == 0
    
    def test_add_finding(self):
        """Test adding findings."""
        tracker = AccuracyTracker()
        
        finding = Finding(
            category="test",
            severity="high",
            description="Test finding",
            evidence_source="test_tool",
            confidence=0.8
        )
        
        tracker.add_finding(finding)
        assert len(tracker.findings) == 1
    
    def test_calculate_metrics(self):
        """Test metrics calculation."""
        tracker = AccuracyTracker()
        
        # Add findings
        for i in range(5):
            finding = Finding(
                category=f"test_{i}",
                severity="high",
                description=f"Finding {i}",
                evidence_source="test_tool",
                confidence=0.8
            )
            tracker.add_finding(finding)
        
        metrics = tracker.calculate_metrics()
        
        assert metrics["total_findings"] == 5
        assert metrics["average_confidence"] == 0.8
    
    def test_hallucination_risk_assessment(self):
        """Test hallucination risk assessment."""
        tracker = AccuracyTracker()
        
        # Add high-risk finding (no evidence)
        finding = Finding(
            category="test",
            severity="high",
            description="Test finding",
            evidence_source="test_tool",
            confidence=0.95,
            raw_evidence=""
        )
        tracker.add_finding(finding)
        
        risk = tracker._assess_hallucination_risk()
        assert "risk_score" in risk
        assert "risk_level" in risk
