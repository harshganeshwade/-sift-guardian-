"""Tests for Validation Components"""

import pytest
from pathlib import Path

from src.validation.integrity import EvidenceIntegrityValidator


class TestEvidenceIntegrityValidator:
    """Tests for evidence integrity validation."""
    
    def test_validator_initialization(self, tmp_path):
        """Test validator initialization."""
        validator = EvidenceIntegrityValidator(str(tmp_path))
        assert validator.evidence_path == tmp_path
    
    def test_register_evidence(self, tmp_path):
        """Test evidence file registration."""
        validator = EvidenceIntegrityValidator(str(tmp_path))
        
        # Create test file
        test_file = tmp_path / "test_evidence.txt"
        test_file.write_text("test evidence content")
        
        result = validator.register_evidence("test_evidence.txt")
        
        assert result["success"] is True
        assert "hash" in result
        assert result["algorithm"] == "sha256"
    
    def test_verify_integrity(self, tmp_path):
        """Test integrity verification."""
        validator = EvidenceIntegrityValidator(str(tmp_path))
        
        # Create and register test file
        test_file = tmp_path / "test_evidence.txt"
        test_file.write_text("test evidence content")
        
        validator.register_evidence("test_evidence.txt")
        
        # Verify integrity
        result = validator.verify_integrity("test_evidence.txt")
        
        assert result["success"] is True
        assert result["integrity_valid"] is True
    
    def test_detect_tampering(self, tmp_path):
        """Test tamper detection."""
        validator = EvidenceIntegrityValidator(str(tmp_path))
        
        # Create and register test file
        test_file = tmp_path / "test_evidence.txt"
        test_file.write_text("test evidence content")
        
        validator.register_evidence("test_evidence.txt")
        
        # Modify file (tamper)
        test_file.write_text("modified content")
        
        # Verify integrity
        result = validator.verify_integrity("test_evidence.txt")
        
        assert result["success"] is True
        assert result["integrity_valid"] is False
    
    def test_verify_all(self, tmp_path):
        """Test verify all files."""
        validator = EvidenceIntegrityValidator(str(tmp_path))
        
        # Create multiple test files
        for i in range(3):
            test_file = tmp_path / f"evidence_{i}.txt"
            test_file.write_text(f"evidence content {i}")
            validator.register_evidence(f"evidence_{i}.txt")
        
        # Verify all
        result = validator.verify_all()
        
        assert result["success"] is True
        assert result["all_valid"] is True
        assert result["files_verified"] == 3
    
    def test_integrity_report(self, tmp_path):
        """Test integrity report generation."""
        validator = EvidenceIntegrityValidator(str(tmp_path))
        
        # Create and register test file
        test_file = tmp_path / "test_evidence.txt"
        test_file.write_text("test evidence content")
        
        validator.register_evidence("test_evidence.txt")
        validator.verify_integrity("test_evidence.txt")
        
        report = validator.get_integrity_report()
        
        assert "registered_files" in report
        assert "total_events" in report
        assert "files" in report
