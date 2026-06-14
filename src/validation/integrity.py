"""Evidence Integrity Validator

Ensures forensic evidence integrity throughout the analysis process:
- Hash verification of evidence files
- Read-only access enforcement
- Chain of custody tracking
- Tamper detection
"""

from typing import Any, Dict, List, Optional
from pathlib import Path
from datetime import datetime
import hashlib
import json
import os


class EvidenceIntegrityValidator:
    """
    Validates and maintains evidence integrity throughout analysis.
    
    Key principles:
    1. Original evidence is never modified
    2. All access is logged
    3. Hashes verify integrity
    4. Chain of custody is maintained
    """
    
    def __init__(self, evidence_path: str):
        self.evidence_path = Path(evidence_path)
        self.integrity_log: List[Dict[str, Any]] = []
        self.original_hashes: Dict[str, str] = {}
        self.current_hashes: Dict[str, str] = {}
        
    def register_evidence(self, file_path: str) -> Dict[str, Any]:
        """Register an evidence file and compute its initial hash."""
        full_path = self.evidence_path / file_path if not os.path.isabs(file_path) else Path(file_path)
        
        if not full_path.exists():
            return {
                "success": False,
                "error": f"Evidence file not found: {full_path}"
            }
        
        # Compute hash
        file_hash = self._compute_hash(full_path)
        
        # Store original hash
        self.original_hashes[str(full_path)] = file_hash
        self.current_hashes[str(full_path)] = file_hash
        
        # Log registration
        self._log_event("register", str(full_path), file_hash)
        
        return {
            "success": True,
            "file": str(full_path),
            "hash": file_hash,
            "algorithm": "sha256",
            "size": full_path.stat().st_size,
            "registered_at": datetime.utcnow().isoformat()
        }
    
    def verify_integrity(self, file_path: str) -> Dict[str, Any]:
        """Verify evidence file integrity against original hash."""
        full_path = self.evidence_path / file_path if not os.path.isabs(file_path) else Path(file_path)
        
        if not full_path.exists():
            return {
                "success": False,
                "error": f"Evidence file not found: {full_path}",
                "integrity": "missing"
            }
        
        # Compute current hash
        current_hash = self._compute_hash(full_path)
        
        # Get original hash
        original_hash = self.original_hashes.get(str(full_path))
        
        if not original_hash:
            return {
                "success": False,
                "error": "File not registered",
                "integrity": "unknown"
            }
        
        # Compare hashes
        integrity_valid = current_hash == original_hash
        
        # Update current hash
        self.current_hashes[str(full_path)] = current_hash
        
        # Log verification
        self._log_event("verify", str(full_path), current_hash, 
                       valid=integrity_valid)
        
        return {
            "success": True,
            "file": str(full_path),
            "integrity_valid": integrity_valid,
            "original_hash": original_hash,
            "current_hash": current_hash,
            "algorithm": "sha256",
            "verified_at": datetime.utcnow().isoformat()
        }
    
    def verify_all(self) -> Dict[str, Any]:
        """Verify integrity of all registered evidence files."""
        results = {}
        all_valid = True
        
        for file_path in self.original_hashes:
            result = self.verify_integrity(file_path)
            results[file_path] = result
            
            if not result.get("integrity_valid", False):
                all_valid = False
        
        return {
            "success": True,
            "all_valid": all_valid,
            "files_verified": len(results),
            "results": results,
            "verified_at": datetime.utcnow().isoformat()
        }
    
    def log_access(self, file_path: str, access_type: str, 
                   purpose: str) -> Dict[str, Any]:
        """Log access to evidence file."""
        full_path = self.evidence_path / file_path if not os.path.isabs(file_path) else Path(file_path)
        
        self._log_event("access", str(full_path), None,
                       access_type=access_type, purpose=purpose)
        
        return {
            "success": True,
            "file": str(full_path),
            "access_type": access_type,
            "purpose": purpose,
            "logged_at": datetime.utcnow().isoformat()
        }
    
    def log_operation(self, file_path: str, operation: str,
                     input_files: List[str], output_files: List[str]) -> Dict[str, Any]:
        """Log an operation performed on evidence."""
        self._log_event("operation", file_path, None,
                       operation=operation,
                       input_files=input_files,
                       output_files=output_files)
        
        return {
            "success": True,
            "operation": operation,
            "logged_at": datetime.utcnow().isoformat()
        }
    
    def _compute_hash(self, file_path: Path, algorithm: str = "sha256") -> str:
        """Compute cryptographic hash of a file."""
        hash_func = hashlib.new(algorithm)
        
        with open(file_path, "rb") as f:
            # Read in chunks to handle large files
            for chunk in iter(lambda: f.read(8192), b""):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()
    
    def _log_event(self, event_type: str, file_path: str, 
                   file_hash: Optional[str], **kwargs):
        """Log an integrity event."""
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "file_path": file_path,
            "file_hash": file_hash,
            **kwargs
        }
        self.integrity_log.append(event)
    
    def get_integrity_log(self) -> List[Dict[str, Any]]:
        """Return full integrity log."""
        return self.integrity_log
    
    def get_integrity_report(self) -> Dict[str, Any]:
        """Generate integrity report for audit purposes."""
        events_by_type = {}
        for event in self.integrity_log:
            event_type = event["event_type"]
            events_by_type[event_type] = events_by_type.get(event_type, 0) + 1
        
        return {
            "report_timestamp": datetime.utcnow().isoformat(),
            "evidence_path": str(self.evidence_path),
            "registered_files": len(self.original_hashes),
            "events_by_type": events_by_type,
            "total_events": len(self.integrity_log),
            "files": [
                {
                    "path": path,
                    "original_hash": self.original_hashes.get(path),
                    "current_hash": self.current_hashes.get(path),
                    "integrity_valid": self.original_hashes.get(path) == self.current_hashes.get(path)
                }
                for path in self.original_hashes
            ]
        }
    
    def save_state(self, state_path: str):
        """Save integrity state to file for persistence."""
        state = {
            "evidence_path": str(self.evidence_path),
            "original_hashes": self.original_hashes,
            "current_hashes": self.current_hashes,
            "integrity_log": self.integrity_log
        }
        
        with open(state_path, "w") as f:
            json.dump(state, f, indent=2)
    
    def load_state(self, state_path: str):
        """Load integrity state from file."""
        with open(state_path, "r") as f:
            state = json.load(f)
        
        self.evidence_path = Path(state["evidence_path"])
        self.original_hashes = state["original_hashes"]
        self.current_hashes = state["current_hashes"]
        self.integrity_log = state["integrity_log"]
