"""Accuracy Tracking System

Tracks findings accuracy, detects potential hallucinations,
and provides metrics for the accuracy report.
"""

from typing import Any, Dict, List, Optional
from datetime import datetime
from dataclasses import dataclass, field
import hashlib
import json


@dataclass
class Finding:
    """Represents a single forensic finding."""
    category: str
    severity: str  # high, medium, low, info
    description: str
    evidence_source: str
    confidence: float  # 0.0 to 1.0
    raw_evidence: str = ""
    timestamp: Optional[datetime] = None
    finding_id: str = ""
    verified: bool = False
    false_positive: bool = False
    
    def __post_init__(self):
        if not self.finding_id:
            # Generate unique ID based on content
            content = f"{self.category}:{self.description}:{self.evidence_source}"
            self.finding_id = hashlib.md5(content.encode()).hexdigest()[:12]
        if not self.timestamp:
            self.timestamp = datetime.utcnow()


class AccuracyTracker:
    """
    Tracks accuracy of forensic findings and detects potential hallucinations.
    
    Metrics tracked:
    - Total findings
    - Verified vs unverified findings
    - False positive rate
    - Confidence distribution
    - Hallucination indicators
    """
    
    def __init__(self):
        self.findings: List[Finding] = []
        self.verification_log: List[Dict[str, Any]] = []
        self.ground_truth: Dict[str, Any] = {}
        
    def add_finding(self, finding: Finding):
        """Add a finding to track."""
        self.findings.append(finding)
    
    def verify_finding(self, finding_id: str, verified: bool, 
                      false_positive: bool = False, notes: str = ""):
        """Verify a finding against ground truth or manual review."""
        for finding in self.findings:
            if finding.finding_id == finding_id:
                finding.verified = verified
                finding.false_positive = false_positive
                
                self.verification_log.append({
                    "finding_id": finding_id,
                    "timestamp": datetime.utcnow().isoformat(),
                    "verified": verified,
                    "false_positive": false_positive,
                    "notes": notes
                })
                break
    
    def load_ground_truth(self, ground_truth: Dict[str, Any]):
        """Load ground truth data for accuracy comparison."""
        self.ground_truth = ground_truth
    
    def calculate_metrics(self) -> Dict[str, Any]:
        """Calculate comprehensive accuracy metrics."""
        if not self.findings:
            return self._empty_metrics()
        
        total = len(self.findings)
        verified = len([f for f in self.findings if f.verified])
        false_positives = len([f for f in self.findings if f.false_positive])
        
        # Confidence distribution
        high_confidence = len([f for f in self.findings if f.confidence >= 0.8])
        medium_confidence = len([f for f in self.findings if 0.5 <= f.confidence < 0.8])
        low_confidence = len([f for f in self.findings if f.confidence < 0.5])
        
        # Severity distribution
        severity_dist = {}
        for f in self.findings:
            severity_dist[f.severity] = severity_dist.get(f.severity, 0) + 1
        
        # Category distribution
        category_dist = {}
        for f in self.findings:
            category_dist[f.category] = category_dist.get(f.category, 0) + 1
        
        # Calculate rates
        verification_rate = verified / total if total > 0 else 0
        false_positive_rate = false_positives / total if total > 0 else 0
        
        # Hallucination indicators
        hallucination_risk = self._assess_hallucination_risk()
        
        return {
            "total_findings": total,
            "verified_findings": verified,
            "false_positives": false_positives,
            "verification_rate": round(verification_rate, 3),
            "false_positive_rate": round(false_positive_rate, 3),
            "confidence_distribution": {
                "high": high_confidence,
                "medium": medium_confidence,
                "low": low_confidence
            },
            "severity_distribution": severity_dist,
            "category_distribution": category_dist,
            "hallucination_risk": hallucination_risk,
            "average_confidence": round(
                sum(f.confidence for f in self.findings) / total, 3
            )
        }
    
    def _assess_hallucination_risk(self) -> Dict[str, Any]:
        """Assess risk of hallucinations in findings."""
        risk_factors = []
        risk_score = 0
        
        for finding in self.findings:
            # Factor 1: High confidence without verification
            if finding.confidence > 0.9 and not finding.verified:
                risk_factors.append(f"Finding {finding.finding_id}: High confidence unverified")
                risk_score += 2
            
            # Factor 2: No raw evidence
            if not finding.raw_evidence or len(finding.raw_evidence) < 20:
                risk_factors.append(f"Finding {finding.finding_id}: Insufficient evidence")
                risk_score += 3
            
            # Factor 3: Single source finding
            if self._is_single_source(finding):
                risk_factors.append(f"Finding {finding.finding_id}: Single source only")
                risk_score += 1
        
        # Normalize risk score
        max_possible_risk = len(self.findings) * 6
        normalized_risk = risk_score / max_possible_risk if max_possible_risk > 0 else 0
        
        return {
            "risk_score": risk_score,
            "normalized_risk": round(normalized_risk, 3),
            "risk_level": "high" if normalized_risk > 0.5 else "medium" if normalized_risk > 0.25 else "low",
            "risk_factors": risk_factors[:10]  # Limit to top 10
        }
    
    def _is_single_source(self, finding: Finding) -> bool:
        """Check if finding comes from a single evidence source."""
        # Count findings with same category but different sources
        sources = set()
        for f in self.findings:
            if f.category == finding.category:
                sources.add(f.evidence_source)
        
        return len(sources) == 1
    
    def _empty_metrics(self) -> Dict[str, Any]:
        """Return empty metrics when no findings exist."""
        return {
            "total_findings": 0,
            "verified_findings": 0,
            "false_positives": 0,
            "verification_rate": 0,
            "false_positive_rate": 0,
            "confidence_distribution": {"high": 0, "medium": 0, "low": 0},
            "severity_distribution": {},
            "category_distribution": {},
            "hallucination_risk": {
                "risk_score": 0,
                "normalized_risk": 0,
                "risk_level": "low",
                "risk_factors": []
            },
            "average_confidence": 0
        }
    
    def generate_accuracy_report(self) -> Dict[str, Any]:
        """Generate comprehensive accuracy report for competition submission."""
        metrics = self.calculate_metrics()
        
        # Compare against ground truth if available
        ground_truth_comparison = None
        if self.ground_truth:
            ground_truth_comparison = self._compare_to_ground_truth()
        
        return {
            "report_timestamp": datetime.utcnow().isoformat(),
            "summary": {
                "total_findings": metrics["total_findings"],
                "accuracy_rate": metrics["verification_rate"],
                "false_positive_rate": metrics["false_positive_rate"],
                "hallucination_risk": metrics["hallucination_risk"]["risk_level"]
            },
            "detailed_metrics": metrics,
            "ground_truth_comparison": ground_truth_comparison,
            "findings_list": [
                {
                    "id": f.finding_id,
                    "category": f.category,
                    "severity": f.severity,
                    "description": f.description,
                    "confidence": f.confidence,
                    "verified": f.verified,
                    "false_positive": f.false_positive,
                    "evidence_source": f.evidence_source
                }
                for f in self.findings
            ],
            "verification_log": self.verification_log
        }
    
    def _compare_to_ground_truth(self) -> Dict[str, Any]:
        """Compare findings to ground truth data."""
        if not self.ground_truth:
            return {}
        
        gt_findings = self.ground_truth.get("findings", [])
        
        # Calculate true positives, false positives, false negatives
        true_positives = 0
        false_positives = 0
        false_negatives = 0
        
        matched_gt = set()
        
        for finding in self.findings:
            matched = False
            for gt in gt_findings:
                if self._finding_matches_ground_truth(finding, gt):
                    true_positives += 1
                    matched_gt.add(gt.get("id"))
                    matched = True
                    break
            
            if not matched:
                false_positives += 1
        
        false_negatives = len(gt_findings) - len(matched_gt)
        
        # Calculate precision, recall, F1
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        return {
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1_score": round(f1_score, 3),
            "ground_truth_total": len(gt_findings),
            "agent_total": len(self.findings)
        }
    
    def _finding_matches_ground_truth(self, finding: Finding, 
                                     gt_finding: Dict[str, Any]) -> bool:
        """Check if a finding matches a ground truth entry."""
        # Simple matching based on category and description similarity
        gt_category = gt_finding.get("category", "")
        gt_description = gt_finding.get("description", "")
        
        # Category must match
        if finding.category != gt_category:
            return False
        
        # Check description similarity (simple substring check)
        if (gt_description.lower() in finding.description.lower() or
            finding.description.lower() in gt_description.lower()):
            return True
        
        return False
