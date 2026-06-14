#!/usr/bin/env python3
"""
Protocol SIFT Enhanced - Autonomous Incident Response Agent

Main entry point for the agent. This script:
1. Initializes the MCP Server with forensic tools
2. Sets up the agent orchestrator with self-correction
3. Runs autonomous analysis on provided evidence
4. Generates comprehensive audit trail and reports
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from datetime import datetime

from src.mcp_server.server import SIFTMCPServer
from src.agent.orchestrator import AgentOrchestrator
from src.validation.integrity import EvidenceIntegrityValidator
from src.logging.audit import AuditTrailLogger


def setup_logging(log_level: str = "INFO"):
    """Set up logging configuration."""
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("sift_agent.log")
        ]
    )


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Protocol SIFT Enhanced - Autonomous Incident Response Agent"
    )
    
    parser.add_argument(
        "evidence_path",
        type=str,
        help="Path to evidence directory"
    )
    
    parser.add_argument(
        "--case-description", "-c",
        type=str,
        default="Full forensic analysis of provided evidence",
        help="Description of the case or analysis request"
    )
    
    parser.add_argument(
        "--output-dir", "-o",
        type=str,
        default="output",
        help="Directory for output files"
    )
    
    parser.add_argument(
        "--log-level", "-l",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level"
    )
    
    parser.add_argument(
        "--max-iterations", "-m",
        type=int,
        default=10,
        help="Maximum analysis iterations (prevents runaway execution)"
    )
    
    parser.add_argument(
        "--generate-report", "-r",
        action="store_true",
        help="Generate comprehensive accuracy report"
    )
    
    return parser.parse_args()


def main():
    """Main execution function."""
    args = parse_arguments()
    
    # Set up logging
    setup_logging(args.log_level)
    logger = logging.getLogger(__name__)
    
    logger.info("=" * 60)
    logger.info("Protocol SIFT Enhanced - Autonomous Incident Response Agent")
    logger.info("=" * 60)
    logger.info(f"Evidence Path: {args.evidence_path}")
    logger.info(f"Case: {args.case_description}")
    logger.info(f"Output Dir: {args.output_dir}")
    
    # Create output directory
    output_path = Path(args.output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Initialize components
    logger.info("Initializing system components...")
    
    # 1. MCP Server
    mcp_server = SIFTMCPServer(evidence_base_path=args.evidence_path)
    logger.info(f"MCP Server initialized with {len(mcp_server.tool_registry.get_all_tools())} tools")
    
    # 2. Evidence Integrity Validator
    integrity_validator = EvidenceIntegrityValidator(args.evidence_path)
    logger.info("Evidence Integrity Validator initialized")
    
    # 3. Audit Trail Logger
    audit_logger = AuditTrailLogger(log_dir=str(output_path / "logs"))
    logger.info(f"Audit Trail Logger initialized (Session: {audit_logger.session_id})")
    
    # 4. Agent Orchestrator
    orchestrator = AgentOrchestrator(mcp_server, args.evidence_path)
    orchestrator.max_iterations = args.max_iterations
    logger.info("Agent Orchestrator initialized")
    
    # Register evidence files for integrity tracking
    logger.info("Registering evidence files for integrity tracking...")
    evidence_path = Path(args.evidence_path)
    if evidence_path.exists():
        for evidence_file in evidence_path.rglob("*"):
            if evidence_file.is_file():
                integrity_validator.register_evidence(str(evidence_file))
    
    # Run analysis
    logger.info("=" * 60)
    logger.info("Starting autonomous analysis...")
    logger.info("=" * 60)
    
    try:
        # Execute analysis
        results = orchestrator.analyze(args.case_description)
        
        # Log final results
        audit_logger.log_agent_decision(
            decision_type="analysis_complete",
            reasoning=f"Analysis completed after {results['summary']['iterations']} iterations",
            inputs={"case_description": args.case_description},
            outputs={"findings_count": results['summary']['total_findings']},
            confidence=0.9
        )
        
        # Save results
        results_file = output_path / "analysis_results.json"
        with open(results_file, "w") as f:
            json.dump(results, f, indent=2, default=str)
        logger.info(f"Results saved to: {results_file}")
        
        # Generate accuracy report
        if args.generate_report:
            logger.info("Generating accuracy report...")
            accuracy_report = orchestrator.accuracy_tracker.generate_accuracy_report()
            
            report_file = output_path / "accuracy_report.json"
            with open(report_file, "w") as f:
                json.dump(accuracy_report, f, indent=2, default=str)
            logger.info(f"Accuracy report saved to: {report_file}")
        
        # Generate audit trail
        logger.info("Generating audit trail...")
        audit_trail = audit_logger.generate_full_audit_trail()
        
        audit_file = output_path / "audit_trail.json"
        with open(audit_file, "w") as f:
            json.dump(audit_trail, f, indent=2, default=str)
        logger.info(f"Audit trail saved to: {audit_file}")
        
        # Generate integrity report
        logger.info("Generating integrity report...")
        integrity_report = integrity_validator.get_integrity_report()
        
        integrity_file = output_path / "integrity_report.json"
        with open(integrity_file, "w") as f:
            json.dump(integrity_report, f, indent=2, default=str)
        logger.info(f"Integrity report saved to: {integrity_file}")
        
        # Print summary
        print("\n" + "=" * 60)
        print("ANALYSIS COMPLETE")
        print("=" * 60)
        print(f"Total Findings: {results['summary']['total_findings']}")
        print(f"High Severity: {results['summary']['high_severity']}")
        print(f"Medium Severity: {results['summary']['medium_severity']}")
        print(f"Low Severity: {results['summary']['low_severity']}")
        print(f"Analysis Duration: {results['summary']['duration_seconds']:.2f} seconds")
        print(f"Iterations: {results['summary']['iterations']}")
        print(f"\nOutput Files:")
        print(f"  - Results: {results_file}")
        print(f"  - Audit Trail: {audit_file}")
        print(f"  - Integrity Report: {integrity_file}")
        if args.generate_report:
            print(f"  - Accuracy Report: {report_file}")
        print("=" * 60)
        
        return 0
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
