"""Dashboard generator for Protocol SIFT Enhanced analysis output."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def normalize_distribution(distribution: Dict[str, Any]) -> Dict[str, int]:
    return {str(key): int(value or 0) for key, value in distribution.items()}


def build_card(title: str, value: Any, subtitle: Optional[str] = None) -> str:
    subtitle_html = f"<div class='card-subtitle'>{subtitle}</div>" if subtitle else ""
    return f"""
        <div class='card'>
            <div class='card-title'>{title}</div>
            <div class='card-value'>{value}</div>
            {subtitle_html}
        </div>
    """


def build_bar(label: str, value: int, max_value: int, color: str) -> str:
    width = 0 if max_value == 0 else int((value / max_value) * 100)
    return f"""
        <div class='bar-row'>
            <div class='bar-label'>{label}</div>
            <div class='bar-track'>
                <div class='bar-fill' style='width:{width}%; background:{color};'></div>
            </div>
            <div class='bar-value'>{value}</div>
        </div>
    """


def build_distribution_section(title: str, distribution: Dict[str, Any], colors: Dict[str, str]) -> str:
    data = normalize_distribution(distribution)
    if not data:
        return f"<div class='section'><h3>{title}</h3><p>No data available.</p></div>"

    max_value = max(data.values()) or 1
    rows = [build_bar(label, value, max_value, colors.get(label, "#4a90e2")) for label, value in data.items()]
    return f"""
        <div class='section'>
            <h3>{title}</h3>
            <div class='bar-chart'>
                {''.join(rows)}
            </div>
        </div>
    """


def build_trace_list(trace: List[Dict[str, Any]]) -> str:
    if not trace:
        return "<p>No execution trace available.</p>"

    items = []
    for entry in trace:
        status = "success" if entry.get("success") else "failed"
        tool = entry.get("tool", "unknown")
        detail = entry.get("error") or entry.get("metadata", {}).get("return_code") or "completed"
        items.append(
            f"<li><strong>{tool}</strong> — {status} <span class='trace-detail'>{detail}</span></li>"
        )
    return f"<ul class='trace-list'>{''.join(items)}</ul>"


def build_findings_table(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return "<p>No findings were generated in this run.</p>"

    rows = []
    for finding in findings:
        rows.append(
            f"""
                <tr>
                    <td>{finding.get('category')}</td>
                    <td>{finding.get('severity')}</td>
                    <td>{finding.get('confidence')}</td>
                    <td>{finding.get('evidence_source')}</td>
                    <td>{finding.get('description')}</td>
                </tr>
            """
        )
    return f"""
        <div class='section'>
            <h3>Findings</h3>
            <table>
                <thead>
                    <tr><th>Category</th><th>Severity</th><th>Confidence</th><th>Source</th><th>Description</th></tr>
                </thead>
                <tbody>{''.join(rows)}</tbody>
            </table>
        </div>
    """


def build_audit_summary(audit_data: Dict[str, Any]) -> str:
    if not audit_data:
        return "<p>No audit trail loaded.</p>"

    audit_meta = audit_data.get("audit_trail", {})
    summary = audit_meta.get("summary", {})
    return f"""
        <div class='section'>
            <h3>Audit Trail Summary</h3>
            <div class='card-grid'>
                {build_card('Session', audit_meta.get('session_id', 'n/a'))}
                {build_card('Decisions', summary.get('total_decisions', 0))}
                {build_card('Corrections', summary.get('total_corrections', 0))}
                {build_card('Tool Executions', summary.get('total_tool_executions', 0))}
            </div>
        </div>
    """


def build_html(results: Dict[str, Any], audit: Dict[str, Any]) -> str:
    summary = results.get("summary", {})
    execution = results.get("execution_summary", {})
    metrics = results.get("accuracy_metrics", {})
    trace = results.get("execution_trace", [])
    findings = results.get("findings", [])
    integrity = results.get("evidence_integrity", {})

    severity_distribution = metrics.get("severity_distribution", {})
    confidence_distribution = metrics.get("confidence_distribution", {})

    tool_count = len(execution.get("tools_used", []))
    evidence_count = len(integrity.get("artifacts_analyzed", []))
    correlation_count = len(integrity.get("correlation_graph", {}))

    top_cards = [
        build_card("Total Findings", summary.get("total_findings", 0)),
        build_card("High Severity", summary.get("high_severity", 0)),
        build_card("Medium Severity", summary.get("medium_severity", 0)),
        build_card("Low Severity", summary.get("low_severity", 0)),
        build_card("Duration (s)", f"{summary.get('duration_seconds', 0):.3f}"),
        build_card("Iterations", summary.get("iterations", 0)),
    ]

    details = f"""
        <div class='section'>
            <h3>Execution Summary</h3>
            <div class='card-grid'>
                {build_card('Total Executions', execution.get('total_executions', 0))}
                {build_card('Successful', execution.get('successful', 0))}
                {build_card('Failed', execution.get('failed', 0))}
                {build_card('Tools Used', tool_count)}
                {build_card('Evidence Artifacts', evidence_count)}
                {build_card('Correlation Nodes', correlation_count)}
            </div>
        </div>
    """

    findings_section = build_findings_table(findings)
    trace_section = f"<div class='section'><h3>Execution Trace</h3>{build_trace_list(trace)}</div>"
    audit_section = build_audit_summary(audit)
    severity_section = build_distribution_section(
        "Severity Distribution",
        severity_distribution,
        {"high": "#e74c3c", "medium": "#f39c12", "low": "#3498db"}
    )
    confidence_section = build_distribution_section(
        "Confidence Distribution",
        confidence_distribution,
        {"high": "#2ecc71", "medium": "#f1c40f", "low": "#95a5a6"}
    )

    no_findings_note = "<p class='note'>This run did not produce any findings. Verify input evidence and run again with additional evidence or adjusted analysis options.</p>" if not findings else ""

    return f"""
        <!DOCTYPE html>
        <html lang='en'>
        <head>
            <meta charset='UTF-8'>
            <meta name='viewport' content='width=device-width, initial-scale=1.0'>
            <title>Protocol SIFT Enhanced Dashboard</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; background: #f5f7fb; color: #2f3b52; }}
                .page {{ max-width: 1200px; margin: 0 auto; padding: 32px; }}
                header {{ margin-bottom: 24px; }}
                h1 {{ margin: 0 0 8px; font-size: 2.4rem; }}
                p.lead {{ margin: 0; color: #54627a; }}
                .card-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(210px, 1fr)); gap: 16px; margin-top: 16px; }}
                .card {{ background: #ffffff; border-radius: 14px; box-shadow: 0 12px 32px rgba(45, 55, 77, 0.08); padding: 20px; }}
                .card-title {{ font-size: 0.95rem; color: #7a8ba6; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px; }}
                .card-value {{ font-size: 2.2rem; font-weight: 700; }}
                .section {{ margin-top: 32px; }}
                .section h3 {{ margin-bottom: 16px; color: #1f2a46; }}
                table {{ width: 100%; border-collapse: collapse; background: #ffffff; border-radius: 14px; overflow: hidden; box-shadow: 0 12px 32px rgba(45, 55, 77, 0.08); }}
                th, td {{ text-align: left; padding: 14px 16px; border-bottom: 1px solid #eef1f7; }}
                th {{ background: #f4f7fb; font-weight: 700; }}
                .bar-chart {{ display: grid; gap: 12px; }}
                .bar-row {{ display: grid; grid-template-columns: 170px 1fr 80px; gap: 12px; align-items: center; }}
                .bar-label {{ font-weight: 600; color: #39425a; }}
                .bar-track {{ background: #e7ecf5; border-radius: 999px; height: 18px; overflow: hidden; }}
                .bar-fill {{ height: 100%; border-radius: 999px; }}
                .bar-value {{ font-weight: 600; color: #39425a; text-align: right; }}
                .trace-list {{ list-style: none; margin: 0; padding: 0; }}
                .trace-list li {{ background: #ffffff; padding: 14px 16px; border-radius: 10px; margin-bottom: 10px; box-shadow: 0 8px 20px rgba(45, 55, 77, 0.06); }}
                .trace-detail {{ color: #7a8ba6; display: block; margin-top: 6px; font-size: 0.95rem; }}
                .note {{ margin-top: 16px; color: #5b6b82; font-size: 1rem; }}
            </style>
        </head>
        <body>
            <div class='page'>
                <header>
                    <h1>Protocol SIFT Enhanced Dashboard</h1>
                    <p class='lead'>A lightweight HTML dashboard generated from your analysis output.</p>
                </header>

                <div class='section'>
                    <h3>Run Summary</h3>
                    <div class='card-grid'>
                        {''.join(top_cards)}
                    </div>
                </div>

                {details}
                {severity_section}
                {confidence_section}
                {findings_section}
                {trace_section}
                {audit_section}
                {no_findings_note}
            </div>
        </body>
        </html>
    """


def generate_dashboard(
    results_path: str = "output/analysis_results.json",
    audit_path: str = "output/audit_trail.json",
    output_path: str = "output/dashboard.html"
) -> str:
    results_file = Path(results_path)
    audit_file = Path(audit_path)
    output_file = Path(output_path)

    results = load_json(results_file)
    audit = load_json(audit_file) if audit_file.exists() else {}

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(build_html(results, audit), encoding="utf-8")

    return str(output_file)
