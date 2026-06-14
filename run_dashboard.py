"""Entry point to generate an HTML dashboard from the Protocol SIFT Enhanced output."""
import os
import platform
import subprocess
from src.visualization import generate_dashboard


def open_file(path: str) -> None:
    system = platform.system()
    if system == "Windows":
        os.startfile(path)
    elif system == "Darwin":
        subprocess.run(["open", path], check=False)
    else:
        subprocess.run(["xdg-open", path], check=False)


if __name__ == "__main__":
    dashboard_path = generate_dashboard(
        results_path="output/analysis_results.json",
        audit_path="output/audit_trail.json",
        output_path="output/dashboard.html"
    )
    print(f"Dashboard generated: {dashboard_path}")
    print("Opening dashboard...")
    open_file(dashboard_path)
