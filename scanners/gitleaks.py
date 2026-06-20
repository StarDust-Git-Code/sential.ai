import subprocess
import json
import os

class GitleaksScanner:
    def __init__(self, target_dir: str):
        self.target_dir = target_dir

    def run(self):
        report_path = "gitleaks_report.json"
        try:
            # --no-git allows scanning directories that aren't git repositories
            result = subprocess.run(
                ["gitleaks", "detect", "--source", self.target_dir, "--report-format", "json", "--report-path", report_path, "--no-git"],
                capture_output=True,
                text=True
            )
            
            # Gitleaks returns 1 if leaks are found, 0 if none, or other codes for errors
            if os.path.exists(report_path):
                with open(report_path, "r", encoding="utf-8") as f:
                    findings = json.load(f)
                os.remove(report_path)
                return findings
            return []
        except FileNotFoundError:
            raise FileNotFoundError("Gitleaks is not installed or not in PATH.")
        except Exception as e:
            raise Exception(f"Error running Gitleaks: {e}")
