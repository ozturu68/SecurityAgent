import json
import os
import logging

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self, scan_data, vulnerabilities):
        self.scan_data = scan_data
        self.vulnerabilities = vulnerabilities
        self.output_dir = "outputs"
        if not os.path.exists(self.output_dir): os.makedirs(self.output_dir)

    def export_json(self, filename="report"):
        path = os.path.join(self.output_dir, f"{filename}.json")
        data = {
            "scan_meta": self.scan_data,
            "findings": self.vulnerabilities,
            "count": len(self.vulnerabilities)
        }
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        return path