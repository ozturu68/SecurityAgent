# modules/reporter.py
import json
import os
import logging

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self, scan_data, vulnerabilities):
        self.scan_data = scan_data
        self.vulnerabilities = vulnerabilities
        self.output_dir = "outputs"
        
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def export_json(self, filename="report"):
        """Sonuçları JSON formatında kaydeder."""
        report = {
            "scan_info": self.scan_data,
            "vulnerabilities": self.vulnerabilities,
            "summary": f"Total vulnerabilities: {len(self.vulnerabilities)}"
        }
        
        full_path = os.path.join(self.output_dir, f"{filename}.json")
        
        with open(full_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
            
        logger.info(f"JSON rapor oluşturuldu: {full_path}")
        return full_path

    def export_html(self, filename="report"):
        """(Opsiyonel) HTML çıktı placeholder."""
        pass