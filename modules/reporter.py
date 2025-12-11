import json
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self, scan_data, vulnerabilities, recommended_actions=None, summary=None):
        self.scan_data = scan_data
        self.vulnerabilities = vulnerabilities
        self.recommended_actions = recommended_actions or []
        self.summary = summary or ""
        self.output_dir = "outputs"
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def export_json(self, filename="report"):
        """Export findings to structured JSON"""
        path = os.path.join(self.output_dir, f"{filename}.json")
        
        # Extract and organize metadata
        meta = self.scan_data.copy()
        timestamp = meta.pop('time', datetime.now().isoformat())
        
        # Calculate severity distribution
        severity_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for vuln in self.vulnerabilities:
            severity = vuln.get("severity", "Medium")
            severity_count[severity] = severity_count.get(severity, 0) + 1
        
        data = {
            "report_metadata": {
                "generated_at": timestamp,
                "target": meta.get("target"),
                "ip": meta.get("ip"),
                "scan_mode": meta.get("mode", "quick"),
                "scanner_version": "CyberSec-Agent v1.0"
            },
            "scan_results": {
                "open_ports": meta.get("open_ports", []),
                "services": meta.get("services", {}),
                "whois": meta.get("whois", {})
            },
            "security_analysis": {
                "summary": self.summary,
                "total_findings": len(self.vulnerabilities),
                "severity_distribution": severity_count,
                "vulnerabilities": self.vulnerabilities,
                "recommended_actions": self.recommended_actions
            }
        }
        
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"JSON report saved: {path}")
        return path


# ========================================
# FILE 4: modules/analyzer.py - UPDATED
# ========================================
import logging
from core.llm_engine import LLMEngine
from core.parser import DualStreamParser

logger = logging.getLogger(__name__)

class VulnerabilityAnalyzer:
    def __init__(self, scan_data, model_name=None):
        self.scan_data = scan_data
        self.llm = LLMEngine(model_name=model_name)

    def analyze(self):
        """Analyze scan data and return structured results"""
        logger.info("Analysis started.")
        
        raw_response = self.llm.analyze_scan_data(self.scan_data)
        
        if not raw_response:
            logger.error("AI did not respond")
            return {
                "vulnerabilities": [],
                "recommended_actions": [],
                "summary": "Analysis failed - no AI response"
            }

        parsed_data = DualStreamParser.parse_response(raw_response)
        
        summary = parsed_data.get("summary", "")
        vulnerabilities = parsed_data.get("vulnerabilities", [])
        actions = parsed_data.get("recommended_actions", [])
        
        if summary:
            logger.info(f"Summary: {summary}")
        
        if not vulnerabilities:
            logger.warning("No vulnerabilities found")
        else:
            logger.info(f"{len(vulnerabilities)} vulnerabilities detected")
        
        return {
            "vulnerabilities": vulnerabilities,
            "recommended_actions": actions,
            "summary": summary
        }
