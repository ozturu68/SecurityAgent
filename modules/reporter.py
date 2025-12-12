import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

class ReportGenerator:
    """Generate security scan reports in multiple formats"""
    
    def __init__(self, output_dir:  str = "reports"):
        """
        Initialize report generator
        
        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        logger.info(f"Report generator initialized: {self.output_dir}")
    
    def generate_report(self, scan_data: Dict, analysis: Dict, target: str) -> str:
        """
        Generate comprehensive security report
        
        Args: 
            scan_data: Raw scan results
            analysis: AI analysis results
            target: Target identifier
            
        Returns:
            Path to generated report file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name = f"security_report_{target. replace('/', '_')}_{timestamp}.json"
        report_path = self.output_dir / report_name
        
        report = {
            'metadata': {
                'target': target,
                'scan_timestamp': timestamp,
                'report_version': '1.0'
            },
            'scan_results':  scan_data,
            'vulnerability_analysis': analysis,
            'summary': self._generate_summary(scan_data, analysis)
        }
        
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Report generated: {report_path}")
            return str(report_path)
            
        except IOError as e:
            logger. error(f"Failed to write report: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error generating report: {e}")
            raise
    
    def _generate_summary(self, scan_data: Dict, analysis: Dict) -> Dict:
        """
        Generate executive summary
        
        Args: 
            scan_data:  Scan results
            analysis: Analysis results
            
        Returns:
            Summary dictionary
        """
        summary = {
            'total_ports_scanned': 0,
            'open_ports': 0,
            'services_detected': 0,
            'critical_findings': 0,
            'recommendations_count': 0
        }
        
        # Port bilgilerini say
        if 'nmap' in scan_data and 'scan' in scan_data['nmap']:
            for host, host_data in scan_data['nmap']['scan'].items():
                if 'tcp' in host_data:
                    tcp_ports = host_data['tcp']
                    summary['total_ports_scanned'] += len(tcp_ports)
                    summary['open_ports'] += sum(
                        1 for port_data in tcp_ports. values() 
                        if port_data. get('state') == 'open'
                    )
                    summary['services_detected'] += sum(
                        1 for port_data in tcp_ports.values() 
                        if port_data.get('name')
                    )
        
        # Analiz bulgularını say
        if analysis and 'vulnerabilities' in analysis: 
            vulns = analysis['vulnerabilities']
            if isinstance(vulns, list):
                summary['critical_findings'] = sum(
                    1 for v in vulns 
                    if isinstance(v, dict) and v.get('severity') == 'critical'
                )
        
        if analysis and 'recommendations' in analysis: 
            recs = analysis['recommendations']
            summary['recommendations_count'] = len(recs) if isinstance(recs, list) else 0
        
        return summary
    
    def export_to_html(self, json_report_path: str) -> str:
        """
        Convert JSON report to HTML format
        
        Args:
            json_report_path: Path to JSON report
            
        Returns:
            Path to HTML report
        """
        # Bu özellik ileriki sürümlerde eklenebilir
        logger.warning("HTML export not implemented yet")
        raise NotImplementedError("HTML export feature coming soon")
    
    def export_to_markdown(self, json_report_path: str) -> str:
        """
        Convert JSON report to Markdown format
        
        Args:
            json_report_path: Path to JSON report
            
        Returns:
            Path to Markdown report
        """
        try:
            with open(json_report_path, 'r', encoding='utf-8') as f:
                report = json.load(f)
            
            md_path = Path(json_report_path).with_suffix('.md')
            
            with open(md_path, 'w', encoding='utf-8') as f:
                # Header
                f.write(f"# Security Scan Report\n\n")
                f.write(f"**Target:** {report['metadata']['target']}\n\n")
                f.write(f"**Scan Date:** {report['metadata']['scan_timestamp']}\n\n")
                
                # Summary
                f.write(f"## Summary\n\n")
                for key, value in report['summary']. items():
                    f.write(f"- **{key. replace('_', ' ').title()}:** {value}\n")
                
                # Vulnerabilities
                f.write(f"\n## Vulnerability Analysis\n\n")
                if 'vulnerabilities' in report. get('vulnerability_analysis', {}):
                    vulns = report['vulnerability_analysis']['vulnerabilities']
                    if isinstance(vulns, list):
                        for vuln in vulns: 
                            if isinstance(vuln, dict):
                                f.write(f"### {vuln. get('title', 'Unknown')}\n")
                                f. write(f"**Severity:** {vuln.get('severity', 'N/A')}\n\n")
                                f.write(f"{vuln.get('description', 'No description')}\n\n")
                
                # Recommendations
                f. write(f"## Recommendations\n\n")
                if 'recommendations' in report.get('vulnerability_analysis', {}):
                    recs = report['vulnerability_analysis']['recommendations']
                    if isinstance(recs, list):
                        for i, rec in enumerate(recs, 1):
                            f. write(f"{i}. {rec}\n")
            
            logger.info(f"Markdown report generated: {md_path}")
            return str(md_path)
            
        except Exception as e:
            logger.error(f"Failed to generate Markdown report: {e}")
            raise