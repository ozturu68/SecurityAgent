import pytest
from unittest.mock import patch, Mock, MagicMock, AsyncMock
from pathlib import Path
import json


class TestIntegration:
    """Integration tests for complete scan workflow"""
    
    @pytest.mark.integration
    @patch('modules.scanner.PortScanner')
    @patch('modules.recon.ReconModule')
    @patch('modules.analyzer.VulnerabilityAnalyzer')
    @patch('modules.reporter.ReportGenerator')
    def test_complete_scan_workflow(
        self, 
        mock_reporter_class,
        mock_analyzer_class,
        mock_recon_class,
        mock_scanner_class,
        tmp_path
    ):
        """Test complete scan workflow from recon to report"""
        target = '192.168.1.1'
        
        mock_recon = MagicMock()
        mock_recon.gather_info.return_value = {
            'resolution': {
                'ip_address': target,
                'type': 'ip',
                'geolocation': {'country': 'US', 'city': 'Mountain View'}
            },
            'whois': {'whois_data': 'Sample WHOIS data'}
        }
        mock_recon_class.return_value = mock_recon
        
        mock_scanner = MagicMock()
        mock_scanner.scan. return_value = {
            'target': target,
            'protocols': {
                'tcp': {
                    80: {'state': 'open', 'service': 'http'},
                    443: {'state': 'open', 'service': 'https'}
                }
            },
            'summary': {'total_open_ports': 2}
        }
        mock_scanner_class.return_value = mock_scanner
        
        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = [
            {'title': 'Test Vuln', 'severity': 'medium'}
        ]
        mock_analyzer_class.return_value = mock_analyzer
        
        mock_reporter = MagicMock()
        report_path = str(tmp_path / 'report.json')
        mock_reporter.generate_report.return_value = report_path
        mock_reporter_class.return_value = mock_reporter
        
        from modules.recon import ReconModule
        from modules.scanner import PortScanner
        from modules.analyzer import VulnerabilityAnalyzer
        from modules.reporter import ReportGenerator
        
        recon = ReconModule()
        scanner = PortScanner()
        
        recon_data = recon.gather_info(target)
        assert recon_data['resolution']['ip_address'] == target
        
        scan_data = scanner.scan(target, '80,443')
        assert scan_data['summary']['total_open_ports'] == 2
        
        analyzer = VulnerabilityAnalyzer(scan_data)
        analysis = analyzer.analyze()
        assert len(analysis) > 0
        
        reporter = ReportGenerator()
        report = reporter.generate_report(scan_data, analysis, target)
        assert report == report_path
    
    @pytest.mark.integration
    def test_error_propagation(self):
        """Test that errors propagate correctly through workflow"""
        from modules.scanner import PortScanner, PortScanError
        
        with patch('nmap.PortScanner', side_effect=Exception("Nmap not found")):
            with pytest.raises(PortScanError):
                scanner = PortScanner()