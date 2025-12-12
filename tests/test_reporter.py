import pytest
import json
from pathlib import Path
from unittest.mock import Mock, patch, mock_open
from modules.reporter import ReportGenerator


class TestReportGenerator:
    """Unit tests for ReportGenerator"""
    
    @pytest.fixture
    def temp_output_dir(self, tmp_path):
        """Create temporary output directory"""
        return str(tmp_path / "test_reports")
    
    @pytest.fixture
    def reporter(self, temp_output_dir):
        """Create reporter instance"""
        return ReportGenerator(output_dir=temp_output_dir)
    
    @pytest.fixture
    def sample_scan_data(self):
        """Sample scan data for testing"""
        return {
            'nmap':  {
                'scan':  {
                    '192.168.1.1':  {
                        'tcp': {
                            80: {'state': 'open', 'name': 'http', 'product': 'Apache', 'version': '2.4'},
                            443: {'state':  'open', 'name':  'https', 'product': 'nginx', 'version': '1.18'},
                            8080: {'state': 'filtered', 'name': 'http-proxy'}
                        }
                    }
                }
            }
        }
    
    @pytest.fixture
    def sample_analysis(self):
        """Sample analysis data for testing"""
        return {
            'vulnerabilities': [
                {
                    'title': 'Outdated Apache Version',
                    'severity': 'critical',
                    'description': 'Apache 2.4 has known vulnerabilities'
                },
                {
                    'title': 'Weak SSL Configuration',
                    'severity':  'medium',
                    'description': 'SSL configuration needs hardening'
                }
            ],
            'recommendations': [
                'Update Apache to latest version',
                'Enable HSTS headers',
                'Disable unnecessary services'
            ]
        }
    
    def test_initialization(self, temp_output_dir):
        """Test reporter initialization"""
        reporter = ReportGenerator(output_dir=temp_output_dir)
        assert reporter.output_dir == Path(temp_output_dir)
        assert reporter.output_dir.exists()
    
    def test_generate_report_creates_file(self, reporter, sample_scan_data, sample_analysis):
        """Test report file creation"""
        report_path = reporter.generate_report(
            scan_data=sample_scan_data,
            analysis=sample_analysis,
            target='192.168.1.1'
        )
        
        assert Path(report_path).exists()
        assert report_path.endswith('.json')
        assert '192.168.1.1' in report_path
    
    def test_generate_report_content(self, reporter, sample_scan_data, sample_analysis):
        """Test report content structure"""
        report_path = reporter.generate_report(
            scan_data=sample_scan_data,
            analysis=sample_analysis,
            target='192.168.1.1'
        )
        
        with open(report_path, 'r') as f:
            report = json.load(f)
        
        assert 'metadata' in report
        assert 'scan_results' in report
        assert 'vulnerability_analysis' in report
        assert 'summary' in report
        assert report['metadata']['target'] == '192.168.1.1'
    
    def test_generate_summary_counts_ports(self, reporter, sample_scan_data, sample_analysis):
        """Test summary generation with port counts"""
        summary = reporter._generate_summary(sample_scan_data, sample_analysis)
        
        assert summary['total_ports_scanned'] == 3
        assert summary['open_ports'] == 2
        assert summary['services_detected'] == 3
    
    def test_generate_summary_counts_vulnerabilities(self, reporter, sample_scan_data, sample_analysis):
        """Test summary counts critical vulnerabilities"""
        summary = reporter._generate_summary(sample_scan_data, sample_analysis)
        
        assert summary['critical_findings'] == 1
        assert summary['recommendations_count'] == 3
    
    def test_generate_summary_empty_data(self, reporter):
        """Test summary with empty data"""
        summary = reporter._generate_summary({}, {})
        
        assert summary['total_ports_scanned'] == 0
        assert summary['open_ports'] == 0
        assert summary['critical_findings'] == 0
    
    def test_generate_report_invalid_target_chars(self, reporter, sample_scan_data, sample_analysis):
        """Test report generation with special characters in target"""
        report_path = reporter.generate_report(
            scan_data=sample_scan_data,
            analysis=sample_analysis,
            target='192.168.1.1/24'
        )
        
        assert '/' not in Path(report_path).name
        assert Path(report_path).exists()
    
    def test_generate_report_io_error(self, reporter, sample_scan_data, sample_analysis):
        """Test report generation with IO error"""
        with patch('builtins.open', side_effect=IOError("Disk full")):
            with pytest.raises(IOError):
                reporter.generate_report(
                    scan_data=sample_scan_data,
                    analysis=sample_analysis,
                    target='192.168.1.1'
                )
    
    def test_export_to_html_not_implemented(self, reporter):
        """Test HTML export raises NotImplementedError"""
        with pytest.raises(NotImplementedError, match="coming soon"):
            reporter.export_to_html('/fake/report.json')
    
    def test_export_to_markdown_success(self, reporter, sample_scan_data, sample_analysis):
        """Test Markdown export"""
        json_path = reporter.generate_report(
            scan_data=sample_scan_data,
            analysis=sample_analysis,
            target='192.168.1.1'
        )
        
        md_path = reporter.export_to_markdown(json_path)
        
        assert Path(md_path).exists()
        assert md_path.endswith('.md')
        
        with open(md_path, 'r') as f:
            content = f.read()
        
        assert '# Security Scan Report' in content
        assert '192.168.1.1' in content
        assert 'Outdated Apache Version' in content
        assert 'Update Apache' in content
    
    def test_export_to_markdown_file_not_found(self, reporter):
        """Test Markdown export with non-existent file"""
        with pytest.raises(Exception):
            reporter.export_to_markdown('/nonexistent/report.json')
    
    def test_report_json_encoding(self, reporter, sample_scan_data):
        """Test JSON report handles unicode correctly"""
        analysis = {
            'vulnerabilities': [
                {
                    'title':  'Test Güvenlik Açığı',
                    'severity':  'low',
                    'description': 'Unicode test:  你好世界'
                }
            ],
            'recommendations': ['Test önerisi']
        }
        
        report_path = reporter.generate_report(
            scan_data=sample_scan_data,
            analysis=analysis,
            target='test'
        )
        
        with open(report_path, 'r', encoding='utf-8') as f:
            report = json.load(f)
        
        assert 'Güvenlik' in report['vulnerability_analysis']['vulnerabilities'][0]['title']
        assert '你好世界' in report['vulnerability_analysis']['vulnerabilities'][0]['description']
    
    def test_multiple_reports_different_names(self, reporter, sample_scan_data, sample_analysis):
        """Test multiple reports have unique names"""
        import time
        
        report1 = reporter.generate_report(sample_scan_data, sample_analysis, 'target1')
        time.sleep(1.1)
        report2 = reporter.generate_report(sample_scan_data, sample_analysis, 'target2')
        
        assert report1 != report2
        assert Path(report1).exists()
        assert Path(report2).exists()