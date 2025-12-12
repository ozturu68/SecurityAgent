import pytest
from unittest.mock import Mock, patch, MagicMock
from modules.analyzer import VulnerabilityAnalyzer


class TestVulnerabilityAnalyzer:
    """Unit tests for VulnerabilityAnalyzer"""
    
    @pytest.fixture
    def sample_scan_data(self):
        """Sample scan results for testing"""
        return {
            'target':  '192.168.1.1',
            'protocols': {
                'tcp': {
                    22: {'state': 'open', 'service': 'ssh', 'version': 'OpenSSH 7.4'},
                    80: {'state': 'open', 'service': 'http', 'product': 'Apache', 'version': '2.2.15'},
                    3306: {'state': 'open', 'service': 'mysql', 'version': '5.5.68'}
                }
            }
        }
    
    def test_initialization(self, sample_scan_data):
        """Test analyzer initialization"""
        analyzer = VulnerabilityAnalyzer(
            scan_data=sample_scan_data,
            model_name='mistral'
        )
        assert analyzer. scan_data == sample_scan_data
        assert analyzer.llm is not None
    
    @patch('core.parser.DualStreamParser.parse_response')
    @patch('core.llm_engine.LLMAgent.query')
    def test_analyze_success(self, mock_query, mock_parser, sample_scan_data):
        """Test successful vulnerability analysis"""
        mock_query.return_value = '''
        {
            "summary": "Found 2 critical vulnerabilities",
            "vulnerabilities": [
                {
                    "title": "Outdated Apache Version",
                    "severity": "critical",
                    "description": "Apache 2.2.15 has known vulnerabilities",
                    "cve": ["CVE-2021-44790"]
                }
            ]
        }
        '''
        
        mock_parser.return_value = {
            'summary': 'Found 2 critical vulnerabilities',
            'vulnerabilities': [
                {
                    'title': 'Outdated Apache Version',
                    'severity': 'critical',
                    'description': 'Apache 2.2.15 has known vulnerabilities',
                    'cve': ['CVE-2021-44790']
                }
            ]
        }
        
        analyzer = VulnerabilityAnalyzer(sample_scan_data, model_name='mistral')
        result = analyzer.analyze()
        
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]['severity'] == 'critical'
    
    @patch('core.parser.DualStreamParser.parse_response')
    @patch('core.llm_engine.LLMAgent.query')
    def test_analyze_no_response(self, mock_query, mock_parser, sample_scan_data):
        """Test analysis when LLM returns no response"""
        mock_query.return_value = None
        
        analyzer = VulnerabilityAnalyzer(sample_scan_data)
        result = analyzer.analyze()
        
        assert result == []
    
    @patch('core.parser.DualStreamParser.parse_response')
    @patch('core.llm_engine.LLMAgent.query')
    def test_analyze_no_vulnerabilities(self, mock_query, mock_parser, sample_scan_data):
        """Test analysis when no vulnerabilities found"""
        mock_query.return_value = '{"summary": "No issues found"}'
        
        mock_parser.return_value = {
            'summary': 'No issues found',
            'vulnerabilities': []
        }
        
        analyzer = VulnerabilityAnalyzer(sample_scan_data)
        result = analyzer.analyze()
        
        assert result == []
    
    @patch('core.parser.DualStreamParser.parse_response')
    @patch('core.llm_engine. LLMAgent.query')
    def test_analyze_with_summary(self, mock_query, mock_parser, sample_scan_data):
        """Test that summary is logged when present"""
        mock_query.return_value = 'response'
        
        mock_parser. return_value = {
            'summary': 'Test summary here',
            'vulnerabilities': [{'title': 'Test Vuln', 'severity': 'low'}]
        }
        
        analyzer = VulnerabilityAnalyzer(sample_scan_data)
        result = analyzer.analyze()
        
        assert len(result) == 1
        assert result[0]['title'] == 'Test Vuln'
    
    @patch('core.parser.DualStreamParser.parse_response')
    @patch('core.llm_engine.LLMAgent.query')
    def test_analyze_parser_error(self, mock_query, mock_parser, sample_scan_data):
        """Test handling of parser errors"""
        mock_query.return_value = 'invalid response'
        mock_parser.side_effect = Exception("Parse error")
        
        analyzer = VulnerabilityAnalyzer(sample_scan_data)
        
        with pytest.raises(Exception):
            analyzer.analyze()
    
    def test_empty_scan_data(self):
        """Test analyzer with empty scan data"""
        analyzer = VulnerabilityAnalyzer(scan_data={})
        assert analyzer.scan_data == {}