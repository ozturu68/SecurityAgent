import pytest
from unittest.mock import Mock, patch, MagicMock
from modules.scanner import PortScanner, PortScanError, ScanTimeoutError
import nmap


class TestPortScanner:
    """Unit tests for PortScanner module"""
    
    @pytest.fixture
    def scanner(self):
        """Create scanner instance for testing"""
        with patch('nmap.PortScanner'):
            return PortScanner()
    
    def test_scanner_initialization_success(self):
        """Test successful scanner initialization"""
        with patch('nmap.PortScanner'):
            scanner = PortScanner()
            assert scanner is not None
            assert hasattr(scanner, 'scanner')
    
    def test_scanner_initialization_failure(self):
        """Test scanner initialization when nmap not found"""
        with patch('nmap.PortScanner', side_effect=nmap. PortScannerError("Nmap not found")):
            with pytest.raises(PortScanError, match="Nmap not found"):
                PortScanner()
    
    def test_port_validation_success(self, scanner):
        """Test valid port specifications"""
        assert scanner._validate_ports('1-100') is True
        assert scanner._validate_ports('22,80,443') is True
        assert scanner._validate_ports('1-500,8080') is True
    
    def test_port_validation_exceeds_limit(self, scanner):
        """Test port validation with excessive port count"""
        with pytest.raises(PortScanError, match="exceeds maximum"):
            scanner._validate_ports('1-65535')
    
    def test_port_validation_invalid_format(self, scanner):
        """Test port validation with invalid format"""
        with pytest.raises(PortScanError, match="Invalid port specification"):
            scanner._validate_ports('invalid-ports')
    
    def test_get_scan_params(self, scanner):
        """Test scan parameter generation"""
        assert '-T4 -F' in scanner._get_scan_params('quick')
        assert '-T4 -A -v' in scanner._get_scan_params('full')
        assert '-sS -T2' in scanner._get_scan_params('stealth')
        assert '-T4' in scanner._get_scan_params('unknown_type')
    
    @patch('nmap.PortScanner')
    def test_scan_success(self, mock_nmap):
        """Test successful port scan"""
        mock_instance = MagicMock()
        mock_nmap.return_value = mock_instance
        
        mock_host = MagicMock()
        mock_host.state. return_value = 'up'
        mock_host.hostnames. return_value = [{'name': 'test.local', 'type': 'PTR'}]
        mock_host.all_protocols.return_value = ['tcp']
        mock_host.__getitem__.return_value = {
            80: {'state': 'open', 'name': 'http', 'product': 'Apache', 'version': '2.4', 'extrainfo': ''},
            443: {'state':  'open', 'name':  'https', 'product': 'nginx', 'version': '1.18', 'extrainfo': ''}
        }
        
        mock_instance.all_hosts.return_value = ['192.168.1.1']
        mock_instance.__getitem__.return_value = mock_host
        
        scanner = PortScanner()
        result = scanner.scan('192.168.1.1', '80,443', 'quick')
        
        assert result['target'] == '192.168.1.1'
        assert result['scan_type'] == 'quick'
        assert result['state'] == 'up'
        assert result['summary']['total_open_ports'] == 2
        assert 'tcp' in result['protocols']
    
    @patch('nmap.PortScanner')
    def test_scan_timeout(self, mock_nmap):
        """Test scan timeout handling"""
        mock_instance = MagicMock()
        mock_nmap.return_value = mock_instance
        mock_instance.scan.side_effect = nmap.PortScannerTimeout("Scan timeout")
        
        scanner = PortScanner()
        
        with pytest.raises(ScanTimeoutError):
            scanner.scan('192.168.1.1', '1-100', 'quick', timeout=1)
    
    @patch('nmap.PortScanner')
    def test_scan_with_retry(self, mock_nmap):
        """Test retry mechanism on failure"""
        mock_instance = MagicMock()
        mock_nmap.return_value = mock_instance
        
        mock_instance.scan.side_effect = [
            nmap.PortScannerError("Network error"),
            None
        ]
        
        mock_host = MagicMock()
        mock_host.state.return_value = 'up'
        mock_host.hostnames. return_value = []
        mock_host.all_protocols.return_value = []
        
        mock_instance.all_hosts.return_value = ['192.168.1.1']
        mock_instance.__getitem__.return_value = mock_host
        
        scanner = PortScanner()
        result = scanner.scan('192.168.1.1', '80', 'quick')
        
        assert result is not None
        assert mock_instance.scan.call_count == 2
    
    @patch('nmap.PortScanner')
    def test_scan_max_retries_exceeded(self, mock_nmap):
        """Test max retries exceeded"""
        mock_instance = MagicMock()
        mock_nmap.return_value = mock_instance
        mock_instance.scan.side_effect = nmap.PortScannerError("Persistent error")
        
        scanner = PortScanner()
        
        with pytest.raises(PortScanError, match="Nmap scan error"):
            scanner.scan('192.168.1.1', '80', 'quick')
        
        assert mock_instance.scan.call_count == scanner.MAX_RETRIES
    
    @patch('nmap.PortScanner')
    def test_process_results_no_host(self, mock_nmap):
        """Test result processing when host not found"""
        mock_instance = MagicMock()
        mock_nmap.return_value = mock_instance
        mock_instance.all_hosts.return_value = []
        
        scanner = PortScanner()
        
        with pytest.raises(PortScanError, match="No results found"):
            scanner._process_results('192.168.1.1', 'quick')
    
    @patch('nmap.PortScanner')
    def test_get_scan_info(self, mock_nmap):
        """Test getting scan metadata"""
        mock_instance = MagicMock()
        mock_nmap.return_value = mock_instance
        mock_instance.command_line.return_value = 'nmap -T4 192.168.1.1'
        mock_instance.scanstats.return_value = {'uphosts': '1', 'downhosts':  '0'}
        mock_instance.nmap_version.return_value = (7, 91)
        
        scanner = PortScanner()
        info = scanner. get_scan_info()
        
        assert 'command_line' in info
        assert 'scanstats' in info
        assert 'nmap_version' in info