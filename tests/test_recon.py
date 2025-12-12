import pytest
from unittest.mock import Mock, patch, MagicMock, mock_open
import socket
import subprocess
from modules.recon import ReconModule
import geoip2.errors


class TestReconModule: 
    """Unit tests for ReconModule"""
    
    @pytest. fixture
    def recon_no_geoip(self):
        """Recon module without GeoIP"""
        return ReconModule()
    
    @pytest.fixture
    def recon_with_geoip(self):
        """Recon module with mocked GeoIP"""
        with patch('geoip2.database.Reader'):
            return ReconModule(geoip_db_path='/fake/path. mmdb')
    
    def test_initialization_without_geoip(self):
        """Test initialization without GeoIP database"""
        recon = ReconModule()
        assert recon.geoip_reader is None
    
    @patch('geoip2.database.Reader')
    @patch('pathlib.Path.exists', return_value=True)
    def test_initialization_with_geoip(self, mock_exists, mock_reader):
        """Test initialization with GeoIP database"""
        recon = ReconModule(geoip_db_path='/fake/path.mmdb')
        assert recon.geoip_reader is not None
        mock_reader.assert_called_once_with('/fake/path.mmdb')
    
    @patch('socket.inet_aton')
    @patch('socket.gethostbyaddr')
    def test_resolve_ip_address(self, mock_gethostbyaddr, mock_inet_aton, recon_no_geoip):
        """Test resolving IP address with reverse DNS"""
        mock_inet_aton.return_value = None  # Valid IP
        mock_gethostbyaddr.return_value = ('example.com', [], ['192.168.1.1'])
        
        result = recon_no_geoip.resolve_target('192.168.1.1')
        
        assert result['type'] == 'ip'
        assert result['ip_address'] == '192.168.1.1'
        assert result['hostname'] == 'example.com'
        assert result['error'] is None
    
    @patch('socket.inet_aton', side_effect=socket.error)
    @patch('socket.gethostbyname')
    def test_resolve_domain_name(self, mock_gethostbyname, mock_inet_aton, recon_no_geoip):
        """Test resolving domain name to IP"""
        mock_gethostbyname.return_value = '93.184.216.34'
        
        result = recon_no_geoip.resolve_target('example.com')
        
        assert result['type'] == 'domain'
        assert result['hostname'] == 'example.com'
        assert result['ip_address'] == '93.184.216.34'
        assert result['error'] is None
    
    @patch('socket.inet_aton', side_effect=socket.error)
    @patch('socket.gethostbyname', side_effect=socket.gaierror("Name resolution failed"))
    def test_resolve_invalid_domain(self, mock_gethostbyname, mock_inet_aton, recon_no_geoip):
        """Test resolving invalid domain"""
        result = recon_no_geoip.resolve_target('invalid. nonexistent')
        
        assert result['type'] == 'domain'
        assert result['ip_address'] is None
        assert result['error'] is not None
        assert 'DNS resolution failed' in result['error']
    
    @patch('socket.inet_aton', side_effect=socket.error)
    @patch('socket.gethostbyname', side_effect=socket.timeout)
    def test_resolve_timeout(self, mock_gethostbyname, mock_inet_aton, recon_no_geoip):
        """Test DNS resolution timeout"""
        result = recon_no_geoip.resolve_target('slow.example.com')
        
        assert result['error'] is not None
        assert 'timeout' in result['error']. lower()
    
    def test_get_geolocation_no_reader(self, recon_no_geoip):
        """Test GeoIP lookup without database"""
        result = recon_no_geoip._get_geolocation('8.8.8.8')
        assert result is None
    
    @patch('geoip2.database.Reader')
    def test_get_geolocation_success(self, mock_reader_class):
        """Test successful GeoIP lookup"""
        # Mock GeoIP response
        mock_response = MagicMock()
        mock_response.country. name = 'United States'
        mock_response. country.iso_code = 'US'
        mock_response.city.name = 'Mountain View'
        mock_response. location.latitude = 37.4056
        mock_response.location. longitude = -122.0775
        mock_response.location.time_zone = 'America/Los_Angeles'
        
        mock_reader = MagicMock()
        mock_reader.city.return_value = mock_response
        mock_reader_class.return_value = mock_reader
        
        with patch('pathlib.Path.exists', return_value=True):
            recon = ReconModule(geoip_db_path='/fake/path.mmdb')
            result = recon._get_geolocation('8.8.8.8')
        
        assert result['country'] == 'United States'
        assert result['city'] == 'Mountain View'
        assert result['latitude'] == 37.4056
        assert result['longitude'] == -122.0775
    
    @patch('geoip2.database.Reader')
    def test_get_geolocation_not_found(self, mock_reader_class):
        """Test GeoIP lookup for unknown IP"""
        mock_reader = MagicMock()
        mock_reader.city.side_effect = geoip2.errors.AddressNotFoundError("IP not in database")
        mock_reader_class.return_value = mock_reader
        
        with patch('pathlib.Path.exists', return_value=True):
            recon = ReconModule(geoip_db_path='/fake/path.mmdb')
            result = recon._get_geolocation('192.168.1.1')
        
        assert result is None
    
    @patch('subprocess.run')
    def test_whois_lookup_success(self, mock_run, recon_no_geoip):
        """Test successful WHOIS lookup"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='Domain: example.com\nRegistrar: Example Inc.',
            stderr=''
        )
        
        result = recon_no_geoip. whois_lookup('example.com')
        
        assert result['target'] == 'example.com'
        assert result['whois_data'] is not None
        assert 'Domain: example.com' in result['whois_data']
        assert result['error'] is None
    
    @patch('subprocess.run')
    def test_whois_lookup_timeout(self, mock_run, recon_no_geoip):
        """Test WHOIS lookup timeout"""
        mock_run. side_effect = subprocess.TimeoutExpired('whois', 10)
        
        result = recon_no_geoip.whois_lookup('example.com', timeout=10)
        
        assert result['error'] is not None
        assert 'timeout' in result['error'].lower()
    
    @patch('subprocess.run')
    def test_whois_lookup_command_not_found(self, mock_run, recon_no_geoip):
        """Test WHOIS when command not installed"""
        mock_run.side_effect = FileNotFoundError()
        
        result = recon_no_geoip.whois_lookup('example.com')
        
        assert result['error'] is not None
        assert 'not found' in result['error']
    
    @patch('subprocess.run')
    def test_whois_lookup_command_failed(self, mock_run, recon_no_geoip):
        """Test WHOIS command failure"""
        mock_run. return_value = Mock(
            returncode=1,
            stdout='',
            stderr='Error: Connection refused'
        )
        
        result = recon_no_geoip.whois_lookup('example.com')
        
        assert result['error'] is not None
        assert 'WHOIS command failed' in result['error']
    
    @patch('socket.inet_aton')
    @patch('socket.gethostbyname')
    @patch('subprocess.run')
    def test_gather_info_complete(self, mock_run, mock_gethostbyname, mock_inet_aton, recon_no_geoip):
        """Test complete information gathering"""
        # Mock DNS resolution
        mock_inet_aton.side_effect = socket.error  # It's a domain
        mock_gethostbyname.return_value = '93.184.216.34'
        
        # Mock WHOIS
        mock_run.return_value = Mock(
            returncode=0,
            stdout='Domain:  example.com',
            stderr=''
        )
        
        result = recon_no_geoip.gather_info('example.com')
        
        assert 'resolution' in result
        assert 'whois' in result
        assert 'timestamp' in result
        assert result['resolution']['ip_address'] == '93.184.216.34'
    
    @patch('socket.inet_aton', side_effect=socket.error)
    @patch('socket.gethostbyname', side_effect=socket.gaierror("Failed"))
    def test_gather_info_dns_failure(self, mock_gethostbyname, mock_inet_aton, recon_no_geoip):
        """Test gather_info when DNS fails"""
        result = recon_no_geoip.gather_info('invalid.domain')
        
        assert result['resolution']['error'] is not None
        assert result['whois'] is None  # WHOIS skipped on DNS failure
    
    @patch('geoip2.database.Reader')
    def test_cleanup_closes_geoip_reader(self, mock_reader_class):
        """Test that GeoIP reader is closed on cleanup"""
        mock_reader = MagicMock()
        mock_reader_class.return_value = mock_reader
        
        with patch('pathlib.Path.exists', return_value=True):
            recon = ReconModule(geoip_db_path='/fake/path.mmdb')
            recon.__del__()
        
        mock_reader.close.assert_called_once()