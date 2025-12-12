import nmap
import logging
from typing import Dict, Optional, List
from datetime import datetime

logger = logging.getLogger(__name__)

class PortScanError(Exception):
    """Custom exception for port scanning errors"""
    pass

class ScanTimeoutError(PortScanError):
    """Exception for scan timeout errors"""
    pass

class PortScanner:
    """Network port scanner using Nmap"""
    
    # Güvenlik limitleri
    MAX_PORTS = 1000
    DEFAULT_TIMEOUT = 300  # 5 dakika
    MAX_RETRIES = 2
    
    def __init__(self):
        """Initialize port scanner"""
        try:
            self.scanner = nmap.PortScanner()
            logger.info("Nmap scanner initialized")
        except nmap.PortScannerError as e:
            error_msg = f"Nmap not found or not accessible: {e}"
            logger.critical(error_msg)
            raise PortScanError(error_msg)
        except Exception as e:
            error_msg = f"Failed to initialize scanner: {e}"
            logger. critical(error_msg)
            raise PortScanError(error_msg)
    
    def _validate_ports(self, ports: str) -> bool:
        """
        Validate port specification to prevent abuse
        
        Args:
            ports: Port specification (e.g., '1-1000', '22,80,443')
            
        Returns:
            True if valid, raises exception otherwise
        """
        try:
            # Port sayısını hesapla
            port_count = 0
            
            for part in ports.split(','):
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    port_count += (end - start + 1)
                else:
                    port_count += 1
            
            if port_count > self.MAX_PORTS:
                raise PortScanError(
                    f"Port count ({port_count}) exceeds maximum ({self.MAX_PORTS})"
                )
            
            logger.debug(f"Port validation passed: {port_count} ports")
            return True
            
        except ValueError as e:
            raise PortScanError(f"Invalid port specification: {e}")
    
    def scan(
        self, 
        target:  str, 
        ports: str = '1-1000',
        scan_type: str = 'quick',
        timeout: Optional[int] = None
    ) -> Dict: 
        """
        Perform port scan on target
        
        Args:
            target: IP address or hostname
            ports: Port range (e.g., '1-1000' or '22,80,443')
            scan_type:  Scan mode ('quick', 'full', 'stealth')
            timeout: Scan timeout in seconds
            
        Returns:
            Dictionary containing scan results
            
        Raises:
            PortScanError: For scan-related errors
            ScanTimeoutError: For timeout errors
        """
        # Port validasyonu
        self._validate_ports(ports)
        
        # Timeout ayarla
        if timeout is None: 
            timeout = self.DEFAULT_TIMEOUT
        
        # Scan parametrelerini belirle
        scan_params = self._get_scan_params(scan_type)
        
        logger.info(f"Starting {scan_type} scan on {target}:{ports} (timeout: {timeout}s)")
        
        # Retry mekanizması
        last_error = None
        for attempt in range(1, self.MAX_RETRIES + 1):
            try:
                # Nmap taramasını başlat
                self.scanner. scan(
                    hosts=target,
                    ports=ports,
                    arguments=f"{scan_params} --host-timeout {timeout}s"
                )
                
                # Sonuçları işle
                result = self._process_results(target, scan_type)
                logger.info(f"Scan completed successfully (attempt {attempt})")
                return result
                
            except nmap.PortScannerTimeout as e:
                error_msg = f"Scan timeout after {timeout}s (attempt {attempt}/{self.MAX_RETRIES})"
                logger.warning(error_msg)
                last_error = ScanTimeoutError(error_msg)
                
                if attempt >= self.MAX_RETRIES: 
                    raise last_error
                    
            except nmap.PortScannerError as e: 
                error_msg = f"Nmap scan error: {e} (attempt {attempt}/{self.MAX_RETRIES})"
                logger.error(error_msg)
                last_error = PortScanError(error_msg)
                
                if attempt >= self.MAX_RETRIES: 
                    raise last_error
                    
            except KeyError as e:
                error_msg = f"Target {target} not found in scan results:  {e}"
                logger.error(error_msg)
                raise PortScanError(error_msg)
                
            except Exception as e:
                error_msg = f"Unexpected scan error: {type(e).__name__}: {e}"
                logger.error(error_msg)
                raise PortScanError(error_msg)
        
        # Retry sonrası başarısız
        if last_error:
            raise last_error
    
    def _get_scan_params(self, scan_type:  str) -> str:
        """
        Get Nmap parameters for scan type
        
        Args: 
            scan_type: Scan mode
            
        Returns:
            Nmap command arguments
        """
        scan_types = {
            'quick': '-T4 -F',  # Hızlı, yaygın portlar
            'full': '-T4 -A -v',  # Detaylı, servis versiyonları
            'stealth': '-sS -T2',  # Gizli, yavaş
        }
        
        params = scan_types.get(scan_type, '-T4')
        logger.debug(f"Scan parameters for '{scan_type}': {params}")
        return params
    
    def _process_results(self, target: str, scan_type:  str) -> Dict:
        """
        Process and structure scan results
        
        Args: 
            target:  Scanned target
            scan_type:  Scan mode used
            
        Returns:
            Structured scan results
        """
        if target not in self.scanner.all_hosts():
            raise PortScanError(f"No results found for target:  {target}")
        
        host_data = self.scanner[target]
        
        result = {
            'target': target,
            'scan_type': scan_type,
            'timestamp': datetime.now().isoformat(),
            'state': host_data.state(),
            'protocols': {},
            'hostnames': host_data.hostnames(),
            'summary': {
                'total_open_ports': 0,
                'total_filtered_ports': 0,
                'total_closed_ports': 0
            }
        }
        
        # Protokolleri işle (TCP, UDP)
        for protocol in host_data.all_protocols():
            ports_data = {}
            port_list = host_data[protocol]. keys()
            
            for port in port_list:
                port_info = host_data[protocol][port]
                state = port_info['state']
                
                ports_data[port] = {
                    'state': state,
                    'service': port_info. get('name', 'unknown'),
                    'product': port_info.get('product', ''),
                    'version': port_info.get('version', ''),
                    'extrainfo': port_info.get('extrainfo', '')
                }
                
                # Özet istatistikleri güncelle
                if state == 'open':
                    result['summary']['total_open_ports'] += 1
                elif state == 'filtered':
                    result['summary']['total_filtered_ports'] += 1
                elif state == 'closed': 
                    result['summary']['total_closed_ports'] += 1
            
            result['protocols'][protocol] = ports_data
        
        logger.info(
            f"Scan results:  {result['summary']['total_open_ports']} open, "
            f"{result['summary']['total_filtered_ports']} filtered, "
            f"{result['summary']['total_closed_ports']} closed"
        )
        
        return result
    
    def get_scan_info(self) -> Dict:
        """
        Get information about the last scan
        
        Returns: 
            Scan metadata
        """
        return {
            'command_line': self.scanner.command_line(),
            'scanstats': self.scanner.scanstats(),
            'nmap_version': self.scanner.nmap_version()
        }