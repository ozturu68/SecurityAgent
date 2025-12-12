import socket
import subprocess
import logging
from typing import Dict, Optional
import geoip2.database
import geoip2.errors
from pathlib import Path

logger = logging.getLogger(__name__)

class ReconModule:
    """Reconnaissance module for domain/IP intelligence gathering"""
    
    def __init__(self, geoip_db_path: Optional[str] = None):
        """
        Initialize reconnaissance module
        
        Args: 
            geoip_db_path: Path to GeoLite2-City. mmdb database file
        """
        self. geoip_reader = None
        
        # GeoIP veritabanı yolu
        if geoip_db_path and Path(geoip_db_path).exists():
            try:
                self.geoip_reader = geoip2.database.Reader(geoip_db_path)
                logger. info(f"GeoIP database loaded:  {geoip_db_path}")
            except Exception as e: 
                logger.warning(f"Failed to load GeoIP database: {e}")
        else:
            logger.warning("GeoIP database not found.  Location features disabled.")
    
    def resolve_target(self, target: str) -> Dict[str, any]:
        """
        Resolve domain to IP or validate IP address
        
        Args: 
            target: Domain name or IP address
            
        Returns: 
            Dictionary containing resolution results
        """
        result = {
            'target': target,
            'ip_address': None,
            'hostname': None,
            'type': None,
            'error': None,
            'geolocation': None
        }
        
        try:
            # IP adresi mi kontrol et
            socket.inet_aton(target)
            result['type'] = 'ip'
            result['ip_address'] = target
            
            # Reverse DNS lookup
            try:
                hostname = socket.gethostbyaddr(target)
                result['hostname'] = hostname[0]
                logger.info(f"Reverse DNS:  {target} -> {hostname[0]}")
            except socket. herror as e:
                logger.debug(f"Reverse DNS failed for {target}: {e}")
            except socket.timeout:
                logger.warning(f"Reverse DNS timeout for {target}")
                
        except socket.error:
            # Domain adı ise IP'ye çözümle
            result['type'] = 'domain'
            result['hostname'] = target
            
            try:
                ip_address = socket.gethostbyname(target)
                result['ip_address'] = ip_address
                logger.info(f"DNS resolution: {target} -> {ip_address}")
            except socket. gaierror as e:
                error_msg = f"DNS resolution failed:  {e}"
                result['error'] = error_msg
                logger.error(error_msg)
                return result
            except socket.timeout:
                error_msg = f"DNS resolution timeout for {target}"
                result['error'] = error_msg
                logger.error(error_msg)
                return result
        
        # GeoIP lokasyon bilgisi ekle
        if result['ip_address'] and self.geoip_reader:
            result['geolocation'] = self._get_geolocation(result['ip_address'])
        
        return result
    
    def _get_geolocation(self, ip_address: str) -> Optional[Dict[str, str]]:
        """
        Get geographical location of IP address
        
        Args: 
            ip_address: IP address to lookup
            
        Returns: 
            Dictionary with location data or None
        """
        if not self.geoip_reader:
            return None
        
        try: 
            response = self.geoip_reader.city(ip_address)
            location = {
                'country': response.country.name,
                'country_code': response.country.iso_code,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location. longitude,
                'timezone': response.location.time_zone
            }
            logger.info(f"GeoIP:  {ip_address} -> {location['city']}, {location['country']}")
            return location
            
        except geoip2.errors.AddressNotFoundError:
            logger.debug(f"IP address not found in GeoIP database:  {ip_address}")
        except geoip2.errors.GeoIP2Error as e:
            logger.warning(f"GeoIP lookup error: {e}")
        except Exception as e:
            logger.error(f"Unexpected GeoIP error: {e}")
        
        return None
    
    def whois_lookup(self, target: str, timeout: int = 10) -> Dict[str, any]:
        """
        Perform WHOIS lookup on target
        
        Args:
            target: Domain or IP to lookup
            timeout: Command timeout in seconds
            
        Returns:
            Dictionary containing WHOIS data
        """
        result = {
            'target': target,
            'whois_data': None,
            'error': None
        }
        
        try: 
            # WHOIS komutunu çalıştır
            process = subprocess.run(
                ['whois', target],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            
            if process.returncode == 0:
                result['whois_data'] = process.stdout
                logger.info(f"WHOIS lookup successful for {target}")
            else:
                error_msg = f"WHOIS command failed:  {process.stderr}"
                result['error'] = error_msg
                logger.error(error_msg)
                
        except subprocess. TimeoutExpired:
            error_msg = f"WHOIS lookup timeout ({timeout}s) for {target}"
            result['error'] = error_msg
            logger.error(error_msg)
        except FileNotFoundError:
            error_msg = "WHOIS command not found. Install whois package."
            result['error'] = error_msg
            logger.error(error_msg)
        except Exception as e:
            error_msg = f"Unexpected WHOIS error: {e}"
            result['error'] = error_msg
            logger.error(error_msg)
        
        return result
    
    def gather_info(self, target: str) -> Dict[str, any]: 
        """
        Gather all reconnaissance information
        
        Args:
            target: Target domain or IP
            
        Returns: 
            Complete reconnaissance data
        """
        logger.info(f"Starting reconnaissance on {target}")
        
        # DNS çözümleme
        resolution = self.resolve_target(target)
        
        # WHOIS bilgisi (sadece çözümleme başarılıysa)
        whois_data = None
        if not resolution['error']:
            whois_data = self.whois_lookup(target)
        
        return {
            'resolution': resolution,
            'whois':  whois_data,
            'timestamp': __import__('datetime').datetime.now().isoformat()
        }
    
    def __del__(self):
        """Close GeoIP reader on cleanup"""
        if self.geoip_reader:
            self. geoip_reader.close()