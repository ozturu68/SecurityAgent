"""
Enhanced Security Validator with SSRF protection and comprehensive input validation
"""

import re
import logging
import socket
import ipaddress
from ipaddress import ip_address, ip_network, AddressValueError, NetmaskValueError
from typing import Optional, Tuple, List
from urllib.parse import urlparse

from config import SecurityConfig

logger = logging.getLogger(__name__)


class SecurityException(Exception):
    """Custom exception for security violations"""
    pass


class SSRFException(SecurityException):
    """Exception for SSRF attack attempts"""
    pass


class SecurityValidator:
    """
    Comprehensive security validator with SSRF protection
    """
    
    # Allowed domain characters
    ALLOWED_DOMAIN_CHARS = r'^[a-z0-9\-\.]+$'
    
    # Dangerous characters and patterns from config
    DANGEROUS_CHARS = SecurityConfig.DANGEROUS_CHARS
    DANGEROUS_PATTERNS = SecurityConfig.DANGEROUS_PATTERNS
    
    # Private IP ranges (RFC 1918, RFC 4193, etc.)
    PRIVATE_IP_RANGES = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),  # Loopback
        ipaddress.ip_network('169.254.0.0/16'),  # Link-local
        ipaddress.ip_network('::1/128'),  # IPv6 loopback
        ipaddress.ip_network('fc00::/7'),  # IPv6 private
        ipaddress.ip_network('fe80::/10'),  # IPv6 link-local
    ]
    
    # Special domains to block
    BLOCKED_DOMAINS = [
        'localhost',
        'broadcasthost',
        'ip6-localhost',
        'ip6-loopback',
        'local',
        'invalid',
        'test',
        'internal',
        'corp',
        'intranet'
    ]
    
    @classmethod
    def validate_target(cls, target: str, allow_private: bool = False) -> str:
        """
        Validate and classify target (IP, domain, or subnet)
        
        Args:
            target (str): Target to validate
            allow_private (bool): Allow private IP addresses
            
        Returns:
            str: Target type ('IP', 'DOMAIN', 'SUBNET')
            
        Raises:
            SecurityException: If target is invalid or dangerous
        """
        if not target or len(target.strip()) == 0:
            logger.error("Empty target provided")
            raise SecurityException("Target cannot be empty")
        
        target = target.strip().lower()
        
        # Check for dangerous characters
        cls._check_dangerous_chars(target)
        
        # Try IP address
        try:
            ip = ip_address(target)
            cls._check_ip_safety(ip, allow_private)
            logger.debug(f"Valid IP address: {target}")
            return "IP"
        except (AddressValueError, ValueError):
            pass
        
        # Try subnet
        if '/' in target:
            try:
                network = ip_network(target, strict=False)
                cls._check_network_safety(network, allow_private)
                logger.debug(f"Valid subnet: {target}")
                return "SUBNET"
            except (AddressValueError, NetmaskValueError, ValueError):
                pass
        
        # Try domain
        if cls._is_valid_domain(target):
            cls._check_domain_safety(target, allow_private)
            logger.debug(f"Valid domain: {target}")
            return "DOMAIN"
        
        logger.error(f"Invalid target format: {target}")
        raise SecurityException(
            "Invalid target format. Must be IP address, domain, or subnet (CIDR)"
        )
    
    @classmethod
    def validate_url(cls, url: str, allow_private: bool = False) -> bool:
        """
        Validate URL with SSRF protection
        
        Args:
            url (str): URL to validate
            allow_private (bool): Allow private IP addresses
            
        Returns:
            bool: True if valid
            
        Raises:
            SSRFException: If URL poses SSRF risk
            SecurityException: If URL is invalid
        """
        if not url or not url.strip():
            raise SecurityException("URL cannot be empty")
        
        if not SecurityConfig.ENABLE_SSRF_PROTECTION:
            logger.warning("SSRF protection is DISABLED")
            return True
        
        try:
            parsed = urlparse(url)
            
            # Check scheme
            if parsed.scheme not in ['http', 'https']:
                raise SecurityException(f"Invalid URL scheme: {parsed.scheme}")
            
            # Get hostname
            hostname = parsed.hostname
            if not hostname:
                raise SecurityException("URL must have a hostname")
            
            # Check for blocked domains
            for blocked in cls.BLOCKED_DOMAINS:
                if blocked in hostname.lower():
                    raise SSRFException(
                        f"Blocked domain detected: {blocked} in {hostname}"
                    )
            
            # Resolve hostname to IP
            try:
                ip_str = socket.gethostbyname(hostname)
                ip = ip_address(ip_str)
                
                # Check if IP is private
                cls._check_ip_safety(ip, allow_private)
                
                logger.debug(f"URL validated: {url} -> {ip_str}")
                return True
                
            except socket.gaierror as e:
                raise SecurityException(f"Cannot resolve hostname: {hostname}")
            
        except SSRFException:
            raise
        except SecurityException:
            raise
        except Exception as e:
            logger.error(f"URL validation error: {str(e)}")
            raise SecurityException(f"Invalid URL: {str(e)}")
    
    @classmethod
    def _check_ip_safety(cls, ip: ipaddress.IPv4Address | ipaddress.IPv6Address, 
                        allow_private: bool) -> None:
        """
        Check if IP address is safe to access
        
        Args:
            ip: IP address object
            allow_private: Allow private IPs
            
        Raises:
            SSRFException: If IP is unsafe
        """
        # Always block loopback
        if ip.is_loopback:
            raise SSRFException(f"Loopback address not allowed: {ip}")
        
        # Always block link-local
        if ip.is_link_local:
            raise SSRFException(f"Link-local address not allowed: {ip}")
        
        # Always block multicast
        if ip.is_multicast:
            raise SSRFException(f"Multicast address not allowed: {ip}")
        
        # Check private IPs if not allowed
        if not allow_private and ip.is_private:
            # Check if in allowed private ranges
            if SecurityConfig.ALLOWED_PRIVATE_RANGES:
                for allowed_range in SecurityConfig.ALLOWED_PRIVATE_RANGES:
                    try:
                        if ip in ip_network(allowed_range):
                            logger.debug(f"IP {ip} in allowed private range")
                            return
                    except:
                        pass
            
            raise SSRFException(f"Private IP address not allowed: {ip}")
    
    @classmethod
    def _check_network_safety(cls, network: ipaddress.IPv4Network | ipaddress.IPv6Network,
                             allow_private: bool) -> None:
        """
        Check if network is safe to scan
        
        Args:
            network: Network object
            allow_private: Allow private networks
            
        Raises:
            SSRFException: If network is unsafe
        """
        # Check if network overlaps with private ranges
        if not allow_private:
            for private_range in cls.PRIVATE_IP_RANGES:
                if network.overlaps(private_range):
                    if not SecurityConfig.ALLOWED_PRIVATE_RANGES:
                        raise SSRFException(
                            f"Network overlaps with private range: {network}"
                        )
    
    @classmethod
    def _is_valid_domain(cls, domain: str) -> bool:
        """
        Check if string is a valid domain name
        
        Args:
            domain (str): Domain to check
            
        Returns:
            bool: True if valid domain format
        """
        domain_pattern = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
        return bool(re.match(domain_pattern, domain))
    
    @classmethod
    def _check_domain_safety(cls, domain: str, allow_private: bool) -> None:
        """
        Check if domain is safe to access
        
        Args:
            domain (str): Domain name
            allow_private (bool): Allow private IPs behind domain
            
        Raises:
            SSRFException: If domain is unsafe
        """
        # Check blocked domains
        for blocked in cls.BLOCKED_DOMAINS:
            if blocked in domain.lower():
                raise SSRFException(f"Blocked domain: {blocked} in {domain}")
        
        # Check domain length
        if len(domain) > 253:
            raise SecurityException("Domain name too long (max 253 characters)")
        
        # Check for invalid characters
        if not re.match(cls.ALLOWED_DOMAIN_CHARS, domain):
            raise SecurityException("Domain contains invalid characters")
        
        # Try to resolve domain and check IP
        if SecurityConfig.ENABLE_SSRF_PROTECTION:
            try:
                ip_str = socket.gethostbyname(domain)
                ip = ip_address(ip_str)
                cls._check_ip_safety(ip, allow_private)
            except socket.gaierror:
                # DNS resolution failed - might be okay for some use cases
                logger.warning(f"Cannot resolve domain: {domain}")
            except SSRFException:
                raise
    
    @classmethod
    def _check_dangerous_chars(cls, text: str) -> None:
        """
        Check for dangerous characters in input
        
        Args:
            text (str): Text to check
            
        Raises:
            SecurityException: If dangerous characters found
        """
        found_chars = [char for char in cls.DANGEROUS_CHARS if char in text]
        if found_chars:
            raise SecurityException(
                f"Dangerous characters detected: {', '.join(found_chars)}"
            )
    
    @classmethod
    def validate_scan_mode(cls, mode: str) -> bool:
        """
        Validate scan mode
        
        Args:
            mode (str): Scan mode to validate
            
        Returns:
            bool: True if valid
            
        Raises:
            SecurityException: If mode is invalid
        """
        from config import ScanConfig
        
        valid_modes = list(ScanConfig.SCAN_MODES.keys())
        
        if mode.lower() not in valid_modes:
            raise SecurityException(
                f"Invalid scan mode '{mode}'. Valid modes: {', '.join(valid_modes)}"
            )
        
        return True
    
    @classmethod
    def sanitize_nmap_command(cls, target: str, mode: str) -> str:
        """
        Build safe Nmap command
        
        Args:
            target (str): Validated target
            mode (str): Scan mode
            
        Returns:
            str: Safe Nmap command
            
        Raises:
            SecurityException: If parameters are unsafe
        """
        from config import ScanConfig
        
        # Validate inputs
        cls.validate_target(target)
        cls.validate_scan_mode(mode)
        
        # Get scan arguments from config
        scan_args = ScanConfig.SCAN_MODES[mode.lower()]['nmap_args']
        
        # Build safe command
        safe_command = f"nmap {scan_args} -oX - {target}"
        
        logger.debug(f"Safe Nmap command: {safe_command}")
        return safe_command
    
    @classmethod
    def sanitize_prompt(cls, prompt: str) -> str:
        """
        Sanitize LLM prompt for security
        
        Args:
            prompt (str): Prompt to sanitize
            
        Returns:
            str: Sanitized prompt
            
        Raises:
            SecurityException: If prompt is dangerous
        """
        if not prompt or len(prompt.strip()) == 0:
            raise SecurityException("Prompt cannot be empty")
        
        # Check for prompt injection patterns
        dangerous_llm_patterns = [
            r'ignore\s+previous\s+instructions',
            r'system\s+prompt',
            r'you\s+are\s+no\s+longer',
            r'override\s+restrictions',
            r'bypass\s+security',
            r'reveal\s+the\s+prompt',
            r'act\s+as\s+(god|admin|system)',
            r'<\/?system>',
            r'\/\/\s*system',
        ]
        
        for pattern in dangerous_llm_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                raise SecurityException(
                    f"Potential prompt injection detected: {pattern}"
                )
        
        # Length check
        from config import AIConfig
        if len(prompt) > AIConfig.MAX_PROMPT_SIZE:
            logger.warning(f"Prompt too long ({len(prompt)}), truncating")
            prompt = prompt[:AIConfig.MAX_PROMPT_SIZE] + "..."
        
        return prompt
    
    @classmethod
    def sanitize_output(cls, output: str) -> str:
        """
        Sanitize LLM output for security
        
        Args:
            output (str): Output to sanitize
            
        Returns:
            str: Sanitized output
        """
        if not output:
            return ""
        
        # Remove potential XSS
        output = re.sub(r'<script.*?>.*?</script>', '', output, 
                       flags=re.IGNORECASE | re.DOTALL)
        output = re.sub(r'on\w+\s*=\s*["\'].*?["\']', '', output, 
                       flags=re.IGNORECASE)
        output = re.sub(r'javascript\s*:', '', output, flags=re.IGNORECASE)
        
        # Mask sensitive data (optional)
        output = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                       '[EMAIL_MASKED]', output)
        
        return output
    
    @classmethod
    def validate_file_path(cls, path: str) -> bool:
        """
        Validate file path for security
        
        Args:
            path (str): File path to validate
            
        Returns:
            bool: True if safe
            
        Raises:
            SecurityException: If path is unsafe
        """
        # Block path traversal
        if ".." in path or "~" in path:
            raise SecurityException("Path traversal attempt detected")
        
        # Block absolute paths
        if path.startswith('/') or ':' in path or '\\' in path:
            raise SecurityException("Absolute paths not allowed")
        
        # Check for dangerous characters
        cls._check_dangerous_chars(path)
        
        return True