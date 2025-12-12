"""
CyberSec-Agent Configuration Management
Handles environment variables, validation, and default settings
"""

import os
from pathlib import Path
from typing import Optional, List
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# ============================================
# PROJECT STRUCTURE
# ============================================
BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / 'logs'
OUTPUT_DIR = BASE_DIR / 'outputs'
DATA_DIR = BASE_DIR / 'data'

# Create directories if they don't exist
for directory in [LOG_DIR, OUTPUT_DIR, DATA_DIR]:
    directory.mkdir(parents=True, exist_ok=True)


# ============================================
# AI MODEL CONFIGURATION
# ============================================
class AIConfig:
    """AI Model Configuration"""
    MODEL_NAME: str = os.getenv('MODEL_NAME', 'mistral:latest')
    OLLAMA_URL: str = os.getenv('OLLAMA_URL', 'http://localhost:11434')
    MAX_PROMPT_SIZE: int = int(os.getenv('MAX_PROMPT_SIZE', '10000'))
    
    # System prompt for vulnerability analysis
    SYSTEM_PROMPT: str = """You are a professional cybersecurity analyst AI. Your job is to analyze network scan data and output security findings in JSON format.

INPUT: Network scan data containing open ports, services, and metadata
OUTPUT: Pure JSON object with vulnerability analysis

REQUIRED JSON FORMAT:
{
  "summary": "Brief executive summary of security findings",
  "risk_level": "Critical|High|Medium|Low",
  "vulnerabilities": [
    {
      "service": "service name (e.g., ssh, http)",
      "port": 22,
      "severity": "Critical|High|Medium|Low",
      "cve_ids": ["CVE-2021-XXXXX"],
      "description": "Detailed technical explanation of the risk",
      "attack_scenarios": ["Potential attack scenario 1"],
      "remediation": ["Specific remediation step 1"]
    }
  ],
  "recommendations": [
    {
      "severity": "High|Medium|Low",
      "description": "Specific actionable recommendation"
    }
  ],
  "priority_actions": ["Most critical action items"],
  "overall_recommendation": "Strategic security recommendation"
}

CRITICAL RULES:
1. Output ONLY the JSON object (no markdown code blocks, no ```json)
2. Do NOT include 'think', 'reasoning', or any other extra fields
3. Use accurate severity levels: Critical (9-10), High (7-8), Medium (4-6), Low (1-3)
4. Be specific and technical in vulnerability descriptions
5. Provide actionable, realistic recommendations
6. If no vulnerabilities found, return empty array: []
7. Always include at least a summary and risk_level

Now analyze the scan data and respond with ONLY the JSON object:"""


# ============================================
# SCAN CONFIGURATION
# ============================================
class ScanConfig:
    """Network Scanning Configuration"""
    DEFAULT_MODE: str = os.getenv('DEFAULT_SCAN_MODE', 'quick')
    TIMEOUT: int = int(os.getenv('SCAN_TIMEOUT', '300'))
    RECON_TIMEOUT: int = int(os.getenv('RECON_TIMEOUT', '30'))
    
    # Scan mode definitions
    SCAN_MODES = {
        "quick": {
            "description": "Hızlı tarama: En yaygın 100 port",
            "nmap_args": "-F -T4 --open --reason",
            "requires_root": False,
            "duration": "~30-60 saniye"
        },
        "stealth": {
            "description": "Gizli tarama: SYN scan (-sS)",
            "nmap_args": "-sS -T2 --open --reason",
            "requires_root": True,
            "duration": "~2-5 dakika"
        },
        "full": {
            "description": "Kapsamlı tarama: Tüm portlar + versiyon tespiti",
            "nmap_args": "-sV -sC -p- -T4 --open --reason",
            "requires_root": False,
            "duration": "~15-30 dakika"
        }
    }


# ============================================
# WEB CRAWLER CONFIGURATION
# ============================================
class CrawlerConfig:
    """Web Crawler Configuration"""
    MAX_DEPTH: int = int(os.getenv('CRAWLER_MAX_DEPTH', '2'))
    MAX_URLS: int = int(os.getenv('CRAWLER_MAX_URLS', '50'))
    TIMEOUT: int = int(os.getenv('CRAWLER_TIMEOUT', '10'))
    MAX_CONCURRENT: int = int(os.getenv('CRAWLER_MAX_CONCURRENT', '10'))
    USER_AGENT: str = os.getenv('CRAWLER_USER_AGENT', 
                                'CyberSec-Agent/1.0 (Security Research)')
    
    # Sensitive endpoints to scan
    SENSITIVE_PATHS: List[str] = [
        # Admin panels
        '/admin', '/admin.php', '/administrator', '/wp-admin',
        '/backend', '/controlpanel', '/cpanel',
        
        # Config files
        '/config.php', '/.env', '/web.config', '/appsettings.json',
        '/database.yml', '/settings.py',
        
        # Backup files
        '/backup.zip', '/backup.tar.gz', '/database.sql',
        
        # API endpoints
        '/api', '/graphql', '/swagger', '/api-docs',
        
        # Debug files
        '/phpinfo.php', '/debug.php', '/error.log',
        
        # Auth endpoints
        '/login', '/auth', '/oauth', '/sso',
        
        # Database
        '/phpmyadmin', '/mysql', '/dbadmin',
        
        # Version control
        '/.git', '/.git/config', '/.svn'
    ]


# ============================================
# CVE MANAGER CONFIGURATION
# ============================================
class CVEConfig:
    """CVE Database Configuration"""
    API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    API_KEY: Optional[str] = os.getenv('NVD_API_KEY')
    TIMEOUT: int = int(os.getenv('CVE_QUERY_TIMEOUT', '15'))
    
    # Cache settings
    CACHE_ENABLED: bool = os.getenv('CVE_CACHE_ENABLED', 'true').lower() == 'true'
    CACHE_SIZE: int = int(os.getenv('CVE_CACHE_SIZE', '200'))
    
    # Retry settings
    MAX_RETRIES: int = int(os.getenv('CVE_MAX_RETRIES', '3'))
    RETRY_DELAY: int = int(os.getenv('CVE_RETRY_DELAY', '30'))
    
    # Query settings
    RESULTS_PER_PAGE: int = int(os.getenv('CVE_RESULTS_PER_PAGE', '10'))


# ============================================
# LOGGING CONFIGURATION
# ============================================
class LogConfig:
    """Logging Configuration"""
    LEVEL: str = os.getenv('LOG_LEVEL', 'INFO')
    FILE: Path = Path(os.getenv('LOG_FILE', str(LOG_DIR / 'cybersec_agent.log')))
    MAX_BYTES: int = int(os.getenv('LOG_MAX_BYTES', '10485760'))  # 10MB
    BACKUP_COUNT: int = int(os.getenv('LOG_BACKUP_COUNT', '5'))
    FORMAT: str = os.getenv('LOG_FORMAT', 'json')  # 'json' or 'text'
    DEBUG_MODE: bool = os.getenv('DEBUG_MODE', 'false').lower() == 'true'


# ============================================
# OUTPUT CONFIGURATION
# ============================================
class OutputConfig:
    """Output and Reporting Configuration"""
    DIR: Path = Path(os.getenv('OUTPUT_DIR', str(OUTPUT_DIR)))
    FORMAT: str = os.getenv('OUTPUT_FORMAT', 'json')  # 'json' or 'html'


# ============================================
# SECURITY CONFIGURATION
# ============================================
class SecurityConfig:
    """Security Settings"""
    ENABLE_SSRF_PROTECTION: bool = os.getenv('ENABLE_SSRF_PROTECTION', 
                                             'true').lower() == 'true'
    
    # Allowed private IP ranges for scanning
    ALLOWED_PRIVATE_RANGES: List[str] = [
        r.strip() for r in os.getenv('ALLOWED_PRIVATE_RANGES', '').split(',') 
        if r.strip()
    ]
    
    # Dangerous characters for input validation
    DANGEROUS_CHARS: List[str] = [';', '&', '|', '`', '$', '(', ')', 
                                  '{', '}', '[', ']', '<', '>', '!', '~']
    
    # Dangerous patterns
    DANGEROUS_PATTERNS: List[str] = [
        r'/etc/passwd',
        r'/etc/shadow',
        r'\.\./',
        r'rm\s+-rf',
        r'chmod\s+777',
        r'wget\s+http',
        r'curl\s+http'
    ]


# ============================================
# PERFORMANCE CONFIGURATION
# ============================================
class PerformanceConfig:
    """Performance and Optimization Settings"""
    ENABLE_ASYNC: bool = os.getenv('ENABLE_ASYNC', 'true').lower() == 'true'
    MAX_CONCURRENT_SCANS: int = int(os.getenv('MAX_CONCURRENT_SCANS', '5'))


# ============================================
# SUPPORTED MODELS
# ============================================
SUPPORTED_MODELS = {
    "deepseek-1.5b": "deepseek-r1:1.5b",
    "deepseek-7b": "deepseek-r1:7b",
    "mistral": "mistral:latest",
    "nemotron": "nemotron-mini:latest"
}


# ============================================
# APPLICATION METADATA
# ============================================
APP_NAME = "CyberSec-Agent"
VERSION = "1.1.0"
AUTHOR = "O. Turan"
COPYRIGHT = f"© 2023-2024 {AUTHOR}"


# ============================================
# VALIDATION
# ============================================
def validate_config():
    """Validate configuration settings"""
    errors = []
    
    # Check if MODEL_NAME is supported
    if AIConfig.MODEL_NAME not in SUPPORTED_MODELS.values():
        errors.append(f"Unsupported model: {AIConfig.MODEL_NAME}")
    
    # Check scan mode
    if ScanConfig.DEFAULT_MODE not in ScanConfig.SCAN_MODES:
        errors.append(f"Invalid scan mode: {ScanConfig.DEFAULT_MODE}")
    
    # Check log level
    valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
    if LogConfig.LEVEL.upper() not in valid_log_levels:
        errors.append(f"Invalid log level: {LogConfig.LEVEL}")
    
    if errors:
        raise ValueError(f"Configuration validation failed:\n" + "\n".join(errors))
    
    return True


# Validate on import
try:
    validate_config()
except ValueError as e:
    print(f"⚠️  Configuration Warning: {e}")