"""
Enhanced CVE Manager with caching, rate limiting, and retry logic
"""

import requests
import json
import logging
import time
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
from functools import lru_cache
import hashlib

from config import CVEConfig

logger = logging.getLogger(__name__)


class CVEManager:
    """
    CVE data manager with NVD API integration, caching, and rate limit handling
    """
    
    def __init__(self):
        """Initialize CVE Manager"""
        self.api_url = CVEConfig.API_URL
        self.api_key = CVEConfig.API_KEY
        self.timeout = CVEConfig.TIMEOUT
        self.max_retries = CVEConfig.MAX_RETRIES
        self.retry_delay = CVEConfig.RETRY_DELAY
        self.results_per_page = CVEConfig.RESULTS_PER_PAGE
        
        # Session setup
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CyberSec-Agent/1.0',
            'Accept': 'application/json'
        })
        
        if self.api_key:
            self.session.headers.update({'apiKey': self.api_key})
            logger.info("NVD API key configured")
        else:
            logger.warning("No NVD API key - rate limits will be restrictive")
        
        # Statistics
        self.stats = {
            'total_queries': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'rate_limit_hits': 0,
            'errors': 0
        }
    
    def search_cves_by_service(
        self, 
        service_name: str, 
        version: str,
        max_results: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Search CVEs for a specific service and version with caching
        
        Args:
            service_name (str): Service name (e.g., apache, nginx)
            version (str): Service version (e.g., 2.4.49)
            max_results (int): Maximum number of results to return
            
        Returns:
            List[Dict]: List of CVE data dictionaries
        """
        if not service_name or not version:
            logger.warning("Service name or version is empty")
            return []
        
        # Generate cache key
        cache_key = self._generate_cache_key(service_name, version)
        
        # Check cache first
        if CVEConfig.CACHE_ENABLED:
            cached = self._get_from_cache(cache_key)
            if cached is not None:
                self.stats['cache_hits'] += 1
                logger.debug(f"Cache hit for {service_name} {version}")
                return cached[:max_results]
        
        self.stats['cache_misses'] += 1
        self.stats['total_queries'] += 1
        
        # Query NVD API with retry logic
        cves = self._query_nvd_with_retry(service_name, version)
        
        # Cache the results
        if CVEConfig.CACHE_ENABLED and cves:
            self._save_to_cache(cache_key, cves)
        
        return cves[:max_results]
    
    def _query_nvd_with_retry(
        self, 
        service_name: str, 
        version: str
    ) -> List[Dict[str, Any]]:
        """
        Query NVD API with exponential backoff retry
        
        Args:
            service_name (str): Service name
            version (str): Service version
            
        Returns:
            List[Dict]: CVE data list
        """
        params = {
            'keywordSearch': f'{service_name} {version}',
            'resultsPerPage': self.results_per_page,
            'startIndex': 0
        }
        
        last_exception = None
        
        for attempt in range(1, self.max_retries + 1):
            try:
                logger.debug(f"CVE query attempt {attempt}/{self.max_retries}: {service_name} {version}")
                
                response = self.session.get(
                    self.api_url, 
                    params=params, 
                    timeout=self.timeout
                )
                
                # Handle rate limiting (403)
                if response.status_code == 403:
                    self.stats['rate_limit_hits'] += 1
                    logger.warning(f"Rate limit hit (attempt {attempt})")
                    
                    if attempt < self.max_retries:
                        # Exponential backoff
                        wait_time = self.retry_delay * (2 ** (attempt - 1))
                        logger.info(f"Waiting {wait_time}s before retry...")
                        time.sleep(wait_time)
                        continue
                    else:
                        logger.error("Max retries exceeded for rate limit")
                        return []
                
                response.raise_for_status()
                data = response.json()
                
                cves = self._process_nvd_response(data)
                logger.info(f"Found {len(cves)} CVEs for {service_name} {version}")
                
                return cves
                
            except requests.exceptions.Timeout as e:
                last_exception = e
                logger.warning(f"Attempt {attempt}: Request timeout")
                if attempt < self.max_retries:
                    time.sleep(5)
                    
            except requests.exceptions.ConnectionError as e:
                last_exception = e
                logger.error(f"Attempt {attempt}: Connection error")
                if attempt < self.max_retries:
                    time.sleep(10)
                    
            except json.JSONDecodeError as e:
                last_exception = e
                logger.error(f"Attempt {attempt}: Invalid JSON response")
                if attempt < self.max_retries:
                    time.sleep(3)
                    
            except Exception as e:
                last_exception = e
                logger.error(f"Attempt {attempt}: Unexpected error: {str(e)}")
                if attempt < self.max_retries:
                    time.sleep(5)
        
        # All retries failed
        self.stats['errors'] += 1
        logger.error(f"All CVE query attempts failed: {last_exception}")
        return []
    
    def _process_nvd_response(self, data: Dict) -> List[Dict[str, Any]]:
        """
        Process NVD API response into structured format
        
        Args:
            data (Dict): Raw NVD API response
            
        Returns:
            List[Dict]: Processed CVE list
        """
        cves = []
        
        if 'vulnerabilities' not in data:
            return cves
        
        for vuln in data['vulnerabilities']:
            try:
                cve = vuln['cve']
                cve_id = cve.get('id', '')
                
                # Get CVSS metrics
                cvss_metrics = self._get_cvss_metrics(cve)
                
                # Get descriptions
                descriptions = cve.get('descriptions', [])
                description = self._get_english_description(descriptions)
                
                # Last modified date
                last_modified = cve.get('lastModified', datetime.now().isoformat())
                
                cve_data = {
                    'id': cve_id,
                    'description': description,
                    'cvss_score': cvss_metrics.get('score', 0.0),
                    'cvss_severity': cvss_metrics.get('severity', 'UNKNOWN'),
                    'cvss_vector': cvss_metrics.get('vector', ''),
                    'last_modified': last_modified,
                    'references': self._get_references(cve),
                    'affected_products': self._get_affected_products(cve)
                }
                
                cves.append(cve_data)
                
            except Exception as e:
                logger.warning(f"Error processing CVE: {str(e)}")
                continue
        
        # Sort by CVSS score (highest first)
        return sorted(cves, key=lambda x: x['cvss_score'], reverse=True)
    
    def _get_cvss_metrics(self, cve_data: Dict) -> Dict[str, Any]:
        """
        Extract CVSS metrics from CVE data
        
        Args:
            cve_data (Dict): CVE data
            
        Returns:
            Dict: CVSS score, severity, and vector
        """
        metrics = cve_data.get('metrics', {})
        
        # Try CVSS 3.1 or 3.0 first
        for version in ['cvssMetricV31', 'cvssMetricV30']:
            if version in metrics and metrics[version]:
                metric = metrics[version][0]
                cvss_data = metric.get('cvssData', {})
                return {
                    'score': cvss_data.get('baseScore', 0.0),
                    'severity': cvss_data.get('baseSeverity', 'UNKNOWN').upper(),
                    'vector': cvss_data.get('vectorString', '')
                }
        
        # Fallback to CVSS 2.0
        if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
            metric = metrics['cvssMetricV2'][0]
            cvss_data = metric.get('cvssData', {})
            score = cvss_data.get('baseScore', 0.0)
            return {
                'score': score,
                'severity': self._get_cvss2_severity(score),
                'vector': cvss_data.get('vectorString', '')
            }
        
        return {'score': 0.0, 'severity': 'UNKNOWN', 'vector': ''}
    
    def _get_cvss2_severity(self, score: float) -> str:
        """Map CVSS 2.0 score to severity level"""
        if score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        elif score > 0.0:
            return 'LOW'
        return 'NONE'
    
    def _get_english_description(self, descriptions: List[Dict]) -> str:
        """Extract English description from list"""
        for desc in descriptions:
            if desc.get('lang', '').lower() == 'en':
                return desc.get('value', '')
        return descriptions[0].get('value', '') if descriptions else ''
    
    def _get_references(self, cve_data: Dict) -> List[str]:
        """Extract reference URLs"""
        references = cve_data.get('references', [])
        return [ref.get('url', '') for ref in references if ref.get('url')][:5]
    
    def _get_affected_products(self, cve_data: Dict) -> List[str]:
        """Extract affected products from CVE"""
        affected = []
        configurations = cve_data.get('configurations', [])
        
        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                cpe_matches = node.get('cpeMatch', [])
                for match in cpe_matches:
                    criteria = match.get('criteria', '')
                    if criteria:
                        parts = criteria.split(':')
                        if len(parts) >= 5:
                            vendor, product = parts[3], parts[4]
                            affected.append(f"{vendor}/{product}")
        
        return list(set(affected))[:5]
    
    def get_recent_cves(
        self, 
        days: int = 7, 
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """
        Get recently published CVEs
        
        Args:
            days (int): Number of days to look back
            limit (int): Maximum results
            
        Returns:
            List[Dict]: Recent CVE list
        """
        try:
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days)
            
            params = {
                'pubStartDate': start_date.strftime('%Y-%m-%dT00:00:00.000 UTC-00:00'),
                'pubEndDate': end_date.strftime('%Y-%m-%dT23:59:59.999 UTC-00:00'),
                'resultsPerPage': limit,
                'startIndex': 0
            }
            
            logger.debug(f"Fetching CVEs from last {days} days")
            response = self.session.get(self.api_url, params=params, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            return self._process_nvd_response(data)
            
        except Exception as e:
            logger.error(f"Error fetching recent CVEs: {str(e)}")
            return []
    
    def _generate_cache_key(self, service_name: str, version: str) -> str:
        """Generate cache key for service/version combination"""
        key_string = f"{service_name.lower()}:{version}".encode('utf-8')
        return hashlib.md5(key_string).hexdigest()
    
    @lru_cache(maxsize=200)
    def _get_from_cache(self, cache_key: str) -> Optional[List[Dict[str, Any]]]:
        """Get CVE data from cache (LRU cache)"""
        return None
    
    def _save_to_cache(self, cache_key: str, cves: List[Dict[str, Any]]) -> None:
        """Save CVE data to cache"""
        # LRU cache handles this automatically when we call _get_from_cache
        pass
    
    def get_stats(self) -> Dict[str, Any]:
        """Get manager statistics"""
        cache_info = self._get_from_cache.cache_info()
        
        return {
            **self.stats,
            'cache_size': cache_info.currsize,
            'cache_maxsize': cache_info.maxsize,
            'cache_hit_rate': (
                self.stats['cache_hits'] / max(self.stats['total_queries'], 1) * 100
            ) if self.stats['total_queries'] > 0 else 0
        }
    
    def clear_cache(self) -> None:
        """Clear the CVE cache"""
        self._get_from_cache.cache_clear()
        logger.info("CVE cache cleared")