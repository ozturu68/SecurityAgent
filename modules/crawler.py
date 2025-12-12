import asyncio
import aiohttp
import logging
from typing import List, Set, Dict, Optional
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import ipaddress
from datetime import datetime

logger = logging.getLogger(__name__)

class SSRFProtectionError(Exception):
    """Exception for SSRF protection violations"""
    pass

class CrawlerError(Exception):
    """Base exception for crawler errors"""
    pass

class AsyncWebCrawler:
    """Asynchronous web crawler with SSRF protection"""
    
    # Güvenlik ayarları
    MAX_PAGES = 100
    MAX_DEPTH = 3
    REQUEST_TIMEOUT = 10
    MAX_CONCURRENT_REQUESTS = 5
    
    # SSRF koruması - Yasaklı IP aralıkları
    BLOCKED_NETWORKS = [
        ipaddress.ip_network('10.0.0.0/8'),       # Private
        ipaddress.ip_network('172.16.0.0/12'),    # Private
        ipaddress.ip_network('192.168.0.0/16'),   # Private
        ipaddress.ip_network('127.0.0.0/8'),      # Loopback
        ipaddress.ip_network('169.254.0.0/16'),   # Link-local
        ipaddress.ip_network('::1/128'),          # IPv6 loopback
        ipaddress.ip_network('fc00::/7'),         # IPv6 private
    ]
    
    def __init__(
        self, 
        respect_robots: bool = True,
        user_agent: Optional[str] = None,
        rate_limit: float = 1.0
    ):
        """
        Initialize async web crawler
        
        Args:
            respect_robots:  Obey robots.txt rules
            user_agent: Custom user agent string
            rate_limit:  Minimum seconds between requests
        """
        self.respect_robots = respect_robots
        self.user_agent = user_agent or 'SecurityAgent-Crawler/1.0'
        self. rate_limit = rate_limit
        self.visited_urls: Set[str] = set()
        self.robots_cache: Dict[str, List[str]] = {}
        
        logger.info(f"Crawler initialized (robots: {respect_robots}, rate: {rate_limit}s)")
    
    async def crawl(
        self, 
        start_url: str, 
        max_pages: Optional[int] = None,
        max_depth: Optional[int] = None
    ) -> Dict:
        """
        Crawl website starting from URL
        
        Args:
            start_url: Starting URL
            max_pages: Maximum pages to crawl
            max_depth: Maximum crawl depth
            
        Returns: 
            Dictionary containing crawl results
        """
        max_pages = max_pages or self.MAX_PAGES
        max_depth = max_depth or self.MAX_DEPTH
        
        logger.info(f"Starting crawl:  {start_url} (max_pages={max_pages}, max_depth={max_depth})")
        
        # SSRF koruması kontrol
        await self._check_ssrf_protection(start_url)
        
        # robots.txt yükle
        if self.respect_robots:
            await self._load_robots_txt(start_url)
        
        results = {
            'start_url': start_url,
            'timestamp': datetime.now().isoformat(),
            'pages':  [],
            'errors': [],
            'summary': {
                'total_pages': 0,
                'total_links': 0,
                'total_errors': 0
            }
        }
        
        # Async session oluştur
        timeout = aiohttp.ClientTimeout(total=self.REQUEST_TIMEOUT)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            # İlk URL'yi kuyruğa ekle
            queue = [(start_url, 0)]  # (url, depth)
            
            while queue and len(self.visited_urls) < max_pages:
                # Eş zamanlı request batch'i
                batch = []
                while queue and len(batch) < self.MAX_CONCURRENT_REQUESTS:
                    batch.append(queue.pop(0))
                
                # Batch'i işle
                tasks = [
                    self._crawl_page(session, url, depth, max_depth, queue)
                    for url, depth in batch
                ]
                
                page_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Sonuçları topla
                for result in page_results:
                    if isinstance(result, Exception):
                        results['errors'].append(str(result))
                        results['summary']['total_errors'] += 1
                    elif result: 
                        results['pages'].append(result)
                        results['summary']['total_pages'] += 1
                        results['summary']['total_links'] += len(result. get('links', []))
                
                # Rate limiting
                await asyncio.sleep(self.rate_limit)
        
        logger.info(
            f"Crawl completed:  {results['summary']['total_pages']} pages, "
            f"{results['summary']['total_errors']} errors"
        )
        
        return results
    
    async def _crawl_page(
        self, 
        session: aiohttp.ClientSession,
        url: str,
        depth: int,
        max_depth: int,
        queue: List[tuple]
    ) -> Optional[Dict]:
        """
        Crawl single page
        
        Args:
            session:  Aiohttp session
            url: URL to crawl
            depth: Current depth
            max_depth: Maximum depth
            queue: URL queue for BFS
            
        Returns: 
            Page data or None
        """
        # Zaten ziyaret edildiyse atla
        if url in self. visited_urls:
            return None
        
        # robots.txt kontrolü
        if self.respect_robots and not self._is_allowed_by_robots(url):
            logger.debug(f"Blocked by robots.txt: {url}")
            return None
        
        self.visited_urls.add(url)
        
        try: 
            # HTTP isteği
            headers = {'User-Agent': self.user_agent}
            async with session. get(url, headers=headers, allow_redirects=True) as response:
                
                # Sadece HTML sayfalarını işle
                content_type = response.headers.get('Content-Type', '')
                if 'text/html' not in content_type:
                    logger.debug(f"Skipping non-HTML:  {url}")
                    return None
                
                html = await response.text()
                
                # HTML parsing
                soup = BeautifulSoup(html, 'html.parser')
                
                # Bağlantıları çıkar
                links = []
                if depth < max_depth:
                    links = await self._extract_links(url, soup, queue, depth)
                
                # Sayfa verilerini topla
                page_data = {
                    'url': url,
                    'status_code': response.status,
                    'depth': depth,
                    'title': soup.title.string if soup.title else '',
                    'links': links,
                    'forms': len(soup.find_all('form')),
                    'scripts':  len(soup.find_all('script')),
                    'content_length': len(html)
                }
                
                logger.info(f"Crawled: {url} (status={response.status}, links={len(links)})")
                return page_data
                
        except aiohttp.ClientError as e:
            logger.error(f"Request error for {url}: {e}")
            raise CrawlerError(f"Request failed:  {e}")
        except asyncio.TimeoutError:
            logger.error(f"Timeout for {url}")
            raise CrawlerError(f"Request timeout: {url}")
        except Exception as e: 
            logger.error(f"Unexpected error crawling {url}: {e}")
            raise CrawlerError(f"Crawl error: {e}")
    
    async def _extract_links(
        self, 
        base_url: str, 
        soup: BeautifulSoup,
        queue: List[tuple],
        current_depth: int
    ) -> List[str]:
        """
        Extract and queue links from page
        
        Args:
            base_url: Current page URL
            soup:  Parsed HTML
            queue: URL queue
            current_depth: Current crawl depth
            
        Returns: 
            List of extracted links
        """
        links = []
        base_domain = urlparse(base_url).netloc
        
        for anchor in soup.find_all('a', href=True):
            href = anchor['href']
            
            # Mutlak URL'ye çevir
            absolute_url = urljoin(base_url, href)
            parsed = urlparse(absolute_url)
            
            # Sadece aynı domain ve http(s)
            if parsed.netloc == base_domain and parsed.scheme in ['http', 'https']:
                # Fragment'leri temizle
                clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if parsed.query:
                    clean_url += f"?{parsed.query}"
                
                links.append(clean_url)
                
                # Kuyruğa ekle (henüz ziyaret edilmediyse)
                if clean_url not in self.visited_urls:
                    queue.append((clean_url, current_depth + 1))
        
        return links
    
    async def _check_ssrf_protection(self, url: str):
        """
        Check URL against SSRF protection rules
        
        Args:
            url: URL to check
            
        Raises:
            SSRFProtectionError: If URL is blocked
        """
        parsed = urlparse(url)
        hostname = parsed.hostname
        
        if not hostname:
            raise SSRFProtectionError("Invalid URL: no hostname")
        
        try:
            # IP adresini çözümle
            import socket
            ip = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip)
            
            # Yasaklı ağları kontrol et
            for network in self.BLOCKED_NETWORKS:
                if ip_obj in network:
                    raise SSRFProtectionError(
                        f"SSRF protection:  {hostname} resolves to blocked network {network}"
                    )
            
            logger.debug(f"SSRF check passed:  {hostname} -> {ip}")
            
        except socket.gaierror:
            raise SSRFProtectionError(f"Cannot resolve hostname: {hostname}")
    
    async def _load_robots_txt(self, base_url: str):
        """
        Load and parse robots.txt
        
        Args:
            base_url:  Website base URL
        """
        parsed = urlparse(base_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        
        # Cache'de varsa atla
        if parsed.netloc in self.robots_cache:
            return
        
        try:
            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(robots_url) as response:
                    if response.status == 200:
                        text = await response.text()
                        disallowed = self._parse_robots_txt(text)
                        self.robots_cache[parsed.netloc] = disallowed
                        logger.info(f"Loaded robots.txt:  {robots_url} ({len(disallowed)} rules)")
                    else:
                        self.robots_cache[parsed.netloc] = []
        except Exception as e:
            logger.warning(f"Failed to load robots. txt: {e}")
            self.robots_cache[parsed. netloc] = []
    
    def _parse_robots_txt(self, content: str) -> List[str]:
        """
        Parse robots.txt content
        
        Args:
            content: robots.txt file content
            
        Returns: 
            List of disallowed paths
        """
        disallowed = []
        user_agent_match = False
        
        for line in content.split('\n'):
            line = line.strip()
            
            if line.lower().startswith('user-agent:'):
                agent = line.split(':', 1)[1].strip()
                user_agent_match = (agent == '*' or agent.lower() in self.user_agent. lower())
            
            elif user_agent_match and line.lower().startswith('disallow:'):
                path = line.split(':', 1)[1].strip()
                if path: 
                    disallowed.append(path)
        
        return disallowed
    
    def _is_allowed_by_robots(self, url: str) -> bool:
        """
        Check if URL is allowed by robots.txt
        
        Args:
            url: URL to check
            
        Returns:
            True if allowed
        """
        parsed = urlparse(url)
        disallowed = self.robots_cache.get(parsed.netloc, [])
        
        for path in disallowed:
            if parsed.path.startswith(path):
                return False
        
        return True