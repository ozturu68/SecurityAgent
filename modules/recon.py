import socket
import whois
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class ReconScanner:
    def __init__(self, target):
        self.target = target
        self.domain = self._extract_domain(target)
        self.ip = None

    def _extract_domain(self, target):
        if target.startswith("http"):
            return urlparse(target).netloc
        return target

    def run(self):
        print(f"    └── Domain/IP Çözümleniyor...")
        try:
            self.ip = socket.gethostbyname(self.domain)
        except:
            return {}
            
        try:
            w = whois.whois(self.domain)
            w_info = {"registrar": w.registrar, "emails": w.emails}
        except:
            w_info = {}

        return {"target": self.domain, "ip": self.ip, "whois": w_info}