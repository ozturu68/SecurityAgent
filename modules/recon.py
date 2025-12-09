import socket
import whois
import logging
from urllib.parse import urlparse

# Logger yapılandırması
logger = logging.getLogger(__name__)

class ReconScanner:
    def __init__(self, target):
        self.target = target
        self.domain = self._extract_domain(target)
        self.ip = None

    def _extract_domain(self, target):
        """URL veya IP'den temiz domain/host adını ayıklar."""
        if target.startswith("http"):
            return urlparse(target).netloc
        return target

    def get_ip(self):
        """Domain'i IP adresine çevirir."""
        try:
            self.ip = socket.gethostbyname(self.domain)
            logger.info(f"IP Çözüldü: {self.domain} -> {self.ip}")
            return self.ip
        except socket.gaierror:
            logger.error(f"IP çözülemedi: {self.domain}")
            return None

    def get_whois_info(self):
        """Whois bilgilerini çeker."""
        logger.info(f"Whois sorgusu yapılıyor: {self.domain}")
        try:
            w = whois.whois(self.domain)
            # Tarih nesnelerini string'e çevir (JSON hatası vermemesi için)
            return {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "emails": w.emails
            }
        except Exception as e:
            logger.warning(f"Whois sorgusu başarısız: {e}")
            return {"error": "Whois data not found"}

    def run(self):
        """Tüm keşif işlemlerini çalıştırır."""
        print(f"    └── Recon (Keşif) modülü çalışıyor...")
        
        ip = self.get_ip()
        whois_data = self.get_whois_info() if ip else {}

        recon_data = {
            "target": self.domain,
            "ip": ip,
            "whois": whois_data
        }
        
        return recon_data