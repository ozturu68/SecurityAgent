import nmap
import logging
import socket
from datetime import datetime

# Logger'ı yapılandır
logger = logging.getLogger(__name__)

class NetworkScanner:
    def __init__(self, target, mode="quick"):
        self.target = target
        self.mode = mode
        self.nm = nmap.PortScanner()
        
    def _resolve_ip(self, target):
        """Domain girildiyse IP'ye çevirir."""
        try:
            ip = socket.gethostbyname(target)
            logger.debug(f"Domain çözüldü: {target} -> {ip}")
            return ip
        except socket.gaierror:
            logger.error(f"IP çözülemedi: {target}")
            return None

    def _get_scan_arguments(self):
        """Seçilen moda göre Nmap argümanlarını belirler."""
        if self.mode == "quick":
            # Hızlı tarama: En popüler 100 port, zamanlama T4
            return "-F -T4 --open"
        elif self.mode == "full":
            # Detaylı tarama: Versiyon tespiti (-sV), Script taraması (-sC)
            return "-sV -sC -T4 --open"
        elif self.mode == "stealth":
            # Gizli tarama: SYN Scan (-sS), yavaş zamanlama (T2)
            # Not: SYN Scan genellikle root yetkisi gerektirir (sudo).
            return "-sS -T2 --open"
        else:
            return "-F -T4"

    def run(self):
        """Taramayı başlatır ve yapılandırılmış veri döner."""
        ip_target = self._resolve_ip(self.target)
        if not ip_target:
            return None

        arguments = self._get_scan_arguments()
        logger.info(f"Nmap taraması başlatılıyor: {ip_target} | Argümanlar: {arguments}")
        print(f"    └── Nmap çalışıyor... (Bu işlem hedef büyüklüğüne göre zaman alabilir)")

        try:
            # Taramayı gerçekleştir
            self.nm.scan(hosts=ip_target, arguments=arguments)
            
            # Sonuçları işle
            scan_data = {
                "target_input": self.target,
                "target_ip": ip_target,
                "scan_time": datetime.now().isoformat(),
                "scan_mode": self.mode,
                "status": "down",
                "open_ports": [],
                "services": {},
                "os_match": "Unknown"
            }

            if ip_target in self.nm.all_hosts():
                host_data = self.nm[ip_target]
                scan_data["status"] = host_data.state()
                
                # Protokolleri (tcp/udp) kontrol et
                for proto in host_data.all_protocols():
                    ports = host_data[proto].keys()
                    for port in sorted(ports):
                        service_info = host_data[proto][port]
                        scan_data["open_ports"].append(port)
                        
                        # Servis detaylarını al (product + version)
                        service_name = service_info.get('name', 'unknown')
                        product = service_info.get('product', '')
                        version = service_info.get('version', '')
                        full_service_name = f"{product} {version}".strip() or service_name
                        
                        scan_data["services"][port] = full_service_name

                # OS Tahmini (Eğer -O veya -sC kullanıldıysa ve root ise gelebilir)
                # python-nmap bazen osmatch'i farklı döndürebilir, basit kontrol:
                if 'osmatch' in host_data and host_data['osmatch']:
                    scan_data["os_match"] = host_data['osmatch'][0]['name']

            logger.info(f"Tarama tamamlandı. {len(scan_data['open_ports'])} açık port bulundu.")
            return scan_data

        except Exception as e:
            logger.error(f"Tarama sırasında hata oluştu: {str(e)}")
            return None