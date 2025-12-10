import nmap
import logging
import socket
import sys
from datetime import datetime

logger = logging.getLogger(__name__)

class NetworkScanner:
    def __init__(self, target, mode="quick"):
        self.target = target
        self.mode = mode
        try:
            self.nm = nmap.PortScanner()
        except Exception as e:
            logger.critical(f"Nmap başlatılamadı: {e}")
            print(" [!] Hata: Nmap sistemde bulunamadı veya çalıştırılamadı.")
            sys.exit(1)
        
    def _resolve_ip(self, target):
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            return None

    def _get_scan_arguments(self):
        common = "--open --reason"
        if self.mode == "quick": return f"-F -T4 {common}"
        if self.mode == "full": return f"-sV -sC -T4 {common}"
        if self.mode == "stealth": return f"-sS -T2 {common}"
        return f"-F {common}"

    def run(self):
        ip_target = self._resolve_ip(self.target)
        if not ip_target:
            return None

        args = self._get_scan_arguments()
        logger.info(f"Tarama: {ip_target} | Args: {args}")
        print(f"    └── Nmap çalışıyor... ({self.mode})")

        try:
            self.nm.scan(hosts=ip_target, arguments=args)
            
            scan_data = {
                "target": self.target,
                "ip": ip_target,
                "time": datetime.now().isoformat(),
                "open_ports": [],
                "services": {}
            }

            if ip_target in self.nm.all_hosts():
                host = self.nm[ip_target]
                for proto in host.all_protocols():
                    for port in sorted(host[proto].keys()):
                        svc = host[proto][port]
                        scan_data["open_ports"].append(port)
                        scan_data["services"][port] = f"{svc.get('product','')} {svc.get('version','')}".strip() or svc.get('name')

            return scan_data
        except Exception as e:
            logger.error(f"Tarama hatası: {e}")
            return None