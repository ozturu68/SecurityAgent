import sys
import os
import subprocess
import time
import argparse
import logging

# --- BÖLÜM 1: OTOMATİK KURULUM VE ORTAM YÖNETİMİ ---
# Bu kısım standart kütüphanelerle çalışır, dış bağımlılık istemez.

def is_venv():
    """Programın sanal ortamda çalışıp çalışmadığını kontrol eder."""
    return (hasattr(sys, 'real_prefix') or
            (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix))

def ensure_environment():
    """Sanal ortamı ve root yetkisini otomatik ayarlar."""
    venv_path = os.path.join(os.getcwd(), "venv")
    
    # 1. Sanal Ortam Kontrolü ve Kurulumu
    if not is_venv():
        print(" [i] Sanal ortam kontrol ediliyor...")
        
        # Windows/Linux python yolu ayrımı
        if sys.platform == "win32":
            python_executable = os.path.join(venv_path, "Scripts", "python.exe")
        else:
            python_executable = os.path.join(venv_path, "bin", "python3")

        # Venv yoksa oluştur
        if not os.path.exists(python_executable):
            print(" [i] Sanal ortam bulunamadı. Oluşturuluyor... (Bu işlem bir kez yapılır)")
            subprocess.check_call([sys.executable, "-m", "venv", "venv"])
            
            print(" [i] Gerekli kütüphaneler yükleniyor...")
            subprocess.check_call([python_executable, "-m", "pip", "install", "-r", "requirements.txt"])
            print(" [OK] Kurulum tamamlandı.")

        # Kendini venv içindeki python ile yeniden başlat
        print(" [i] Sanal ortama geçiş yapılıyor...")
        os.execv(python_executable, [python_executable] + sys.argv)

    # 2. Root (Sudo) Yetkisi Kontrolü
    # Buraya gelindiyse artık venv içindeyizdir. Şimdi yetkiyi yükseltelim.
    if os.geteuid() != 0:
        print(" [*] Nmap için Root yetkisi gerekiyor. Lütfen şifrenizi girin...")
        try:
            # Mevcut python yorumlayıcısını (venv içindeki) sudo ile çağır
            subprocess.check_call(['sudo', sys.executable] + sys.argv)
            sys.exit(0) # Alt işlem bitince ana işlemi kapat
        except Exception as e:
            print(f" [!] Yetki alma başarısız: {e}")
            sys.exit(1)

# Ortam kontrolünü hemen başlat (Daha import yapmadan)
ensure_environment()

# --- BÖLÜM 2: PROJE MODÜLLERİ ---
# Buraya gelindiyse; Venv içindeyiz, kütüphaneler yüklü ve Root yetkimiz var.
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    
    from modules.scanner import NetworkScanner
    from modules.recon import ReconScanner
    from modules.analyzer import VulnerabilityAnalyzer
    from modules.reporter import ReportGenerator
    from utils.logger import setup_logger
except ImportError as e:
    print(f"KRİTİK HATA: Modüller yüklenemedi: {e}")
    print("Lütfen 'pip install -r requirements.txt' komutunu elle deneyin.")
    sys.exit(1)

BANNER = f"""
{Fore.CYAN}
   ______      __               _____           
  / ____/_  __/ /_  ___  _____ / ___/___  c   
 / /   / / / / __ \/ _ \/ ___/ \__ \/ _ \/ ___/ 
/ /___/ /_/ / /_/ /  __/ /    ___/ /  __/ /__   
\____/\__, /_.___/\___/_/    /____/\___/\___/   
     /____/                                     
{Fore.YELLOW}  >> CyberSec-Agent v1.2 (Auto-Pilot) << {Style.RESET_ALL}
"""

def parse_arguments():
    parser = argparse.ArgumentParser(description="Otomatize Siber Güvenlik Analiz Ajanı")
    parser.add_argument("-t", "--target", required=True, help="Hedef IP, Domain veya IP Aralığı")
    parser.add_argument("-m", "--mode", choices=["quick", "full", "stealth"], default="quick", help="Tarama Modu")
    parser.add_argument("-o", "--output", help="Rapor dosya adı")
    parser.add_argument("--verbose", action="store_true", help="Detaylı log kaydı")
    return parser.parse_args()

def main():
    print(BANNER)
    args = parse_arguments()
    
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logger = setup_logger(log_level)
    logger.info(f"Oturum Başladı. Hedef: {args.target}")

    start_time = time.time()

    try:
        # 1. RECON
        print(f"\n{Fore.BLUE}[*] 1. Aşama: Keşif (Recon)...{Style.RESET_ALL}")
        recon = ReconScanner(target=args.target)
        recon_results = recon.run()
        
        target_ip = recon_results.get("ip")
        if not target_ip:
            logger.error("Hedef IP bulunamadı.")
            print(f"{Fore.RED}[!] Hedef çözülemedi.{Style.RESET_ALL}")
            return

        print(f"{Fore.GREEN}[+] Hedef IP: {target_ip}{Style.RESET_ALL}")

        # 2. SCAN
        print(f"\n{Fore.BLUE}[*] 2. Aşama: Port Taraması...{Style.RESET_ALL}")
        scanner = NetworkScanner(target=target_ip, mode=args.mode)
        scan_results = scanner.run()
        
        full_scan_data = {**recon_results, **(scan_results or {})}

        # 3. ANALYZE
        print(f"\n{Fore.BLUE}[*] 3. Aşama: Analiz...{Style.RESET_ALL}")
        analyzer = VulnerabilityAnalyzer(scan_data=full_scan_data)
        vulnerabilities = analyzer.analyze()
        
        print(f"{Fore.GREEN}[+] {len(vulnerabilities)} bulgu.{Style.RESET_ALL}")

        # 4. REPORT
        print(f"\n{Fore.BLUE}[*] 4. Aşama: Raporlama...{Style.RESET_ALL}")
        reporter = ReportGenerator(full_scan_data, vulnerabilities)
        output_name = args.output if args.output else f"scan_report_{int(time.time())}"
        reporter.export_json(filename=output_name)
        
        print(f"\n{Fore.GREEN}[OK] Tamamlandı: outputs/{output_name}.json{Style.RESET_ALL}")

    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] İptal edildi.{Style.RESET_ALL}")
    except Exception as e:
        logger.error(f"Hata: {e}", exc_info=True)
        print(f"\n{Fore.RED}[!] Hata oluştu: {e}{Style.RESET_ALL}")
    finally:
        print(f"{Fore.YELLOW}Süre: {time.time() - start_time:.2f} sn{Style.RESET_ALL}")

if __name__ == "__main__":
    main()