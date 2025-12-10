import sys
import os
import subprocess
import time
import argparse
import logging
import shutil

# --- BÖLÜM 1: OTOMATİK KURULUM VE ORTAM YÖNETİMİ ---
def check_system_deps():
    """Sistemde kritik araçların kurulu olup olmadığını denetler."""
    missing = []
    if not shutil.which("nmap"):
        missing.append("nmap")
    
    # Not: Ollama kontrolünü AI Manager içinde yapıyoruz, burada zorunlu değil
    # ama kullanıcıya baştan söylemek iyidir.
    if not shutil.which("ollama"):
        missing.append("ollama")

    if missing:
        print("\n [!] KRİTİK EKSİKLER VAR:")
        for tool in missing:
            print(f"     - {tool} bulunamadı.")
        print("\n [i] Lütfen bunları yükleyip tekrar deneyin.")
        sys.exit(1)

def ensure_environment():
    """Sanal ortamı ve root yetkisini ayarlar."""
    check_system_deps()
    venv_path = os.path.join(os.getcwd(), "venv")
    
    # 1. Sanal Ortam
    if not (hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)):
        python_executable = os.path.join(venv_path, "Scripts", "python.exe") if sys.platform == "win32" else os.path.join(venv_path, "bin", "python3")
        
        if not os.path.exists(python_executable):
            print(" [i] Kurulum yapılıyor (İlk çalıştırma)...")
            subprocess.check_call([sys.executable, "-m", "venv", "venv"])
            subprocess.check_call([python_executable, "-m", "pip", "install", "-r", "requirements.txt"])

        os.execv(python_executable, [python_executable] + sys.argv)

    # 2. Root Yetkisi
    if os.geteuid() != 0:
        print(" [*] Tam otomasyon için Root şifresi gerekiyor...")
        try:
            subprocess.check_call(['sudo', sys.executable] + sys.argv)
            sys.exit(0)
        except Exception as e:
            sys.exit(1)

ensure_environment()

# --- BÖLÜM 2: ANA PROGRAM ---
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    
    from config import MODEL_NAME
    from modules.scanner import NetworkScanner
    from modules.recon import ReconScanner
    from modules.analyzer import VulnerabilityAnalyzer
    from modules.reporter import ReportGenerator
    from utils.logger import setup_logger
    from utils.ai_manager import AIManager # YENİ EKLENTİ
except ImportError as e:
    print(f"Kritik Hata: {e}")
    sys.exit(1)

BANNER = f"""
{Fore.CYAN}
   ______      __               _____           
  / ____/_  __/ /_  ___  _____ / ___/___  c   
 / /   / / / / __ \/ _ \/ ___/ \__ \/ _ \/ ___/ 
/ /___/ /_/ / /_/ /  __/ /    ___/ /  __/ /__   
\____/\__, /_.___/\___/_/    /____/\___/\___/   
{Fore.YELLOW}  >> CyberSec-Agent Auto-Pilot << {Style.RESET_ALL}
"""

def parse_arguments():
    parser = argparse.ArgumentParser(description="Otomatize Siber Güvenlik Analiz Ajanı")
    parser.add_argument("-t", "--target", required=True, help="Hedef IP veya Domain")
    parser.add_argument("-m", "--mode", choices=["quick", "full", "stealth"], default="quick", help="Tarama Modu")
    parser.add_argument("-o", "--output", help="Rapor adı")
    parser.add_argument("--verbose", action="store_true", help="Detaylı log")
    return parser.parse_args()

def main():
    print(BANNER)
    args = parse_arguments()
    logger = setup_logger(logging.DEBUG if args.verbose else logging.INFO)
    
    # --- AI HAZIRLIĞI ---
    # Tarama sürerken arka planda AI hazır olsun diye en başta başlatıyoruz.
    ai_manager = AIManager(MODEL_NAME)
    ai_manager.start_engine()
    # Model kontrolünü burada yapalım ki analiz sırasında beklemeyelim
    ai_manager.check_model()

    try:
        start_time = time.time()
        
        # 1. RECON
        print(f"\n{Fore.BLUE}[*] 1. Aşama: Hedef Çözümleme...{Style.RESET_ALL}")
        recon = ReconScanner(target=args.target)
        recon_results = recon.run()
        
        target_ip = recon_results.get("ip")
        if not target_ip:
            print(f"{Fore.RED}[!] Hedef IP bulunamadı.{Style.RESET_ALL}")
            return

        # 2. SCAN
        print(f"\n{Fore.BLUE}[*] 2. Aşama: Ağ Taraması ({args.mode})...{Style.RESET_ALL}")
        scanner = NetworkScanner(target=target_ip, mode=args.mode)
        scan_results = scanner.run()
        
        if not scan_results:
             print(f"{Fore.RED}[!] Tarama sonuç vermedi.{Style.RESET_ALL}")
             return

        full_scan_data = {**recon_results, **scan_results}

        # 3. ANALYZE
        print(f"\n{Fore.BLUE}[*] 3. Aşama: AI Analizi...{Style.RESET_ALL}")
        analyzer = VulnerabilityAnalyzer(scan_data=full_scan_data)
        vulnerabilities = analyzer.analyze()
        
        # 4. REPORT
        print(f"\n{Fore.BLUE}[*] 4. Aşama: Raporlama...{Style.RESET_ALL}")
        reporter = ReportGenerator(full_scan_data, vulnerabilities)
        output_name = args.output if args.output else f"report_{int(time.time())}"
        out_path = reporter.export_json(filename=output_name)
        
        print(f"\n{Fore.GREEN}[OK] İşlem Tamamlandı.{Style.RESET_ALL}")
        print(f"    Rapor: {out_path}")

    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Kullanıcı iptali.{Style.RESET_ALL}")
    except Exception as e:
        logger.error(f"Beklenmeyen Hata: {e}", exc_info=True)
        print(f"\n{Fore.RED}[!] Bir hata oluştu. Log dosyasına bakınız.{Style.RESET_ALL}")
    finally:
        # Program bittiğinde, eğer biz başlattıysak AI motorunu temizleyelim
        # Not: Sürekli açık kalmasını istiyorsanız bu satırı yorum satırı yapın.
        ai_manager.stop_engine()

if __name__ == "__main__":
    main()