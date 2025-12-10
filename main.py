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

    # 2. Root Yetkisi (SADECE STEALTH MOD İÇİN)
    if "--mode" in sys.argv or "-m" in sys.argv:
        try:
            mode_idx = sys.argv.index("-m") if "-m" in sys.argv else sys.argv.index("--mode")
            mode = sys.argv[mode_idx + 1]
        except (ValueError, IndexError):
            mode = "quick"
    else:
        mode = "quick"
    
    if mode == "stealth" and os.geteuid() != 0:
        print(f" [!] '{mode}' modu için Root yetkisi gerekiyor (SYN Scan).")
        response = input(" [?] Sudo ile devam edilsin mi? (e/h): ").strip().lower()
        
        if response == 'e':
            try:
                subprocess.check_call(['sudo', sys.executable] + sys.argv)
                sys.exit(0)
            except Exception as e:
                print(f" [!] Sudo başarısız: {e}")
                sys.exit(1)
        else:
            print(" [i] Stealth modu iptal edildi. Lütfen 'quick' veya 'full' kullanın.")
            sys.exit(0)

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
    from utils.ai_manager import AIManager
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
    parser = argparse.ArgumentParser(
        description="Otomatize Siber Güvenlik Analiz Ajanı",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnekler:
  %(prog)s -t scanme.nmap.org -m quick
  %(prog)s -t 192.168.1.1 -m full --model 7b
  %(prog)s -t example.com -m stealth --verbose
        """
    )
    parser.add_argument("-t", "--target", required=True, help="Hedef IP veya Domain")
    parser.add_argument("-m", "--mode", choices=["quick", "full", "stealth"], 
                       default="quick", help="Tarama Modu (default: quick)")
    parser.add_argument("-o", "--output", help="Rapor adı (uzantısız)")
    parser.add_argument("--model", choices=["1.5b", "7b", "8b"], 
                       default="7b", help="AI Model boyutu (default: 7b)")
    parser.add_argument("--verbose", action="store_true", help="Detaylı log")
    return parser.parse_args()

def get_model_name(size):
    """Model boyutuna göre tam model adını döndür"""
    models = {
        "1.5b": "deepseek-r1:1.5b",
        "7b": "deepseek-r1:7b",
        "8b": "deepseek-r1:8b"
    }
    return models.get(size, "deepseek-r1:7b")

def main():
    print(BANNER)
    args = parse_arguments()
    logger = setup_logger(logging.DEBUG if args.verbose else logging.INFO)
    
    # Model seçimi
    selected_model = get_model_name(args.model)
    print(f"{Fore.YELLOW}[i] Seçili Model: {selected_model}{Style.RESET_ALL}")
    
    # --- AI HAZIRLIĞI ---
    ai_manager = AIManager(selected_model)
    ai_manager.start_engine()
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

        # 3. ANALYZE (Model değiştirme için özel config)
        print(f"\n{Fore.BLUE}[*] 3. Aşama: AI Analizi...{Style.RESET_ALL}")
        
        # Model'i geçici olarak değiştir
        import config
        original_model = config.MODEL_NAME
        config.MODEL_NAME = selected_model
        
        analyzer = VulnerabilityAnalyzer(scan_data=full_scan_data)
        vulnerabilities = analyzer.analyze()
        
        config.MODEL_NAME = original_model  # Geri al
        
        # 4. REPORT
        print(f"\n{Fore.BLUE}[*] 4. Aşama: Raporlama...{Style.RESET_ALL}")
        reporter = ReportGenerator(full_scan_data, vulnerabilities)
        output_name = args.output if args.output else f"report_{int(time.time())}"
        out_path = reporter.export_json(filename=output_name)
        
        elapsed = time.time() - start_time
        print(f"\n{Fore.GREEN}[OK] İşlem Tamamlandı ({elapsed:.1f}s).{Style.RESET_ALL}")
        print(f"    Rapor: {out_path}")
        print(f"    Bulgu Sayısı: {len(vulnerabilities)}")

    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Kullanıcı iptali.{Style.RESET_ALL}")
    except Exception as e:
        logger.error(f"Beklenmeyen Hata: {e}", exc_info=True)
        print(f"\n{Fore.RED}[!] Bir hata oluştu. Log dosyasına bakınız.{Style.RESET_ALL}")
    finally:
        ai_manager.stop_engine()

if __name__ == "__main__":
    main()