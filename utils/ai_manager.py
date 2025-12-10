import subprocess
import time
import socket
import sys
import shutil
import logging
import ollama
from colorama import Fore, Style

logger = logging.getLogger(__name__)

class AIManager:
    def __init__(self, model_name):
        self.model_name = model_name
        self.server_process = None

    def _is_port_open(self, port=11434):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('localhost', port)) == 0

    def _check_installed(self):
        if not shutil.which("ollama"):
            print(f"{Fore.RED}[!] KRİTİK: 'ollama' yazılımı bulunamadı!{Style.RESET_ALL}")
            print("    Lütfen yükleyin: https://ollama.com/download")
            sys.exit(1)

    def start_engine(self):
        self._check_installed()
        
        if self._is_port_open():
            logger.info("Ollama servisi zaten çalışıyor.")
            return True

        print(f"{Fore.YELLOW}[*] AI Motoru başlatılıyor...{Style.RESET_ALL}")
        try:
            self.server_process = subprocess.Popen(
                ["ollama", "serve"], 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL
            )
            
            for _ in range(20):
                if self._is_port_open():
                    print(f"{Fore.GREEN}[✓] Motor aktif.{Style.RESET_ALL}")
                    return True
                time.sleep(1)
            
            return False
        except Exception as e:
            logger.error(f"AI başlatma hatası: {e}")
            return False

    def check_model(self):
        print(f"{Fore.CYAN}[*] Model kontrolü: {self.model_name}{Style.RESET_ALL}")
        try:
            models_info = ollama.list()
            installed_models = [m['name'] for m in models_info.get('models', [])]
            
            if any(self.model_name in m for m in installed_models):
                return

            print(f"{Fore.YELLOW}[!] Model indiriliyor...{Style.RESET_ALL}")
            ollama.pull(self.model_name)
            print(f"\n{Fore.GREEN}[✓] İndirme tamamlandı.{Style.RESET_ALL}")

        except Exception as e:
            logger.error(f"Model hatası: {e}")
            sys.exit(1)

    def stop_engine(self):
        if self.server_process:
            self.server_process.terminate()