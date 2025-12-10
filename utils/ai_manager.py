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
        """Model varlığını kontrol et ve yoksa indir"""
        print(f"{Fore.CYAN}[*] Model kontrolü: {self.model_name}{Style.RESET_ALL}")
        
        try:
            # Ollama list komutu ile model listesini al
            models_response = ollama.list()
            
            # API yanıtı debug için loglayalım
            logger.debug(f"Ollama list yanıtı: {models_response}")
            
            # Yanıt yapısını kontrol et
            if isinstance(models_response, dict):
                models_list = models_response.get('models', [])
            else:
                models_list = []
            
            # Model adlarını çıkar (farklı yapıları destekle)
            installed_models = []
            for model in models_list:
                if isinstance(model, dict):
                    # Yeni API: {'model': 'name:tag', ...} veya {'name': 'name:tag', ...}
                    model_name = model.get('model') or model.get('name') or model.get('model_name', '')
                    installed_models.append(model_name)
                elif isinstance(model, str):
                    # Eski API: Direkt string listesi
                    installed_models.append(model)
            
            logger.debug(f"Kurulu modeller: {installed_models}")
            
            # Model kontrolü (kısmi eşleşme de kabul et)
            model_exists = any(
                self.model_name in installed_model or installed_model in self.model_name
                for installed_model in installed_models
            )
            
            if model_exists:
                print(f"{Fore.GREEN}[✓] Model mevcut.{Style.RESET_ALL}")
                return True
            
            # Model yoksa indir
            print(f"{Fore.YELLOW}[!] Model indiriliyor: {self.model_name}{Style.RESET_ALL}")
            print(f"    Bu işlem birkaç dakika sürebilir...")
            
            ollama.pull(self.model_name)
            
            print(f"{Fore.GREEN}[✓] İndirme tamamlandı.{Style.RESET_ALL}")
            return True

        except Exception as e:
            logger.error(f"Model kontrolü hatası: {e}", exc_info=True)
            print(f"{Fore.RED}[!] Model kontrolünde hata oluştu.{Style.RESET_ALL}")
            print(f"    Detay: {str(e)}")
            
            # Fallback: Manuel kontrol dene
            print(f"{Fore.YELLOW}[*] Manuel kontrol deneniyor...{Style.RESET_ALL}")
            return self._fallback_check()

    def _fallback_check(self):
        """CLI komutu ile model kontrolü (fallback)"""
        try:
            result = subprocess.run(
                ["ollama", "list"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if self.model_name in result.stdout:
                print(f"{Fore.GREEN}[✓] Model bulundu (CLI).{Style.RESET_ALL}")
                return True
            
            # Model yoksa indir
            print(f"{Fore.YELLOW}[*] Model indiriliyor (CLI)...{Style.RESET_ALL}")
            subprocess.run(
                ["ollama", "pull", self.model_name],
                timeout=600  # 10 dakika timeout
            )
            print(f"{Fore.GREEN}[✓] İndirme tamamlandı.{Style.RESET_ALL}")
            return True
            
        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}[!] İşlem zaman aşımına uğradı.{Style.RESET_ALL}")
            return False
        except Exception as e:
            logger.error(f"Fallback hatası: {e}")
            print(f"{Fore.RED}[!] Model kontrol edilemedi: {e}{Style.RESET_ALL}")
            return False

    def stop_engine(self):
        """Ollama servisini durdur (sadece biz başlattıysak)"""
        if self.server_process:
            try:
                self.server_process.terminate()
                self.server_process.wait(timeout=5)
                logger.info("Ollama servisi durduruldu.")
            except Exception as e:
                logger.warning(f"Servis durdurma hatası: {e}")
                # Force kill
                try:
                    self.server_process.kill()
                except:
                    pass