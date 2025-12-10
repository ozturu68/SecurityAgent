import ollama
import logging
import sys
from config import MODEL_NAME, SYSTEM_PROMPT

# Renkler yoksa hata vermesin
try:
    from colorama import Fore, Style
except ImportError:
    class Fore: CYAN=GREEN=RED=LIGHTBLACK_EX=""; 
    class Style: RESET_ALL=""

logger = logging.getLogger(__name__)

class LLMEngine:
    def __init__(self):
        self.model = MODEL_NAME

    def analyze_scan_data(self, scan_data):
        logger.info(f"LLM Analizi Başlıyor... Model: {self.model}")
        print(f"\n{Fore.CYAN}[🧠] AI Düşünüyor ({self.model})...{Style.RESET_ALL}")

        user_message = f"ANALİZ EDİLECEK VERİ:\n{str(scan_data)}"

        try:
            stream = ollama.chat(
                model=self.model,
                messages=[
                    {'role': 'system', 'content': SYSTEM_PROMPT},
                    {'role': 'user', 'content': user_message},
                ],
                stream=True
            )

            full_response = ""
            is_thinking = False
            
            for chunk in stream:
                content = chunk['message']['content']
                full_response += content
                
                # <think> bloklarını renklendirme
                if "<think>" in content:
                    is_thinking = True
                    sys.stdout.write(Fore.LIGHTBLACK_EX)
                
                if "</think>" in content:
                    is_thinking = False
                    sys.stdout.write(content.replace("</think>", "")) 
                    sys.stdout.write(Style.RESET_ALL)
                    continue

                if is_thinking:
                    sys.stdout.write(content)
                    sys.stdout.flush()
            
            print(f"\n{Fore.GREEN}[✓] Analiz Tamamlandı.{Style.RESET_ALL}")
            
            # DEBUG: Ham yanıtı loglayalım
            logger.debug(f"AI Ham Yanıt:\n{full_response}")
            
            # DEBUG: Yanıtı dosyaya kaydedelim (sorun giderme için)
            try:
                with open('logs/last_ai_response.txt', 'w', encoding='utf-8') as f:
                    f.write(full_response)
                print(f"{Fore.YELLOW}[i] AI yanıtı kaydedildi: logs/last_ai_response.txt{Style.RESET_ALL}")
            except:
                pass
            
            return full_response

        except Exception as e:
            logger.error(f"LLM Hatası: {e}")
            print(f"{Fore.RED}[!] AI Hatası: {e}{Style.RESET_ALL}")
            return None