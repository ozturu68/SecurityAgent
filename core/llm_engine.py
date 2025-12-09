import ollama
import logging
import sys
from config import MODEL_NAME, SYSTEM_PROMPT

try:
    from colorama import Fore, Style
except ImportError:
    class Fore:CYAN=GREEN=RED=LIGHTBLACK_EX=""; 
    class Style:RESET_ALL=""

logger = logging.getLogger(__name__)

class LLMEngine:
    def __init__(self):
        self.model = MODEL_NAME

    def analyze_scan_data(self, scan_data):
        logger.info(f"LLM Analizi Başlatılıyor... Model: {self.model}")
        print(f"\n{Fore.CYAN}[🧠] AI Analiz Ediyor ({self.model})...{Style.RESET_ALL}")

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
            return full_response

        except Exception as e:
            logger.error(f"LLM Bağlantı Hatası: {e}")
            print(f"{Fore.RED}[!] Yapay Zeka Hatası: {e}{Style.RESET_ALL}")
            return None
