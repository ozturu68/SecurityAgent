import logging
import json
from core.llm_engine import LLMAgent
from core.parser import DualStreamParser

logger = logging.getLogger(__name__)

class VulnerabilityAnalyzer:
    def __init__(self, scan_data, model_name=None):
        """
        Args:
            scan_data:  Tarama verileri
            model_name:  Kullanılacak AI model (None ise default)
        """
        self. scan_data = scan_data
        self.llm = LLMAgent(model_name=model_name) if model_name else LLMAgent()

    def analyze_scan_data(self, scan_data):
        """
        Wrapper method for LLMAgent.query() to match old API
        
        Args:
            scan_data: Scan data to analyze
            
        Returns: 
            LLM response string
        """
        # Tarama verisini prompt'a çevir
        prompt = f"""
Aşağıdaki güvenlik taraması sonuçlarını analiz et ve güvenlik açıklarını tespit et:

{json.dumps(scan_data, indent=2)}

Lütfen yanıtını JSON formatında ver: 
{{
    "summary": "Özet açıklama",
    "vulnerabilities":  [
        {{
            "title": "Güvenlik açığı başlığı",
            "severity": "critical/high/medium/low",
            "description": "Detaylı açıklama"
        }}
    ]
}}
"""
        return self.llm.query(prompt)

    def analyze(self):
        logger.info("Analiz başlatıldı.")
        
        raw_response = self.analyze_scan_data(self.scan_data)
        
        if not raw_response:
            logger. error("AI yanıt vermedi")
            return []

        parsed_data = DualStreamParser.parse_response(raw_response)
        
        if "summary" in parsed_data:
            logger. info(f"Özet: {parsed_data['summary']}")

        vulnerabilities = parsed_data.get("vulnerabilities", [])
        
        if not vulnerabilities:
            logger.warning("Hiç güvenlik açığı bulunamadı (Model cevap vermemiş olabilir)")
        else:
            logger.info(f"{len(vulnerabilities)} güvenlik açığı tespit edildi")
        
        return vulnerabilities