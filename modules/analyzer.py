import logging
from core.llm_engine import LLMEngine
from core.parser import DualStreamParser

logger = logging.getLogger(__name__)

class VulnerabilityAnalyzer:
    def __init__(self, scan_data, model_name=None):
        """
        Args:
            scan_data: Tarama verileri
            model_name: Kullanılacak AI model (None ise default)
        """
        self.scan_data = scan_data
        self.llm = LLMEngine(model_name=model_name)

    def analyze(self):
        logger.info("Analiz başlatıldı.")
        
        raw_response = self.llm.analyze_scan_data(self.scan_data)
        
        if not raw_response:
            logger.error("AI yanıt vermedi")
            return []

        parsed_data = DualStreamParser.parse_response(raw_response)
        
        if "summary" in parsed_data:
            logger.info(f"Özet: {parsed_data['summary']}")

        vulnerabilities = parsed_data.get("vulnerabilities", [])
        
        if not vulnerabilities:
            logger.warning("Hiç güvenlik açığı bulunamadı (Model cevap vermemiş olabilir)")
        else:
            logger.info(f"{len(vulnerabilities)} güvenlik açığı tespit edildi")
        
        return vulnerabilities