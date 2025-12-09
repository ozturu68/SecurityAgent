cat <<EOF > modules/analyzer.py
import logging
from core.llm_engine import LLMEngine
from core.parser import DualStreamParser

logger = logging.getLogger(__name__)

class VulnerabilityAnalyzer:
    def __init__(self, scan_data):
        self.scan_data = scan_data
        self.llm = LLMEngine()

    def analyze(self):
        logger.info("Analiz işlemi başlatıldı (AI Destekli).")
        
        raw_response = self.llm.analyze_scan_data(self.scan_data)
        
        if not raw_response:
            return []

        parsed_data = DualStreamParser.parse_response(raw_response)
        vulnerabilities = parsed_data.get("vulnerabilities", [])
        
        if "summary" in parsed_data:
            logger.info(f"AI Özeti: {parsed_data.get('summary')}")

        logger.info(f"Analiz bitti. {len(vulnerabilities)} bulgu saptandı.")
        return vulnerabilities
EOF