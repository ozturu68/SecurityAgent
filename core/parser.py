import json
import re
import logging

logger = logging.getLogger(__name__)

class DualStreamParser:
    @staticmethod
    def parse_response(raw_response):
        if not raw_response:
            return {}

        # Düşünce bloklarını ve Markdown etiketlerini temizle
        clean_text = re.sub(r'<think>.*?</think>', '', raw_response, flags=re.DOTALL)
        clean_text = clean_text.replace('```json', '').replace('```', '').strip()

        try:
            start_idx = clean_text.find('{')
            end_idx = clean_text.rfind('}') + 1
            
            if start_idx == -1 or end_idx == 0:
                return {}
                
            json_str = clean_text[start_idx:end_idx]
            return json.loads(json_str)

        except Exception as e:
            logger.error(f"JSON Ayrıştırma Hatası: {e}")
            return {}