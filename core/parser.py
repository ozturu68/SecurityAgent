import json
import re
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class DualStreamParser:
    @staticmethod
    def extract_json(text: str) -> Optional[str]:
        """JSON bloğunu çoklu yöntemle bul"""
        
        # Yöntem 1: Markdown kod bloğu
        markdown_match = re.search(r'```json\s*(.*?)\s*```', text, re.DOTALL)
        if markdown_match:
            candidate = markdown_match.group(1).strip()
            if candidate.startswith('{') and candidate.endswith('}'):
                return candidate
        
        # Yöntem 2: Markdown olmadan kod bloğu
        code_match = re.search(r'```\s*(.*?)\s*```', text, re.DOTALL)
        if code_match:
            candidate = code_match.group(1).strip()
            if candidate.startswith('{') and candidate.endswith('}'):
                return candidate
        
        # Yöntem 3: Balanced brace extraction (en güçlü yöntem)
        return DualStreamParser._extract_balanced_json(text)
    
    @staticmethod
    def _extract_balanced_json(text: str) -> Optional[str]:
        """Dengeli parantez bulma (nested JSON için)"""
        first_brace = text.find('{')
        if first_brace == -1:
            return None
        
        brace_count = 0
        in_string = False
        escape_next = False
        
        for i in range(first_brace, len(text)):
            char = text[i]
            
            # String içinde miyiz kontrolü
            if char == '"' and not escape_next:
                in_string = not in_string
            
            # Escape karakteri
            if char == '\\' and not escape_next:
                escape_next = True
                continue
            else:
                escape_next = False
            
            # String dışında parantez sayma
            if not in_string:
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        return text[first_brace:i+1]
        
        return None

    @staticmethod
    def parse_response(raw_response: str) -> Dict:
        """Süper güçlendirilmiş ayrıştırma"""
        if not raw_response:
            logger.warning("Boş AI yanıtı")
            return DualStreamParser._empty_result("Yanıt alınamadı")

        # 1. Düşünce bloklarını temizle
        clean = re.sub(r'<think>.*?</think>', '', raw_response, flags=re.DOTALL | re.IGNORECASE)
        clean = clean.strip()
        
        # 2. JSON'u bul
        json_str = DualStreamParser.extract_json(clean)
        if not json_str:
            logger.warning("JSON bulunamadı, ham yanıt loglandı")
            logger.debug(f"Temizlenmiş metin: {clean[:500]}")
            return DualStreamParser._empty_result("Format hatası - JSON bulunamadı")

        # 3. Önce düzeltmeden parse dene
        try:
            data = json.loads(json_str)
            return DualStreamParser._validate_schema(data)
        except json.JSONDecodeError as e:
            logger.warning(f"İlk parse başarısız: {e}")
            # 4. Onarma dene
            repaired = DualStreamParser._aggressive_repair(json_str)
            if repaired:
                try:
                    data = json.loads(repaired)
                    logger.info("JSON onarma başarılı!")
                    return DualStreamParser._validate_schema(data)
                except:
                    pass
        
        # 5. Son çare: Manuel extraction
        logger.error("Tüm parse yöntemleri başarısız")
        return DualStreamParser._manual_extraction(clean)

    @staticmethod
    def _aggressive_repair(broken_json: str) -> Optional[str]:
        """Agresif JSON onarma"""
        try:
            # Temel düzeltmeler
            repaired = broken_json
            
            # 1. Tek tırnak -> Çift tırnak
            repaired = repaired.replace("'", '"')
            
            # 2. Trailing comma temizleme
            repaired = re.sub(r',(\s*[}\]])', r'\1', repaired)
            
            # 3. Çift tırnak düzeltmeleri
            repaired = re.sub(r'(\w+):', r'"\1":', repaired)  # Key'leri tırnak içine al
            
            # 4. Eksik virgüller
            repaired = re.sub(r'"\s*\n\s*"', '",\n"', repaired)  # String'ler arası
            repaired = re.sub(r'}\s*{', '},{', repaired)  # Objeler arası
            repaired = re.sub(r']\s*\[', '],[', repaired)  # Array'ler arası
            
            # 5. Newline'ları string içinde temizle
            # (JSON string'lerde \n olmalı, gerçek newline değil)
            repaired = re.sub(r':\s*"([^"]*)\n([^"]*)"', r': "\1\\n\2"', repaired)
            
            return repaired
            
        except Exception as e:
            logger.error(f"Onarma hatası: {e}")
            return None
    
    @staticmethod
    def _manual_extraction(text: str) -> Dict:
        """Son çare: Regex ile değerleri çıkar"""
        result = {
            "summary": "Manuel çıkarım yapıldı",
            "vulnerabilities": [],
            "recommended_actions": []
        }
        
        try:
            # Summary bul
            summary_match = re.search(r'"summary"\s*:\s*"([^"]*)"', text, re.IGNORECASE)
            if summary_match:
                result["summary"] = summary_match.group(1)
            
            # Port numaralarını bul
            port_matches = re.findall(r'"port"\s*:\s*(\d+)', text)
            
            # Her port için basit bir vulnerability oluştur
            for port in set(port_matches):
                result["vulnerabilities"].append({
                    "port": int(port),
                    "service": "Bilinmiyor",
                    "severity": "Medium",
                    "description": f"Port {port} açık (Manuel tespit)"
                })
            
            logger.info(f"Manuel extraction: {len(result['vulnerabilities'])} bulgu")
            
        except Exception as e:
            logger.error(f"Manuel extraction hatası: {e}")
        
        return result

    @staticmethod
    def _validate_schema(data: Dict) -> Dict:
        """Şema doğrulama ve eksikleri doldurma"""
        if not isinstance(data, dict):
            return DualStreamParser._empty_result("Geçersiz veri tipi")
        
        # Zorunlu alanları doldur
        if "vulnerabilities" not in data:
            data["vulnerabilities"] = []
        
        if "summary" not in data:
            data["summary"] = f"{len(data.get('vulnerabilities', []))} bulgu tespit edildi"
        
        if "recommended_actions" not in data:
            data["recommended_actions"] = []
        
        # Vulnerability'leri validate et
        valid_vulns = []
        for vuln in data.get("vulnerabilities", []):
            if isinstance(vuln, dict) and "port" in vuln:
                # Eksik alanları doldur
                if "severity" not in vuln:
                    vuln["severity"] = "Medium"
                if "service" not in vuln:
                    vuln["service"] = "Unknown"
                if "description" not in vuln:
                    vuln["description"] = "Güvenlik riski tespit edildi"
                
                valid_vulns.append(vuln)
        
        data["vulnerabilities"] = valid_vulns
        return data
    
    @staticmethod
    def _empty_result(message: str) -> Dict:
        """Boş ama geçerli sonuç döndür"""
        return {
            "summary": message,
            "vulnerabilities": [],
            "recommended_actions": []
        }