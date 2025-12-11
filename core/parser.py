import json
import re
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class DualStreamParser:
    @staticmethod
    def extract_json(text: str) -> Optional[str]:
        """Extract JSON from text using multiple methods"""
        # Method 1: Markdown code block
        markdown_match = re.search(r'```json\s*(.*?)\s*```', text, re.DOTALL)
        if markdown_match:
            candidate = markdown_match.group(1).strip()
            if candidate.startswith('{') and candidate.endswith('}'):
                return candidate
        
        # Method 2: Generic code block
        code_match = re.search(r'```\s*(.*?)\s*```', text, re.DOTALL)
        if code_match:
            candidate = code_match.group(1).strip()
            if candidate.startswith('{') and candidate.endswith('}'):
                return candidate
        
        # Method 3: Balanced brace extraction
        return DualStreamParser._extract_balanced_json(text)
    
    @staticmethod
    def _extract_balanced_json(text: str) -> Optional[str]:
        """Find balanced JSON with proper brace counting"""
        first_brace = text.find('{')
        if first_brace == -1:
            return None
        
        brace_count = 0
        in_string = False
        escape_next = False
        
        for i in range(first_brace, len(text)):
            char = text[i]
            
            if char == '"' and not escape_next:
                in_string = not in_string
            
            if char == '\\' and not escape_next:
                escape_next = True
                continue
            else:
                escape_next = False
            
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
        """Parse and validate AI response"""
        if not raw_response:
            logger.warning("Empty AI response")
            return DualStreamParser._empty_result("No response received")

        # Remove <think> blocks
        clean = re.sub(r'<think>.*?</think>', '', raw_response, flags=re.DOTALL | re.IGNORECASE)
        clean = clean.strip()
        
        # Extract JSON
        json_str = DualStreamParser.extract_json(clean)
        if not json_str:
            logger.warning("No JSON found in response")
            return DualStreamParser._empty_result("JSON not found")

        # Parse
        try:
            data = json.loads(json_str)
            return DualStreamParser._validate_schema(data)
        except json.JSONDecodeError as e:
            logger.warning(f"JSON parse failed: {e}")
            repaired = DualStreamParser._aggressive_repair(json_str)
            if repaired:
                try:
                    data = json.loads(repaired)
                    logger.info("JSON repair successful")
                    return DualStreamParser._validate_schema(data)
                except:
                    pass
        
        logger.error("All parse methods failed")
        return DualStreamParser._manual_extraction(clean)

    @staticmethod
    def _aggressive_repair(broken_json: str) -> Optional[str]:
        """Aggressively repair broken JSON"""
        try:
            repaired = broken_json
            repaired = repaired.replace("'", '"')
            repaired = re.sub(r',(\s*[}\]])', r'\1', repaired)
            repaired = re.sub(r'(\w+):', r'"\1":', repaired)
            repaired = re.sub(r'"\s*\n\s*"', '",\n"', repaired)
            repaired = re.sub(r'}\s*{', '},{', repaired)
            repaired = re.sub(r']\s*\[', '],[', repaired)
            return repaired
        except Exception as e:
            logger.error(f"Repair failed: {e}")
            return None
    
    @staticmethod
    def _manual_extraction(text: str) -> Dict:
        """Last resort: extract values manually"""
        result = {
            "summary": "Manual extraction performed",
            "vulnerabilities": [],
            "recommended_actions": []
        }
        
        try:
            summary_match = re.search(r'"summary"\s*:\s*"([^"]*)"', text, re.IGNORECASE)
            if summary_match:
                result["summary"] = summary_match.group(1)
            
            port_matches = re.findall(r'"port"\s*:\s*(\d+)', text)
            for port in set(port_matches):
                result["vulnerabilities"].append({
                    "port": int(port),
                    "service": "Unknown",
                    "severity": "Medium",
                    "description": f"Port {port} open (manual detection)"
                })
            
            logger.info(f"Manual extraction: {len(result['vulnerabilities'])} findings")
        except Exception as e:
            logger.error(f"Manual extraction failed: {e}")
        
        return result

    @staticmethod
    def _validate_schema(data: Dict) -> Dict:
        """Validate and clean up data structure"""
        if not isinstance(data, dict):
            return DualStreamParser._empty_result("Invalid data type")
        
        # Remove unwanted fields
        data.pop('think', None)
        data.pop('reasoning', None)
        data.pop('analysis', None)
        
        # Ensure required fields
        if "vulnerabilities" not in data:
            data["vulnerabilities"] = []
        
        if "summary" not in data:
            vuln_count = len(data.get("vulnerabilities", []))
            data["summary"] = f"{vuln_count} security findings detected" if vuln_count > 0 else "No vulnerabilities found"
        
        if "recommended_actions" not in data:
            data["recommended_actions"] = []
        
        # Validate vulnerabilities
        valid_vulns = []
        for vuln in data.get("vulnerabilities", []):
            if isinstance(vuln, dict) and "port" in vuln:
                if "severity" not in vuln:
                    vuln["severity"] = "Medium"
                if "service" not in vuln:
                    vuln["service"] = "Unknown"
                if "description" not in vuln:
                    vuln["description"] = "Security risk detected"
                valid_vulns.append(vuln)
        
        data["vulnerabilities"] = valid_vulns
        return data
    
    @staticmethod
    def _empty_result(message: str) -> Dict:
        """Return empty but valid result"""
        return {
            "summary": message,
            "vulnerabilities": [],
            "recommended_actions": []
        }
