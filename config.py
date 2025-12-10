import os

# --- 1. DİZİN VE YOL AYARLARI ---
# Projenin ana dizinini dinamik olarak al
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, 'logs')
OUTPUT_DIR = os.path.join(BASE_DIR, 'outputs')

# Gerekli klasörleri hata vermeden oluştur
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# --- 2. MODEL VE MOTOR AYARLARI ---
# Otomatik indirilecek ve kullanılacak model (Hız/Performans dengesi için 1.5b)
MODEL_NAME = "deepseek-r1:1.5b"
OLLAMA_URL = "http://localhost:11434"

# --- 3. AI SİSTEM MESAJI (PROMPT) ---
# DeepSeek-R1'in "düşünme" yeteneğini kullanarak JSON üretmesini sağlayan prompt
SYSTEM_PROMPT = """
Sen uzman bir Siber Güvenlik Analistisin (CyberSec-Agent). 
Görevin: Verilen ağ tarama verilerini (Nmap/Whois) analiz etmek ve kritik güvenlik açıklarını tespit etmektir.

KURALLAR:
1. Çıktın, yazılım tarafından işleneceği için %100 GEÇERLİ BİR JSON OLMALIDIR.
2. Yanıtına mutlaka bir <think> bloğu ile başla. Bu blokta veriyi analiz et, riskleri değerlendir.
3. <think> bloğu bittikten sonra, başka hiçbir açıklama yapmadan SADECE aşağıdaki JSON yapısını döndür.
4. "summary" alanı Türkçe olmalı ve yönetici özeti niteliği taşımalıdır.

BEKLENEN JSON FORMATI:
```json
{
  "summary": "Analizin kısa ve net özeti (Türkçe)",
  "vulnerabilities": [
    {
      "service": "Servis adı (örn: ssh, http)",
      "port": 22,
      "severity": "High/Medium/Low",
      "description": "Neden riskli olduğu ve teknik açıklama"
    }
  ],
  "recommended_actions": [
    "Aksiyon 1 (Somut öneri)", 
    "Aksiyon 2 (Somut öneri)"
  ]
}