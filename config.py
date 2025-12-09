import os

# --- 1. DİZİN VE YOL AYARLARI ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, 'logs')
OUTPUT_DIR = os.path.join(BASE_DIR, 'outputs')

# Klasörleri oluştur
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# --- 2. MODEL AYARLARI ---
# Test aşamasında hızlı olması için 1.5b kullanıyoruz
MODEL_NAME = "deepseek-r1:1.5b"
OLLAMA_URL = "http://localhost:11434"

# --- 3. SİSTEM MESAJI ---
SYSTEM_PROMPT = """
Sen uzman bir Siber Güvenlik Analistisin (CyberSec-Agent). 
Görevin: Verilen ağ tarama verilerini (Nmap/Whois) analiz etmek ve kritik güvenlik açıklarını tespit etmektir.

KURALLAR:
1. Çıktın, yazılım tarafından okunacağı için GEÇERLİ BİR JSON OLMALIDIR.
2. Yanıtına bir <think> bloğu ile başla. Bu blokta veriyi analiz et, riskleri değerlendir.
3. <think> bloğu bittikten sonra, SADECE ve SADECE aşağıdaki JSON yapısını döndür:

```json
{
  "summary": "Analizin kısa bir özeti (Türkçe)",
  "vulnerabilities": [
    {
      "service": "Servis adı (örn: ssh)",
      "port": 22,
      "severity": "High/Medium/Low",
      "description": "Neden riskli olduğu ve çözüm önerisi"
    }
  ],
  "recommended_actions": ["Aksiyon 1", "Aksiyon 2"]
}