# 🛡️ CyberSec-Agent: AI-Powered Security Analyst

CyberSec-Agent, klasik ağ tarama araçlarının (Nmap, Whois) yeteneklerini DeepSeek-R1 (LLM) yapay zeka modelinin muhakeme gücüyle birleştiren yeni nesil bir siber güvenlik otomasyon aracıdır.

Bu proje sadece portları taramakla kalmaz; **Chain of Thought (Düşünme Zinciri)** metodolojisini kullanarak bulguların neden riskli olduğunu bir güvenlik uzmanı gibi analiz eder, sesli düşünür ve stratejik çözüm önerileri sunar.

---

## 🚀 Öne Çıkan Özellikler

### 🧠 Reasoning Core (Yapay Zeka Beyni)
- Nmap çıktılarındaki ham verileri (JSON/XML) analiz etmesi için DeepSeek-R1 modeline gönderir.
- Model, güvenlik açıklarını CVE tabanlı düşünerek derecelendirir.

### ⛓️ Chain of Thought (CoT) Görselleştirme
- Yapay zekanın analiz sırasında *nasıl düşündüğünü* terminalde anlık olarak izleyebilirsiniz.
- **Gri Renk:** Modelin iç sesi / düşünme süreci (`<think>` blokları)  
- **Yeşil Renk:** Nihai karar ve çıktı

### 🤖 Otopilot Kurulum (Self-Bootstrapping)
Program `main.py` üzerinden çalıştırıldığında ortamı otomatik yönetir:
- Sanal ortam (venv) yoksa oluşturur.
- `requirements.txt` içindeki bağımlılıkları yükler.
- SYN Scan (-sS) gibi işlemler için Root yetkisi gerekirse, otomatik olarak sudo ister ve kendini yeniden başlatır.

### 🛡️ Dual-Stream Parser
AI çıktılarının bozuk olmasını engellemek için özel ayrıştırıcı:
- `<think>` bloklarını ayıklar.
- Bozuk markdown (` ```json `) çıktıları düzeltir.
- Regex ile modeli onarır ve programın çökmesini engeller.

---

## 🛠️ Mimari

Sistem 4 aşamalı bir pipeline üzerinde çalışır:

1. **Recon (Keşif):**  
   Domain IP çözümleme, Whois bilgileri toplama.

2. **Scanning (Tarama):**  
   `python-nmap` kullanarak quick, full ve stealth tarama.

3. **Analysis (AI Analizi):**  
   Toplanan veriler LLM'e gönderilir ve JSON analizi oluşturulur.

4. **Reporting (Raporlama):**  
   Sonuçlar `outputs/` klasörüne zaman damgalı şekilde kaydedilir.

---

## 📦 Kurulum

> Proje Linux tabanlı sistemler (Ubuntu, Kali, Debian) için optimize edilmiştir.

### 1. Sistem Gereksinimleri

Aşağıdaki araçların sisteminizde yüklü olması gerekir:

```bash
# Nmap (Tarama motoru)
sudo apt update && sudo apt install nmap -y

# Ollama (AI Motoru)
curl -fsSL https://ollama.com/install.sh | sh
2. AI Modelinin Hazırlanması
Varsayılan model: deepseek-r1:1.5b

bash
Kodu kopyala
ollama pull deepseek-r1:1.5b
İsterseniz 7B / 8B modellerine geçip config.py üzerinden değiştirebilirsiniz.

3. Projeyi İndirme
bash
Kodu kopyala
git clone https://github.com/ozturu68/SecurityAgent.git
cd SecurityAgent
💻 Kullanım
Sanal ortam kurmanıza gerek yoktur, main.py otomatik olarak halleder.

bash
Kodu kopyala
python3 main.py -t <HEDEF> [SEÇENEKLER]
Parametreler
Parametre	Açıklama	Örnek
-t, --target	(Zorunlu) Hedef IP / Domain / Subnet	-t google.com
-m, --mode	Tarama modu: quick, full, stealth	-m stealth
-o, --output	Çıktı dosyası (uzantısız)	-o rapor1
--verbose	Detaylı loglama	--verbose

🔍 Örnek Senaryolar
1. Hızlı Tarama (Quick Scan)
En popüler 100 portu hızlıca tarar:

bash
Kodu kopyala
python3 main.py -t scanme.nmap.org -m quick
2. Gizli Tarama (Stealth Scan)
SYN Scan (-sS) kullanır. Güvenlik duvarlarına takılma olasılığı düşüktür.

bash
Kodu kopyala
python3 main.py -t 192.168.1.50 -m stealth
3. Kapsamlı Tarama (Full Scan)
Versiyon tespiti (-sV) + varsayılan scriptler (-sC):

bash
Kodu kopyala
python3 main.py -t example.com -m full --verbose
📂 Proje Yapısı
bash
Kodu kopyala
CyberSec-Agent/
├── main.py                 # 🚀 Başlatıcı (Otopilot)
├── config.py               # ⚙️ Model Ayarları & Prompt
├── requirements.txt        # Python Bağımlılıkları
├── core/
│   ├── llm_engine.py       # Ollama Streaming
│   └── parser.py           # Dual-Stream JSON Ayrıştırıcı
├── modules/
│   ├── recon.py            # Whois & DNS Çözümleme
│   ├── scanner.py          # Nmap Entegrasyonu
│   ├── analyzer.py         # AI Analiz
│   └── reporter.py         # Raporlama
├── utils/
│   └── logger.py           # Log Sistemi
├── logs/
└── outputs/
🔮 Gelecek Planları (Roadmap)
 Faz 1: Temel CLI yapısı

 Faz 2: Nmap & Whois entegrasyonu

 Faz 3: DeepSeek-R1 + CoT görselleştirme

 Faz 4: Web Crawler (Alt URL tespiti)

 Faz 5: CVE veritabanı ile online çapraz sorgu

 Faz 6: Multi-Agent yapı (Saldırgan + savunmacı)

⚠️ Yasal Uyarı
Bu araç sadece eğitim ve test amaçlıdır.
Yalnızca izin aldığınız sistemlerde kullanınız.
Geliştirici, izinsiz kullanım sorumluluğunu kabul etmez.

📄 Lisans
Bu proje MIT License ile lisanslanmıştır.

yaml
Kodu kopyala

---

Hazır! GitHub README editörüne **doğrudan yapıştırabilirsiniz**.  
İstersen daha profesyonel badge’ler, logo veya GIF demo ekleyebilirim.






