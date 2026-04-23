# NetPhantom 👻

**Modular Pentest Orchestration Framework** — sıfırdan yazılmış async Python pentest aracı.

> ⚠️ **Yalnızca yetkili sistemlerde kullanın.** İzinsiz tarama yasalara aykırıdır.

---

## NetPhantom ne yapar?

Bir hedefe karşı pentest'in ilk aşamalarını otomatik yapan bir araç. Yani bir sisteme saldırmadan önce **"ne var, ne çalışıyor, açık var mı"** sorularını yanıtlar.

### 4 ana işi var:

**1. Port Tarama**
Hedef sistemde hangi portların açık olduğunu tarar. 3.6 saniyede 1024 portu kontrol edip açık olanları listeler.

**2. Banner Grabbing**
Açık portlardaki servislerin kendini nasıl tanıttığına bakar. Örneğin `micro_httpd` bilgisini buradan alır. Bu bilgiyle "bu servisin bilinen bir açığı var mı" diye bakılır.

**3. Keşif (Recon)**
Hedef bir domain ise DNS kayıtlarını çeker, WHOIS ile kimin adına kayıtlı olduğuna bakar, subdomain brute-force ile gizli alt domainleri bulmaya çalışır.

**4. Zafiyet Kontrolü**
Bulduğu servis versiyonlarını CVE veritabanıyla karşılaştırır. Örneğin "bu FTP sunucusu vsFTPd 2.3.4, bunda backdoor var" gibi uyarılar verir.

### Neden zor bir proje?

Nmap gibi hazır araçları çağırmıyor. Her şey sıfırdan yazılmış — raw TCP paketleri elle oluşturuluyor, async I/O ile 500 port aynı anda taranıyor, checksum hesapları manuel yapılıyor. Gerçek bir pentest framework'ünün temelini oluşturuyor.

---

## Özellikler

| Modül | Açıklama |
|---|---|
| Port Scanner | Raw async TCP — CONNECT / SYN / FIN / XMAS / NULL teknikleri |
| Banner Grabber | Servis banner'larını protokole özgü probe'larla çeker |
| OS Fingerprint | TTL + TCP stack analizi ile işletim sistemi tahmini |
| Vuln Checker | Banner regex + CVE imzaları ile güvenlik açığı tespiti |
| DNS Enum | A / AAAA / MX / NS / TXT / CNAME / SOA kayıtları |
| WHOIS Lookup | Domain kayıt bilgileri |
| Subdomain Brute | Async wordlist tabanlı subdomain keşfi |
| Report Gen | Profesyonel HTML / JSON / TXT rapor üretimi |

---

## Kurulum

```bash
git clone https://github.com/yourusername/netphantom
cd netphantom
pip install -r requirements.txt
```

---

## Kullanım

```bash
# Hızlı port tarama
python netphantom.py scan -t 192.168.1.1 -p 1-1024

# Stealth SYN tarama (root gerekir)
sudo python netphantom.py scan -t 192.168.1.1 -p 1-65535 --technique syn --banner

# Recon: DNS + WHOIS + subdomain
python netphantom.py recon -t example.com --dns --whois --subdomains

# Full pipeline + HTML rapor
python netphantom.py full -t 192.168.1.1 --output pentest_report.html

# Mevcut modülleri listele
python netphantom.py list-modules
```

---

## Proje Yapısı

```
netphantom/
├── netphantom.py          # CLI entry point
├── core/
│   ├── orchestrator.py    # Full pipeline yöneticisi
│   └── plugin_manager.py  # Dinamik modül yükleyici
├── modules/
│   ├── scanners/
│   │   ├── port_scanner.py    # Raw async TCP scanner
│   │   ├── banner_grabber.py  # Servis banner grabber
│   │   ├── os_fingerprint.py  # OS tespiti
│   │   └── vuln_checker.py    # CVE eşleştirici
│   └── recon/
│       ├── dns_enum.py        # DNS enumeration
│       ├── whois_lookup.py    # WHOIS
│       └── subdomain_brute.py # Subdomain brute-force
├── reports/
│   └── report_gen.py      # HTML/JSON/TXT rapor üretici
├── utils/
│   ├── logger.py
│   ├── service_db.py
│   └── wordlists/
│       └── subdomains.txt
└── requirements.txt
```

---

## Teknik Detaylar

- **Async I/O**: `asyncio` ile 500+ eşzamanlı bağlantı
- **Raw Socket**: SYN/FIN/XMAS tarama için kernel-level paket üretimi
- **Checksum**: Manuel IP/TCP checksum hesabı (RFC 1071)
- **Plugin System**: Dinamik modül yükleme, genişletilebilir mimari
- **Zero external scan deps**: Nmap, Metasploit bağımlılığı yok

---

## Lisans

MIT — Yalnızca etik ve yasal amaçlar için.
