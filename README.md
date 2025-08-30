
# FOXss Recon - Otomatik XSS Keşif Aracı

FOXss Recon, web uygulamalarında XSS (Cross-Site Scripting) güvenlik açıklarını keşfetmek amacıyla geliştirilmiş bir otomasyon aracıdır. Bu araç, subdomain keşfi, aktif subdomain doğrulaması ve XSS odaklı URL toplama süreçlerini bir araya getirerek kapsamlı bir tarama sağlar.


## 🚀 Özellikler

- Otomatik subdomain keşfi (Subfinder ve Amass kullanılarak)

- Aktif subdomainlerin doğrulanması (HTTPx ile)

- XSS endpointlerinin toplanması (Urlfinder, Katana, Waybackurls, GAU ve Gospider ile)

- Potansiyel XSS parametrelerinin belirlenmesi ve raporlanması

- Yüksek riskli XSS endpointlerinin tespiti

- Detaylı HTML raporu oluşturma
## 🛠️ Kullanılan Araçlar

- Subfinder: Subdomain keşfi için

- Amass: Pasif subdomain taraması

- HTTPx: Aktif subdomain doğrulaması

- Urlfinder: URL toplama

- Katana: Derin URL keşfi

- Waybackurls: Geçmiş URL arşivi taraması

- GAU: Google dork tabanlı URL toplama

- Gospider: Derinlemesine link taraması

  
## 💻 Kullanım


Örnek:

```bash 
  git clone https://github.com/caneraktas1337/foxssrecon.git
  cd foxssrecon
  chmod +x foxssrecon.sh
  ./foxssrecon.sh hedefsite.com
```
    
## 📂 Çıktılar

- Aktif Subdomainler: recon_<domain>/active_subdomains.txt

- Tüm URL'ler: recon_<domain>/urls.txt

- XSS Endpointleri: recon_<domain>/xss_endpoints.txt

- Yüksek Riskli XSS Endpointleri: recon_<domain>/xss_high_risk.txt

- HTML Raporu: recon_<domain>/xss_report.html

  
##  💡 Not

- Bu araç sadece keşif amaçlıdır ve yasal olmayan kullanım yasaktır. FOXss Recon, yalnızca yetkili ve izinli sistemlerde kullanılmalıdır.


##  🔧 Ana Hatalar ve Düzeltmeler:
1. Tool Control Fonksiyonu Eklendi

check_tools() fonksiyonu eklendi
Missing tools array'i düzgün tanımlandı
Go tool kurulum önerileri eklendi



2. Error Handling İyileştirildi

Tüm komutlarda 2>/dev/null eklendi
Boş dosya kontrolleri eklendi
|| touch fallback'leri eklendi

2. Gospider Çıktı Formatı Düzeltildi

Gospider çıktısından URL'ler doğru şekilde extract ediliyor
Grep pattern düzeltildi

4. File Handling İyileştirildi

Dosya varlık kontrolleri eklendi (-s flag ile)
Boş dosyalar için fallback'ler
Temporary directory kullanımı

5. Regex Pattern'ler Düzeltildi

XSS parameter detection için daha iyi regex
URL filtering için gelişmiş pattern'ler

6. Performance İyileştirmeleri

Gospider thread sayısı düşürüldü (20)
Gereksiz dosya türleri filtrelendi
Temp dosyalar otomatik temizleniyor

7. Hata Durumu Yönetimi

Eğer subdomain bulunamazsa ana domain kullanılıyor
Eğer aktif subdomain yoksa http/https ile deneniyor
Empty file kontrolları her yerde

  
