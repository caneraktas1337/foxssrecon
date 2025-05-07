FOXss Recon - Otomatik XSS Keşif Aracı
FOXss Recon, web uygulamalarında XSS (Cross-Site Scripting) güvenlik açıklarını keşfetmek amacıyla geliştirilmiş bir otomasyon aracıdır. Bu araç, subdomain keşfi, aktif subdomain doğrulaması ve XSS odaklı URL toplama süreçlerini bir araya getirerek kapsamlı bir tarama sağlar.

🚀 Özellikler
Otomatik subdomain keşfi (Subfinder ve Amass kullanılarak)

Aktif subdomainlerin doğrulanması (HTTPx ile)

XSS endpointlerinin toplanması (Urlfinder, Katana, Waybackurls, GAU ve Gospider ile)

Potansiyel XSS parametrelerinin belirlenmesi ve raporlanması

Yüksek riskli XSS endpointlerinin tespiti

Detaylı HTML raporu oluşturma

🛠️ Kullanılan Araçlar
Subfinder: Subdomain keşfi için

Amass: Pasif subdomain taraması

HTTPx: Aktif subdomain doğrulaması

Urlfinder: URL toplama

Katana: Derin URL keşfi

Waybackurls: Geçmiş URL arşivi taraması

GAU: Google dork tabanlı URL toplama

Gospider: Derinlemesine link taraması


💻 Kullanım ;
./foxss-recon.sh hedefsite.com

📂 Çıktılar
Aktif Subdomainler: recon_<domain>/active_subdomains.txt

Tüm URL'ler: recon_<domain>/urls.txt

XSS Endpointleri: recon_<domain>/xss_endpoints.txt

Yüksek Riskli XSS Endpointleri: recon_<domain>/xss_high_risk.txt

HTML Raporu: recon_<domain>/xss_report.html


📝 Raporlama
Tarama sonuçları detaylı bir HTML raporu olarak kaydedilir. Raporda:

Aktif subdomainler

Toplanan URL'ler

XSS risk analizi

Yüksek riskli endpointler

Parametre analizi ve test önerileri
bulunmaktadır.

💡 Not
Bu araç sadece keşif amaçlıdır ve yasal olmayan kullanım yasaktır. FOXss Recon, yalnızca yetkili ve izinli sistemlerde kullanılmalıdır.

