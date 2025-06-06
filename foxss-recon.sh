#!/bin/bash

# XSS Hunter - Recon Automation Tool
# Bu araç subdomain keşfi, aktif doğrulama ve XSS odaklı URL toplama süreçlerini otomatize eder

# Renk tanımlamaları
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Banner
echo -e "${RED}


______ _______   __              ______                     
|  ___|  _  \ \ / /              | ___ \                    
| |_  | | | |\ V / ___ ___ ______| |_/ /___  ___ ___  _ __  
|  _| | | | |/   \/ __/ __|______|    // _ \/ __/ _ \| '_ \ 
| |   \ \_/ / /^\ \__ \__ \      | |\ \  __/ (_| (_) | | | |
\_|    \___/\/   \/___/___/      \_| \_\___|\___\___/|_| |_|
                                                 Caner Aktaş           
                                                            
                                         

${NC}"
echo -e "${YELLOW}FOXss Recon${NC}"
echo -e "${BLUE}Version: 1.0${NC}\n"
echo -e "${RED}https://www.github.com/caneraktas1337${NC}\n"

# Kullanım kontrol
if [ $# -ne 1 ]; then
    echo -e "${RED}Kullanım: $0 <domain>${NC}"
    echo -e "${YELLOW}Örnek: $0 hedefsite.com${NC}"
    exit 1
fi

# Parametreler
TARGET_DOMAIN=$1
CURRENT_DATE=$(date +"%Y-%m-%d")
OUTPUT_DIR="recon_$TARGET_DOMAIN"
SUBDOMAINS_FILE="$OUTPUT_DIR/subdomains.txt"
ACTIVE_SUBDOMAINS_FILE="$OUTPUT_DIR/active_subdomains.txt"
URLS_FILE="$OUTPUT_DIR/urls.txt"
XSS_ENDPOINTS="$OUTPUT_DIR/xss_endpoints.txt"
XSS_PARAMS="$OUTPUT_DIR/xss_parameters.txt"  # Her benzersiz parametre için bir dosya
XSS_HIGH_RISK="$OUTPUT_DIR/xss_high_risk.txt"  # Yüksek riskli olabilecek parametreler

# Çıktı dizini oluştur
mkdir -p "$OUTPUT_DIR"

# Araçların varlığını kontrol et
if [ ${#missing_tools[@]} -ne 0 ]; then
    echo -e "${RED}[!] Aşağıdaki araçlar bulunamadı:${NC}"
    for tool in "${missing_tools[@]}"; do
        echo -e "${YELLOW}    - $tool${NC}"
    done
    echo -e "${RED}Lütfen eksik araçları yükleyin ve tekrar deneyin.${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Tüm gerekli araçlar mevcut!${NC}"

# Subdomain keşfi
discover_subdomains() {
    echo -e "\n${BLUE}[*] Subdomain keşfi başlatılıyor...${NC}"
    
    echo -e "${YELLOW}[*] Subfinder çalıştırılıyor...${NC}"
    subfinder -d "$TARGET_DOMAIN" -o "$OUTPUT_DIR/subfinder_subdomains.txt" -silent
    
    echo -e "${YELLOW}[*] Amass çalıştırılıyor...${NC}"
    amass enum -passive -d "$TARGET_DOMAIN" -o "$OUTPUT_DIR/amass_subdomains.txt"
    
    # Sonuçları birleştir ve tekrar edenleri kaldır
    cat "$OUTPUT_DIR/subfinder_subdomains.txt" "$OUTPUT_DIR/amass_subdomains.txt" | sort -u > "$SUBDOMAINS_FILE"
    
    local count=$(wc -l < "$SUBDOMAINS_FILE")
    echo -e "${GREEN}[+] Toplam $count subdomain bulundu.${NC}"
}

# Aktif subdomainleri belirle
identify_active_subdomains() {
    echo -e "\n${BLUE}[*] Aktif subdomainler belirleniyor...${NC}"
    
    httpx -l "$SUBDOMAINS_FILE" -silent -o "$ACTIVE_SUBDOMAINS_FILE"
    
    local count=$(wc -l < "$ACTIVE_SUBDOMAINS_FILE")
    echo -e "${GREEN}[+] Toplam $count aktif subdomain bulundu.${NC}"
}

# URL toplama
collect_urls() {
    echo -e "\n${BLUE}[*] URL'ler toplanıyor...${NC}"
    
    echo -e "${YELLOW}[*] Urlfinder ile URL'ler toplanıyor...${NC}"
    cat "$ACTIVE_SUBDOMAINS_FILE" | urlfinder -o "$OUTPUT_DIR/urlfinder_urls.txt"
    
    echo -e "${YELLOW}[*] Katana ile URL'ler toplanıyor...${NC}"
    katana -list "$ACTIVE_SUBDOMAINS_FILE" -o "$OUTPUT_DIR/katana_urls.txt" -silent
    
    echo -e "${YELLOW}[*] Waybackurls ile URL'ler toplanıyor...${NC}"
    cat "$ACTIVE_SUBDOMAINS_FILE" | waybackurls > "$OUTPUT_DIR/wayback_urls.txt"
    
    echo -e "${YELLOW}[*] GAU ile URL'ler toplanıyor...${NC}"
    cat "$ACTIVE_SUBDOMAINS_FILE" | gau --threads 5 > "$OUTPUT_DIR/gau_urls.txt"
    
    echo -e "${YELLOW}[*] Gospider ile URL'ler toplanıyor...${NC}"
    while read domain; do
        gospider -s "$domain" -d 2 -c 5 -t 100 -o "$OUTPUT_DIR/gospider" > /dev/null 2>&1
    done < "$ACTIVE_SUBDOMAINS_FILE"
    
    if [ -d "$OUTPUT_DIR/gospider" ]; then
        grep -r -o 'https\?://[^[:space:]]\+' "$OUTPUT_DIR/gospider" | cut -d ':' -f2- > "$OUTPUT_DIR/gospider_urls.txt"
    fi
    
    # Tüm URL'leri birleştir
    cat "$OUTPUT_DIR/urlfinder_urls.txt" "$OUTPUT_DIR/katana_urls.txt" "$OUTPUT_DIR/wayback_urls.txt" "$OUTPUT_DIR/gau_urls.txt" "$OUTPUT_DIR/gospider_urls.txt" 2>/dev/null | sort -u > "$URLS_FILE"
    
    local count=$(wc -l < "$URLS_FILE")
    echo -e "${GREEN}[+] Toplam $count benzersiz URL bulundu.${NC}"
}

# XSS endpointlerini analiz et
analyze_xss_endpoints() {
    echo -e "\n${BLUE}[*] XSS için potansiyel URL'ler analiz ediliyor...${NC}"
    
    # XSS için potansiyel endpointler - Genişletilmiş parametre listesi
    grep -i -E '(search=|q=|query=|text=|name=|message=|content=|comment=|input=|value=|keyword=|data=|redirect=|url=|view=|callback=|return_url=|returnurl=|return=|site=|html=|val=|title=|description=|file=|file_name=|filename=|file_contents=|preview=|id=|item=|page_id=|month=|year=|view_id=|email=|type=|username=|user=|term=|profile=|code=|pre=|post=|subject=|token=|tag=|body=|redir=|referrer=|return_to=|path=|continue=|template=|section=|s=|lang=|sort=|dir=|start=|end=|page=|result=|style=|target=|window=|state=|cat=|src=|feed=|mode=)' "$URLS_FILE" > "$XSS_ENDPOINTS"
    
    # Yüksek riskli parametreler için özel filtreleme
    grep -i -E '(html=|innerhtml=|script=|code=|template=|eval=|markup=|style=|value=|src=|href=|action=|onload=|onerror=|onclick=|onmouseover=)' "$XSS_ENDPOINTS" > "$XSS_HIGH_RISK"
    
    # Parametreleri çıkar ve benzersiz olanları bul
    grep -o -E '[a-zA-Z0-9_-]+=([^&]*)' "$XSS_ENDPOINTS" | cut -d '=' -f 1 | sort -u > "$XSS_PARAMS"
    
    # İstatistikleri yazdır
    local total_xss=$(wc -l < "$XSS_ENDPOINTS")
    local high_risk=$(wc -l < "$XSS_HIGH_RISK")
    local unique_params=$(wc -l < "$XSS_PARAMS")
    
    echo -e "${GREEN}[+] XSS için: $total_xss potansiyel endpoint bulundu${NC}"
    echo -e "${YELLOW}[+] Yüksek riskli: $high_risk endpoint${NC}"
    echo -e "${BLUE}[+] Benzersiz parametre sayısı: $unique_params${NC}"
    
    # En sık kullanılan parametreleri göster
    echo -e "\n${PURPLE}[*] En sık kullanılan 10 parametre:${NC}"
    grep -o -E '[a-zA-Z0-9_-]+=([^&]*)' "$XSS_ENDPOINTS" | cut -d '=' -f 1 | sort | uniq -c | sort -nr | head -10
}

# XSS Raporu oluştur
generate_xss_report() {
    echo -e "\n${BLUE}[*] XSS Raporu oluşturuluyor...${NC}"
    
    local report_file="$OUTPUT_DIR/xss_report.html"
    
    # HTML rapor başlık
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>XSS Tarama Raporu - $TARGET_DOMAIN</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f8f9fa; }
        h1, h2, h3 { color: #2c3e50; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .section { margin-bottom: 30px; padding: 15px; border-radius: 8px; background-color: #f8f9fa; }
        .stats { display: flex; flex-wrap: wrap; gap: 20px; margin-bottom: 20px; }
        .stat-card { background-color: white; border-radius: 5px; padding: 15px; flex: 1; box-shadow: 0 1px 5px rgba(0,0,0,0.05); }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f0f0f0; }
        tr:hover { background-color: #f5f5f5; }
        .badge { display: inline-block; padding: 3px 7px; border-radius: 3px; font-size: 12px; color: white; }
        .high-risk { background-color: #e74c3c; color: white; }
        .medium-risk { background-color: #f39c12; color: white; }
        .low-risk { background-color: #3498db; color: white; }
        .param-count { font-weight: bold; }
        .url-cell { word-break: break-all; }
        .highlight { background-color: #fff3cd; padding: 2px 4px; border-radius: 3px; }
        .footer { text-align: center; margin-top: 30px; color: #7f8c8d; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>XSS Tarama Raporu</h1>
        <div class="section">
            <h2>Genel Bilgiler</h2>
            <p><strong>Hedef Domain:</strong> $TARGET_DOMAIN</p>
            <p><strong>Tarama Tarihi:</strong> $CURRENT_DATE</p>
        </div>
        
        <div class="section">
            <h2>İstatistikler</h2>
            <div class="stats">
                <div class="stat-card">
                    <h3>Subdomain</h3>
                    <p>Toplam: $(wc -l < "$SUBDOMAINS_FILE")</p>
                    <p>Aktif: $(wc -l < "$ACTIVE_SUBDOMAINS_FILE")</p>
                </div>
                <div class="stat-card">
                    <h3>URL'ler</h3>
                    <p>Toplam URL'ler: $(wc -l < "$URLS_FILE")</p>
                    <p>XSS için Potansiyel: $(wc -l < "$XSS_ENDPOINTS")</p>
                </div>
                <div class="stat-card">
                    <h3>XSS Risk Analizi</h3>
                    <p>Yüksek Risk: $(wc -l < "$XSS_HIGH_RISK")</p>
                    <p>Benzersiz Parametreler: $(wc -l < "$XSS_PARAMS")</p>
                </div>
            </div>
        </div>
EOF

    # Subdomain listesi ekle
    cat >> "$report_file" << EOF
        <div class="section">
            <h2>Aktif Subdomainler</h2>
            <table>
                <tr>
                    <th>#</th>
                    <th>Subdomain</th>
                </tr>
EOF

    count=1
    while read -r subdomain; do
        echo "<tr><td>$count</td><td>$subdomain</td></tr>" >> "$report_file"
        count=$((count + 1))
    done < "$ACTIVE_SUBDOMAINS_FILE"

    cat >> "$report_file" << EOF
            </table>
        </div>
EOF

    # Yüksek Riskli XSS Endpointleri
    cat >> "$report_file" << EOF
        <div class="section">
            <h2>Yüksek Riskli XSS Endpointleri</h2>
            <p>Aşağıdaki URL'ler, XSS saldırılarına karşı yüksek risk taşıyan parametreler içermektedir.</p>
            <table>
                <tr>
                    <th>#</th>
                    <th>URL</th>
                    <th>Risk Seviyesi</th>
                </tr>
EOF

    count=1
    while read -r url; do
        echo "<tr><td>$count</td><td class=\"url-cell\">$url</td><td><span class=\"badge high-risk\">Yüksek</span></td></tr>" >> "$report_file"
        count=$((count + 1))
    done < "$XSS_HIGH_RISK"

    cat >> "$report_file" << EOF
            </table>
        </div>
EOF
    
    # Tüm XSS Endpointleri
    cat >> "$report_file" << EOF
        <div class="section">
            <h2>Tüm Potansiyel XSS Endpointleri</h2>
            <p>Bu URL'ler, XSS saldırılarına karşı test edilmesi gereken parametreler içermektedir.</p>
            <table>
                <tr>
                    <th>#</th>
                    <th>URL</th>
                </tr>
EOF

    count=1
    while read -r url; do
        echo "<tr><td>$count</td><td class=\"url-cell\">$url</td></tr>" >> "$report_file"
        count=$((count + 1))
    done < "$XSS_ENDPOINTS"

    cat >> "$report_file" << EOF
            </table>
        </div>
        
        <div class="section">
            <h2>Benzersiz XSS Parametreleri</h2>
            <p>Aşağıdaki parametreler, XSS saldırılarına karşı test edilmelidir.</p>
            <table>
                <tr>
                    <th>#</th>
                    <th>Parametre Adı</th>
                </tr>
EOF

    count=1
    while read -r param; do
        echo "<tr><td>$count</td><td>$param</td></tr>" >> "$report_file"
        count=$((count + 1))
    done < "$XSS_PARAMS"

    cat >> "$report_file" << EOF
            </table>
        </div>
        
        <div class="section">
            <h2>XSS Test Önerileri</h2>
            <ol>
                <li>Yukarıdaki endpointlerde aşağıdaki basit XSS payload'larını deneyebilirsiniz:
                    <ul>
                        <li><code class="highlight">&lt;script&gt;alert(1)&lt;/script&gt;</code></li>
                        <li><code class="highlight">&lt;img src=x onerror=alert(1)&gt;</code></li>
                        <li><code class="highlight">&lt;svg onload=alert(1)&gt;</code></li>
                        <li><code class="highlight">javascript:alert(1)</code></li>
                    </ul>
                </li>
                <li>XSS bypass tekniklerini kullanın (örn. karakter kodlama, JavaScript olayları)</li>
                <li>Manuel olarak test etmek her zaman daha iyi sonuçlar vermektedir.</li>
                <li>Bulunan endpointlerde otomatik XSS tarayıcıları kullanın (XSStrike, XSS Hunter vb.)</li>
                <li>DOM tabanlı XSS için JavaScript kaynak kodunu analiz edin</li>
            </ol>
        </div>
        
        <div class="footer">
            <p>Bu rapor otomatik olarak oluşturulmuştur. Tüm bulguların manuel olarak doğrulanması önerilir.</p>
        </div>
    </div>
</body>
</html>
EOF

    echo -e "${GREEN}[+] XSS Raporu oluşturuldu: $report_file${NC}"
}

# Ana akış
function main {
    echo -e "${BLUE}[*] $TARGET_DOMAIN için XSS odaklı recon başlatılıyor...${NC}"
    echo -e "${RED}[*] $TARGET_DOMAIN "Tarama biraz sürebilir, bu arada kahvenizi alıp gelebilirsiniz."${NC}"
    
    discover_subdomains
    identify_active_subdomains
    collect_urls
    analyze_xss_endpoints
    generate_xss_report
    
    echo -e "\n${GREEN}[+] XSS taraması tamamlandı! Sonuçlar $OUTPUT_DIR dizininde.${NC}"
    echo -e "${YELLOW}[*] XSS endpointlerini manuel olarak test etmeyi unutmayın.${NC}"
    echo -e "${PURPLE}[*] XSS raporu: $OUTPUT_DIR/xss_report.html${NC}"
}

# Programı başlat
main
