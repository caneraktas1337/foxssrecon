#!/bin/bash
#
# FOxss Recon v4.5
# Futuristic XSS Recon & Analysis Framework
# Author: Caner Aktas
#

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_title()   { printf "\n${BLUE}%s${NC}\n" "$1"; }
log_info()    { printf "${BLUE}[i] %s${NC}\n" "$1"; }
log_success() { printf "${GREEN}[✓] %s${NC}\n" "$1"; }
log_warn()    { printf "${YELLOW}[!] %s${NC}\n" "$1"; }
log_error()   { printf "${RED}[x] %s${NC}\n" "$1"; }

banner() {
  echo -e "${RED}
 ______ _______   __              ______                     
 |  ___|  _  \ \ / /              | ___ \                    
 | |_  | | | |\ V / ___ ___ ______| |_/ /___  ___ ___  _ __  
 |  _| | | | |/   \/ __/ __|______|    // _ \/ __/ _ \| '_ \ 
 | |   \ \_/ / /^\\ \__ \__ \      | |\ \  __/ (_| (_) | | | |
 \_|    \___/\/   \/___/___/      \_| \_\___|\___\___/|_| |_|
                                              FOxss Recon
${NC}"
  echo -e "${YELLOW}FOxss Recon - Futuristic Neon XSS Recon Framework${NC}"
  echo -e "${BLUE}Version: 4.5 (Deep Smart XSS Recon)${NC}\n"
}

if [ $# -ne 1 ]; then
    log_error "Usage: $0 <domain>"
    exit 1
fi

TARGET_DOMAIN=$1
CURRENT_DATE=$(date +"%Y-%m-%d")
OUTPUT_DIR="recon_$TARGET_DOMAIN"

SUBDOMAINS_FILE="$OUTPUT_DIR/subdomains.txt"
RESOLVED_SUBDOMAINS_FILE="$OUTPUT_DIR/resolved_subdomains.txt"
ACTIVE_SUBDOMAINS_FILE="$OUTPUT_DIR/active_subdomains.txt"

URLS_FILE="$OUTPUT_DIR/urls.txt"
FILTERED_URLS_FILE="$OUTPUT_DIR/urls_filtered.txt"
ACTIVE_URLS_FILE="$OUTPUT_DIR/active_urls.txt"
ACTIVE_URLS_STATUS_FILE="$OUTPUT_DIR/active_urls_status.txt"

XSS_ENDPOINTS="$OUTPUT_DIR/xss_endpoints.txt"
XSS_ENDPOINTS_QS="$OUTPUT_DIR/xss_endpoints_qs.txt"
XSS_ENDPOINTS_NEW="$OUTPUT_DIR/xss_endpoints_new.txt"
XSS_HIGH_RISK="$OUTPUT_DIR/xss_high_risk.txt"
XSS_PARAMS="$OUTPUT_DIR/xss_parameters.txt"

REFLECTION_FILE="$OUTPUT_DIR/xss_reflections.txt"
DALFOX_FILE="$OUTPUT_DIR/dalfox_findings.txt"

JS_URLS_FILE="$OUTPUT_DIR/js_urls.txt"
JS_SINKS_FILE="$OUTPUT_DIR/js_sinks.txt"
JS_SECRETS_FILE="$OUTPUT_DIR/js_secrets.txt"

HIGH_VALUE_URLS_FILE="$OUTPUT_DIR/high_value_urls.txt"
HIDDEN_PARAMS_FILE="$OUTPUT_DIR/hidden_params.txt"

HISTORY_DIR=".foxss_history"
mkdir -p "$HISTORY_DIR"
HISTORY_SUBS="$HISTORY_DIR/${TARGET_DOMAIN}_subdomains_all.txt"
HISTORY_URLS="$HISTORY_DIR/${TARGET_DOMAIN}_urls_all.txt"
HISTORY_XSS="$HISTORY_DIR/${TARGET_DOMAIN}_xss_all.txt"

PARALLEL_JOBS="${PARALLEL_JOBS:-10}"
RESOLVERS_FILE="${RESOLVERS_FILE:-}"
BLIND_XSS_DOMAIN="${BLIND_XSS_DOMAIN:-}"
COLLAB_DOMAIN="${COLLAB_DOMAIN:-}"
BLIND_HOST="${BLIND_XSS_DOMAIN:-$COLLAB_DOMAIN}"

HTTPX_RATE="${HTTPX_RATE:-80}"
JS_MAX_FILES="${JS_MAX_FILES:-120}"
HVT_MAX_URLS="${HVT_MAX_URLS:-80}"

mkdir -p "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR/tmp"

FOXSS_UA=""
FOXSS_XFF=""

init_evasion() {
    log_title "Initializing WAF evasion headers"

    local uas=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0"
        "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0 Mobile Safari/537.36"
    )
    local idx=$((RANDOM % ${#uas[@]}))
    FOXSS_UA="${uas[$idx]}"

    FOXSS_XFF="$((RANDOM % 250 + 1)).$((RANDOM % 250 + 1)).$((RANDOM % 250 + 1)).$((RANDOM % 250 + 1))"

    export FOXSS_UA FOXSS_XFF

    log_info "User-Agent: $FOXSS_UA"
    log_info "X-Forwarded-For: $FOXSS_XFF"
}

check_tools() {
    log_title "Tool check"

    local required=(
        "samoscout"
        "subfinder"
        "dnsx"
        "httpx"
        "katana"
        "gau"
        "waybackurls"
        "urlfinder"
        "dalfox"
        "parallel"
        "curl"
        "anew"
        "qsreplace"
    )

    local optional=(
        "shuffledns"
        "puredns"
    )

    local missing=()

    for t in "${required[@]}"; do
        if ! command -v "$t" &>/dev/null; then
            missing+=("$t")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing required tools:"
        printf '%s\n' "${missing[@]}"
        log_error "Please install them and run again."
        exit 1
    fi

    for t in "${optional[@]}"; do
        if ! command -v "$t" &>/dev/null; then
            log_warn "Optional tool not found (continuing without it): $t"
        fi
    done
}

discover_subdomains() {
    log_title "Subdomain discovery"
    local RAW_SUBS="$OUTPUT_DIR/raw_subdomains.txt"
    : > "$RAW_SUBS"

    log_info "Running samoscout..."
    samoscout -d "$TARGET_DOMAIN" -silent >> "$RAW_SUBS" 2>/dev/null

    log_info "Running subfinder..."
    subfinder -d "$TARGET_DOMAIN" -silent >> "$RAW_SUBS" 2>/dev/null

    sort -u "$RAW_SUBS" > "$SUBDOMAINS_FILE"

    local count
    count=$(wc -l < "$SUBDOMAINS_FILE" 2>/dev/null || echo 0)
    log_success "Total unique subdomains: $count"

    sort -u "$SUBDOMAINS_FILE" | anew "$HISTORY_SUBS" > "$OUTPUT_DIR/new_subdomains.txt"
    local new_count
    new_count=$(wc -l < "$OUTPUT_DIR/new_subdomains.txt" 2>/dev/null || echo 0)
    log_info "Newly discovered subdomains in this run: $new_count"
}

resolve_subdomains_dns() {
    log_title "DNS resolution (shuffledns / puredns / dnsx)"
    : > "$RESOLVED_SUBDOMAINS_FILE"

    local TMP_RESOLVED="$OUTPUT_DIR/tmp/resolved_all.txt"
    : > "$TMP_RESOLVED"

    if command -v shuffledns &>/dev/null; then
        log_info "Using shuffledns..."
        shuffledns -d "$TARGET_DOMAIN" -list "$SUBDOMAINS_FILE" -silent -o "$OUTPUT_DIR/tmp/shuffledns_resolved.txt" 2>/dev/null
        cat "$OUTPUT_DIR/tmp/shuffledns_resolved.txt" >> "$TMP_RESOLVED" 2>/dev/null
    fi

    if command -v puredns &>/dev/null; then
        if [ -n "$RESOLVERS_FILE" ] && [ -f "$RESOLVERS_FILE" ]; then
            log_info "Using puredns with custom resolvers..."
            puredns resolve "$SUBDOMAINS_FILE" -r "$RESOLVERS_FILE" -w "$OUTPUT_DIR/tmp/puredns_resolved.txt" 2>/dev/null
        else
            log_info "Using puredns with default resolvers..."
            puredns resolve "$SUBDOMAINS_FILE" -w "$OUTPUT_DIR/tmp/puredns_resolved.txt" 2>/dev/null
        fi
        cat "$OUTPUT_DIR/tmp/puredns_resolved.txt" >> "$TMP_RESOLVED" 2>/dev/null
    fi

    log_info "Using dnsx..."
    dnsx -silent -l "$SUBDOMAINS_FILE" -o "$OUTPUT_DIR/tmp/dnsx_resolved.txt" 2>/dev/null
    cat "$OUTPUT_DIR/tmp/dnsx_resolved.txt" >> "$TMP_RESOLVED" 2>/dev/null

    if [ -s "$TMP_RESOLVED" ]; then
        sort -u "$TMP_RESOLVED" > "$RESOLVED_SUBDOMAINS_FILE"
    else
        log_warn "No DNS resolution results, falling back to raw subdomain list."
        cp "$SUBDOMAINS_FILE" "$RESOLVED_SUBDOMAINS_FILE"
    fi

    local rcount
    rcount=$(wc -l < "$RESOLVED_SUBDOMAINS_FILE" 2>/dev/null || echo 0)
    log_success "Resolvable subdomains: $rcount"
}

identify_active_subdomains() {
    log_title "Active subdomain discovery (httpx)"
    log_info "Probing subdomains with httpx..."

    httpx -l "$RESOLVED_SUBDOMAINS_FILE" \
        -silent \
        -follow-redirects \
        -rate "$HTTPX_RATE" \
        -H "User-Agent: $FOXSS_UA" \
        -H "X-Forwarded-For: $FOXSS_XFF" \
        -o "$ACTIVE_SUBDOMAINS_FILE" 2>/dev/null

    local acount
    acount=$(wc -l < "$ACTIVE_SUBDOMAINS_FILE" 2>/dev/null || echo 0)
    log_success "Active HTTP(S) subdomains: $acount"
}

collect_urls() {
    log_title "URL collection"
    log_info "Running katana, gau, waybackurls, urlfinder..."

    katana -list "$ACTIVE_SUBDOMAINS_FILE" -silent \
        -crawl-depth 5 \
        -js-crawl \
        -retry 2 \
        -timeout 10 \
        -H "User-Agent: $FOXSS_UA" \
        -H "X-Forwarded-For: $FOXSS_XFF" \
        > "$OUTPUT_DIR/tmp/katana.txt" 2>/dev/null

    gau "$TARGET_DOMAIN" > "$OUTPUT_DIR/tmp/gau.txt" 2>/dev/null
    waybackurls < "$SUBDOMAINS_FILE" > "$OUTPUT_DIR/tmp/wayback.txt" 2>/dev/null

    sed -E 's#https?://([^/]+)/?.*#\1#g' "$ACTIVE_SUBDOMAINS_FILE" | sort -u > "$OUTPUT_DIR/tmp/domains.txt"
    urlfinder -list "$OUTPUT_DIR/tmp/domains.txt" -silent > "$OUTPUT_DIR/tmp/urlfinder.txt" 2>/dev/null

    cat "$OUTPUT_DIR"/tmp/*.txt | grep -E '^https?://' | sort -u > "$URLS_FILE"

    local ucount
    ucount=$(wc -l < "$URLS_FILE" 2>/dev/null || echo 0)
    log_success "Collected unique URLs: $ucount"

    log_info "Filtering out static assets (.png, .jpg, .css, .svg, .woff, .pdf, ...)"
    grep -E '^https?://' "$URLS_FILE" | \
        grep -Ev '\.(png|jpe?g|gif|bmp|ico|svg|css|woff2?|ttf|eot|pdf)(\?|$)' \
        > "$FILTERED_URLS_FILE" 2>/dev/null || cp "$URLS_FILE" "$FILTERED_URLS_FILE"

    local fcount
    fcount=$(wc -l < "$FILTERED_URLS_FILE" 2>/dev/null || echo 0)
    log_success "URLs after smart filtering: $fcount"

    sort -u "$FILTERED_URLS_FILE" | anew "$HISTORY_URLS" > "$OUTPUT_DIR/new_urls.txt"
    local new_u
    new_u=$(wc -l < "$OUTPUT_DIR/new_urls.txt" 2>/dev/null || echo 0)
    log_info "New URLs in this run (post-filter): $new_u"
}

probe_active_urls() {
    log_title "Active URL probing"
    log_info "Probing URLs with httpx..."

    httpx -l "$FILTERED_URLS_FILE" \
        -silent \
        -rate "$HTTPX_RATE" \
        -H "User-Agent: $FOXSS_UA" \
        -H "X-Forwarded-For: $FOXSS_XFF" \
        -o "$ACTIVE_URLS_FILE" 2>/dev/null

    httpx -l "$FILTERED_URLS_FILE" \
        -silent \
        -status-code \
        -rate "$HTTPX_RATE" \
        -H "User-Agent: $FOXSS_UA" \
        -H "X-Forwarded-For: $FOXSS_XFF" \
        -o "$ACTIVE_URLS_STATUS_FILE" 2>/dev/null

    local acount
    acount=$(wc -l < "$ACTIVE_URLS_FILE" 2>/dev/null || echo 0)
    log_success "Active URLs: $acount"
}

analyze_xss() {
    log_title "XSS endpoint and parameter analysis"
    : > "$XSS_ENDPOINTS"
    : > "$XSS_ENDPOINTS_QS"
    : > "$XSS_ENDPOINTS_NEW"

    grep -E '\?|&' "$ACTIVE_URLS_FILE" > "$XSS_ENDPOINTS" 2>/dev/null || true

    local xcount
    xcount=$(wc -l < "$XSS_ENDPOINTS" 2>/dev/null || echo 0)
    log_info "Parameterized endpoints: $xcount"

    log_info "Normalizing query patterns with qsreplace (FOX marker)..."
    cat "$XSS_ENDPOINTS" | qsreplace "FOX" | sort -u > "$XSS_ENDPOINTS_QS"

    local xqcount
    xqcount=$(wc -l < "$XSS_ENDPOINTS_QS" 2>/dev/null || echo 0)
    log_success "Unique normalized XSS endpoint patterns: $xqcount"

    sort -u "$XSS_ENDPOINTS_QS" | anew "$HISTORY_XSS" > "$XSS_ENDPOINTS_NEW"
    local newx
    newx=$(wc -l < "$XSS_ENDPOINTS_NEW" 2>/dev/null || echo 0)
    log_info "New XSS endpoint patterns in this run: $newx"

    log_info "Flagging high-risk patterns..."
    grep -iE '(html|script|src|href|onload|onerror|callback|code|template)=' "$XSS_ENDPOINTS_QS" \
        > "$XSS_HIGH_RISK" 2>/dev/null || true

    log_info "Extracting unique parameter names..."
    grep -oE '[?&][a-zA-Z0-9_-]+=' "$XSS_ENDPOINTS_QS" \
        | sed 's/[?&=]//g' | sort -u \
        > "$XSS_PARAMS" 2>/dev/null || true

    log_success "XSS endpoint and parameter analysis complete."
}

analyze_js_dom() {
    log_title "JavaScript & DOM XSS analysis"

    : > "$JS_URLS_FILE"
    : > "$JS_SINKS_FILE"
    : > "$JS_SECRETS_FILE"

    {
        grep -Ei '\.js(\?|$)' "$ACTIVE_URLS_FILE" 2>/dev/null || true
        grep -Ei '\.js(\?|$)' "$URLS_FILE" 2>/dev/null || true
    } | sort -u > "$JS_URLS_FILE"

    local jcount
    jcount=$(wc -l < "$JS_URLS_FILE" 2>/dev/null || echo 0)

    if [ "$jcount" -eq 0 ]; then
        log_warn "No JS URLs found, skipping JS analysis."
        return
    fi

    log_info "Total JS files: $jcount (max to fetch: $JS_MAX_FILES)."

    local count=0
    while read -r url; do
        [ -z "$url" ] && continue
        count=$((count+1))
        [ "$count" -gt "$JS_MAX_FILES" ] && break

        log_info "Analyzing JS: $url"
        body=$(curl -k -s --max-time 12 \
            -H "User-Agent: $FOXSS_UA" \
            -H "X-Forwarded-For: $FOXSS_XFF" \
            "$url" 2>/dev/null)

        [ -z "$body" ] && continue

        echo "$body" | nl -ba | grep -Ei \
            "innerHTML|outerHTML|document\.write|document\.writeln|eval\(|setTimeout\(|setInterval\(|Function\(|location\.hash|location\.search|localStorage|sessionStorage" \
            | sed "s/^/$url:/" >> "$JS_SINKS_FILE" 2>/dev/null

        echo "$body" | nl -ba | grep -Ei \
            "AIza[0-9A-Za-z\-_]{35}|AKIA[0-9A-Z]{16}|['\"][0-9a-zA-Z_\-]{32,45}['\"]" \
            | sed "s/^/$url:/" >> "$JS_SECRETS_FILE" 2>/dev/null

    done < "$JS_URLS_FILE"

    local sinkc secretc
    sinkc=$(wc -l < "$JS_SINKS_FILE" 2>/dev/null || echo 0)
    secretc=$(wc -l < "$JS_SECRETS_FILE" 2>/dev/null || echo 0)

    log_success "JS sink matches: $sinkc lines"
    log_success "JS secret / API key candidates: $secretc lines"
}

discover_hidden_params() {
    log_title "Hidden parameter discovery (high-value targets)"

    : > "$HIGH_VALUE_URLS_FILE"
    : > "$HIDDEN_PARAMS_FILE"

    grep -Ei 'login|signin|sign-in|sign_in|auth|account|profile|register|signup|reset|password|passwd|admin|panel|dashboard|settings|checkout|payment' \
        "$ACTIVE_URLS_FILE" 2>/dev/null | sort -u > "$HIGH_VALUE_URLS_FILE"

    local hvcount
    hvcount=$(wc -l < "$HIGH_VALUE_URLS_FILE" 2>/dev/null || echo 0)

    if [ "$hvcount" -eq 0 ]; then
        log_warn "No high-value URLs detected, skipping hidden parameter brute forcing."
        return
    fi

    log_info "High-value URLs: $hvcount (max to test: $HVT_MAX_URLS)."

    local cnt=0
    while read -r base; do
        [ -z "$base" ] && continue
        cnt=$((cnt+1))
        [ "$cnt" -gt "$HVT_MAX_URLS" ] && break

        local param_string="debug=true&admin=1&test=1&internal=1&sandbox=1&preview=1"
        local full

        if echo "$base" | grep -q '?'; then
            full="${base}&${param_string}"
        else
            full="${base}?${param_string}"
        fi

        local result
        result=$(curl -k -s -o /dev/null --max-time 10 \
            -w "%{http_code} %{size_download}" \
            -H "User-Agent: $FOXSS_UA" \
            -H "X-Forwarded-For: $FOXSS_XFF" \
            "$full" 2>/dev/null)

        local code size
        code=$(echo "$result" | awk '{print $1}')
        size=$(echo "$result" | awk '{print $2}')

        if [ "$code" != "404" ] && [ "$code" != "400" ] && [ "$code" != "000" ]; then
            echo "$base|$code|size=$size|params=$param_string" >> "$HIDDEN_PARAMS_FILE"
            log_info "Hidden param candidate: $base (HTTP $code, size=$size)"
        fi
    done < "$HIGH_VALUE_URLS_FILE"

    local hcount
    hcount=$(wc -l < "$HIDDEN_PARAMS_FILE" 2>/dev/null || echo 0)
    log_success "Hidden parameter candidates: $hcount"
}

reflection_analysis() {
    log_title "Reflection-based context analysis"

    local TARGET_XSS_FILE="$XSS_ENDPOINTS_NEW"

    if [ ! -s "$TARGET_XSS_FILE" ]; then
        log_warn "No new XSS endpoint patterns, skipping reflection analysis."
        return
    fi

    log_info "Running reflection analysis on new XSS patterns..."

    cat "$TARGET_XSS_FILE" | parallel -j "$PARALLEL_JOBS" '
        url="{}"
        marker="FOXSSREF$RANDOM"
        test_url=$(echo "$url" | sed "s/=\([^&]*\)/=${marker}/g")
        body=$(curl -k -s --max-time 10 \
            -H "User-Agent: '"$FOXSS_UA"'" \
            -H "X-Forwarded-For: '"$FOXSS_XFF"'" \
            "$test_url")
        if echo "$body" | grep -q "$marker"; then
            echo "$url|reflected"
        fi
    ' > "$REFLECTION_FILE" 2>/dev/null

    local rcount
    rcount=$(wc -l < "$REFLECTION_FILE" 2>/dev/null || echo 0)
    log_success "Reflected endpoints: $rcount"
}

run_dalfox_scan() {
    log_title "DalFox XSS scanning"

    local TARGET_XSS_FILE="$XSS_ENDPOINTS_NEW"

    if [ ! -s "$TARGET_XSS_FILE" ]; then
        log_warn "No new XSS endpoint patterns, skipping DalFox scan."
        return
    fi

    local cmd="dalfox pipe --skip-bav --silence --no-spinner --user-agent \"$FOXSS_UA\""

    if [ -n "$BLIND_HOST" ]; then
        log_info "Using blind XSS host: $BLIND_HOST"
        cmd="$cmd -b $BLIND_HOST"
    fi

    log_info "DalFox command: $cmd"
    echo "$cmd" > "$OUTPUT_DIR/dalfox_cmd.txt"

    eval "$cmd" < "$TARGET_XSS_FILE" | tee "$DALFOX_FILE" 2>/dev/null

    local dcount
    dcount=$(grep -Ei "xss|POC|Reflected" "$DALFOX_FILE" 2>/dev/null | wc -l)
    log_success "DalFox scan lines containing potential findings: $dcount"
}

generate_report() {
    log_title "Generating HTML report"

    REPORT="$OUTPUT_DIR/xss_report.html"

    SUB_COUNT=$(wc -l < "$SUBDOMAINS_FILE" 2>/dev/null || echo 0)
    RESOLVED_SUB_COUNT=$(wc -l < "$RESOLVED_SUBDOMAINS_FILE" 2>/dev/null || echo 0)
    ACTIVE_SUB=$(wc -l < "$ACTIVE_SUBDOMAINS_FILE" 2>/dev/null || echo 0)
    URL_COUNT=$(wc -l < "$URLS_FILE" 2>/dev/null || echo 0)
    FILTERED_URL_COUNT=$(wc -l < "$FILTERED_URLS_FILE" 2>/dev/null || echo 0)
    ACTIVE_URL_COUNT=$(wc -l < "$ACTIVE_URLS_FILE" 2>/dev/null || echo 0)
    XSS_COUNT=$(wc -l < "$XSS_ENDPOINTS" 2>/dev/null || echo 0)
    XSS_QS_COUNT=$(wc -l < "$XSS_ENDPOINTS_QS" 2>/dev/null || echo 0)
    XSS_NEW_COUNT=$(wc -l < "$XSS_ENDPOINTS_NEW" 2>/dev/null || echo 0)
    HIGH_RISK_COUNT=$(wc -l < "$XSS_HIGH_RISK" 2>/dev/null || echo 0)
    PARAM_COUNT=$(wc -l < "$XSS_PARAMS" 2>/dev/null || echo 0)
    REFLECTED_COUNT=$(wc -l < "$REFLECTION_FILE" 2>/dev/null || echo 0)

    NEW_SUBS_COUNT=$(wc -l < "$OUTPUT_DIR/new_subdomains.txt" 2>/dev/null || echo 0)
    NEW_URLS_COUNT=$(wc -l < "$OUTPUT_DIR/new_urls.txt" 2>/dev/null || echo 0)

    JS_SINK_COUNT=$(wc -l < "$JS_SINKS_FILE" 2>/dev/null || echo 0)
    JS_SECRET_COUNT=$(wc -l < "$JS_SECRETS_FILE" 2>/dev/null || echo 0)
    HIDDEN_PARAM_COUNT=$(wc -l < "$HIDDEN_PARAMS_FILE" 2>/dev/null || echo 0)

    if [ -s "$DALFOX_FILE" ]; then
        DALFOX_FINDINGS_LINES=$(grep -Ei "xss|POC|Reflected" "$DALFOX_FILE" 2>/dev/null | wc -l)
    else
        DALFOX_FINDINGS_LINES=0
    fi

    HIGH_RISK_ROWS=""
    i=1
    while read -r line; do
        [ -z "$line" ] && continue
        STATUS="-"
        if [ -f "$ACTIVE_URLS_STATUS_FILE" ]; then
            STATUS=$(grep -F "$line" "$ACTIVE_URLS_STATUS_FILE" 2>/dev/null | head -n1 | sed -E 's/.*\[([0-9]{3})\].*/\1/')
            [ -z "$STATUS" ] && STATUS="-"
        fi
        REF_FLAG="No"
        if grep -Fq "$line|reflected" "$REFLECTION_FILE" 2>/dev/null; then
            REF_FLAG="Yes"
        fi
        HIGH_RISK_ROWS+="<tr><td>$i</td><td class='url-cell' style='word-break:break-all;'>$line</td><td>$STATUS</td><td><span class='badge-high'>High</span></td><td>$REF_FLAG</td><td><button class='copy-btn' data-copy=\"$line\">Copy</button></td></tr>"
        i=$((i+1))
    done < "$XSS_HIGH_RISK"

    PARAM_ROWS=""
    i=1
    while read -r p; do
        [ -z "$p" ] && continue
        PARAM_ROWS+="<tr><td>$i</td><td>$p</td></tr>"
        i=$((i+1))
    done < "$XSS_PARAMS"

    JS_SINK_HTML=""
    if [ -s "$JS_SINKS_FILE" ]; then
        JS_SINK_HTML=$(head -n 80 "$JS_SINKS_FILE" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g')
    fi

    JS_SECRET_HTML=""
    if [ -s "$JS_SECRETS_FILE" ]; then
        JS_SECRET_HTML=$(head -n 80 "$JS_SECRETS_FILE" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g')
    fi

    HIDDEN_PARAM_ROWS=""
    i=1
    if [ -s "$HIDDEN_PARAMS_FILE" ]; then
        while IFS='|' read -r url code meta params; do
            [ -z "$url" ] && continue
            HIDDEN_PARAM_ROWS+="<tr><td>$i</td><td class='url-cell'>$url</td><td>$code</td><td>${meta}</td><td>${params}</td></tr>"
            i=$((i+1))
        done < "$HIDDEN_PARAMS_FILE"
    fi

    DALFOX_HTML=""
    if [ -s "$DALFOX_FILE" ]; then
        DALFOX_HTML=$(sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' "$DALFOX_FILE")
    fi

    cat > "$OUTPUT_DIR/report_style.css" <<'CSS'
/* FOxss Recon Futuristic Neon Dashboard v4.5 */

@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

:root {
  --bg: #020617;
  --bg-noise: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200"><filter id="noise"><feTurbulence type="fractalNoise" baseFrequency="0.8" numOctaves="4"/></filter><rect width="100%" height="100%" filter="url(%23noise)" opacity="0.07"/></svg>');
  --glass: rgba(255,255,255,0.06);
  --muted: #8ca0c6;
  --accent-fox: #f97316;
  --accent-cyan: #06b6d4;
  --accent-purple: #a855f7;
  --danger: #ef4444;
  --success: #22c55e;
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  background: var(--bg) fixed;
  background-image: var(--bg-noise);
  color: #e6eef8;
  font-family: Inter, sans-serif;
  display: flex;
}

/* SIDEBAR */

.sidebar {
  width: 240px;
  position: fixed;
  top: 0;
  bottom: 0;
  background: rgba(0,0,0,0.45);
  backdrop-filter: blur(16px);
  padding: 24px;
  border-right: 1px solid rgba(255,255,255,0.1);
  display: flex;
  flex-direction: column;
}

.sidebar .logo-box {
  display: flex;
  align-items: center;
  gap: 14px;
  margin-bottom: 40px;
}

.sidebar .fox-icon {
  width: 40px;
  height: 40px;
  background: radial-gradient(circle, var(--accent-fox), #f43f5e);
  border-radius: 16px;
  box-shadow: 0 0 18px rgba(249,115,22,0.9);
  position: relative;
}
.sidebar .fox-icon::before {
  content: "";
  position: absolute;
  inset: 6px;
  border-radius: 12px 12px 4px 12px;
  border: 2px solid rgba(15,23,42,0.9);
  box-shadow: inset 0 0 8px rgba(15,23,42,0.7);
}

.sidebar .title {
  font-size: 20px;
  font-weight: 700;
  color: var(--accent-fox);
}

.sidebar nav {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.sidebar nav a {
  text-decoration: none;
  color: var(--muted);
  font-size: 14px;
  padding: 8px 4px;
  border-radius: 6px;
  transition: 0.25s;
}

.sidebar nav a:hover {
  color: #fff;
  background: rgba(249,115,22,0.15);
  padding-left: 10px;
  border-left: 2px solid var(--accent-fox);
}

/* MAIN CONTAINER */

.container {
  width: calc(100% - 240px);
  margin-left: 240px;
  padding: 26px;
}

/* HEADER */

.header {
  background: var(--glass);
  padding: 14px 20px;
  border-radius: 14px;
  backdrop-filter: blur(16px);
  border: 1px solid rgba(255,255,255,0.12);
  margin-bottom: 22px;
  display: flex;
  justify-content: space-between;
}

.header .target {
  color: #fff;
  font-size: 16px;
}

.header .meta {
  color: var(--muted);
  font-size: 13px;
}

/* STATS */

.stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(230px,1fr));
  gap: 18px;
}

.card {
  background: var(--glass);
  border-radius: 16px;
  padding: 18px;
  border: 1px solid rgba(255,255,255,0.12);
  backdrop-filter: blur(16px);
  position: relative;
  overflow: hidden;
}

.card::before {
  content: "";
  position: absolute;
  inset: -40%;
  background: conic-gradient(from 180deg, var(--accent-purple), var(--accent-cyan), var(--accent-fox));
  opacity: 0.22;
  transform: rotate(10deg);
}

.card-title {
  font-size: 12px;
  color: var(--muted);
}

.card-num {
  font-size: 24px;
  margin-top: 6px;
  font-weight: 700;
  text-shadow: 0 0 16px rgba(168,85,247,0.55);
  color: #fff;
}

.card-pill {
  margin-top: 6px;
  font-size: 11px;
  color: var(--accent-cyan);
}

/* TABLES */

table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 22px;
  font-size: 13px;
}

th {
  padding: 12px;
  background: rgba(15,23,42,0.9);
  color: var(--accent-cyan);
  font-weight: 600;
  border-bottom: 1px solid rgba(148,163,184,0.4);
}

td {
  padding: 10px 12px;
  border-bottom: 1px solid rgba(148,163,184,0.25);
  color: #dbeafe;
}

tr:nth-child(even) td {
  background: rgba(15,23,42,0.7);
}

tr:hover td {
  background: rgba(124,58,237,0.32);
}

/* BADGES & BUTTONS */

.badge-high {
  background: var(--danger);
  color: white;
  padding: 5px 10px;
  border-radius: 999px;
  font-size: 11px;
}

.copy-btn {
  background: rgba(15,23,42,0.9);
  border: 1px solid rgba(148,163,184,0.5);
  color: var(--muted);
  padding: 5px 10px;
  border-radius: 8px;
  font-size: 11px;
  cursor: pointer;
}
.copy-btn:hover {
  border-color: var(--accent-purple);
  color: #fff;
}

/* CODE / JS PANELS */

pre {
  background: #020617;
  padding: 14px;
  border-radius: 10px;
  border: 1px solid rgba(148,163,184,0.5);
  font-family: "JetBrains Mono", monospace;
  font-size: 11px;
  max-height: 340px;
  overflow: auto;
  box-shadow: 0 0 18px rgba(15,23,42,0.95);
}

/* FOOTER */

.footer {
  text-align: center;
  font-size: 12px;
  margin-top: 34px;
  color: var(--muted);
  opacity: 0.7;
}

@media (max-width: 780px) {
  .sidebar { display:none; }
  .container { margin-left:0; width:100%; }
}
CSS

    cat > "$OUTPUT_DIR/report.js" <<'JS'
document.addEventListener('click', function(e){
    if(e.target && e.target.classList.contains('copy-btn')){
        const txt = e.target.getAttribute('data-copy');
        if(!txt) return;
        if(navigator.clipboard){
            navigator.clipboard.writeText(txt).then(()=>{
                const old = e.target.textContent;
                e.target.textContent='Copied';
                setTimeout(()=>{e.target.textContent=old},1200);
            }).catch(()=>{
                e.target.textContent='Copy error';
                setTimeout(()=>{e.target.textContent='Copy'},1200);
            });
        }
    }
});
JS

    cat > "$REPORT" <<EOF
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>XSS Report - $TARGET_DOMAIN</title>
<link rel="stylesheet" href="report_style.css">
</head>
<body>

<div class="sidebar">
    <div class="logo-box">
        <div class="fox-icon"></div>
        <div class="title">FOxss Recon</div>
    </div>
    <nav>
        <a href="#">Dashboard</a>
        <a href="#">Findings</a>
        <a href="#">Endpoints</a>
        <a href="#">Payloads</a>
        <a href="#">JS Analysis</a>
        <a href="#">Reports</a>
    </nav>
</div>

<div class="container">

<div class="header">
    <div class="target">Scan Target: <b>$TARGET_DOMAIN</b></div>
    <div class="meta">Date: $CURRENT_DATE • FOxss Recon v4.5</div>
</div>

<h2>FOxss Recon v4.5 XSS Scan Summary</h2>

<div class="stats">
  <div class="card">
    <div class="card-title">Discovered Subdomains</div>
    <div class="card-num">$SUB_COUNT</div>
    <div class="card-pill">New this run: $NEW_SUBS_COUNT</div>
  </div>
  <div class="card">
    <div class="card-title">Resolvable Subdomains</div>
    <div class="card-num">$RESOLVED_SUB_COUNT</div>
  </div>
  <div class="card">
    <div class="card-title">Active Subdomains</div>
    <div class="card-num">$ACTIVE_SUB</div>
  </div>
  <div class="card">
    <div class="card-title">Collected URLs</div>
    <div class="card-num">$URL_COUNT</div>
    <div class="card-pill">After smart filter: $FILTERED_URL_COUNT</div>
  </div>
  <div class="card">
    <div class="card-title">Active URLs</div>
    <div class="card-num">$ACTIVE_URL_COUNT</div>
    <div class="card-pill">New this run: $NEW_URLS_COUNT</div>
  </div>
  <div class="card">
    <div class="card-title">XSS-Capable Endpoints</div>
    <div class="card-num">$XSS_COUNT</div>
    <div class="card-pill">Normalized patterns: $XSS_QS_COUNT</div>
  </div>
  <div class="card">
    <div class="card-title">High Risk XSS Endpoints</div>
    <div class="card-num">$HIGH_RISK_COUNT</div>
  </div>
  <div class="card">
    <div class="card-title">Unique Parameters</div>
    <div class="card-num">$PARAM_COUNT</div>
  </div>
  <div class="card">
    <div class="card-title">Reflected Endpoints</div>
    <div class="card-num">$REFLECTED_COUNT</div>
  </div>
  <div class="card">
    <div class="card-title">DalFox Finding Lines</div>
    <div class="card-num">$DALFOX_FINDINGS_LINES</div>
  </div>
  <div class="card">
    <div class="card-title">JS DOM Sink Lines</div>
    <div class="card-num">$JS_SINK_COUNT</div>
  </div>
  <div class="card">
    <div class="card-title">JS Secret/API Key Candidates</div>
    <div class="card-num">$JS_SECRET_COUNT</div>
  </div>
  <div class="card">
    <div class="card-title">Hidden Parameter Candidates</div>
    <div class="card-num">$HIDDEN_PARAM_COUNT</div>
  </div>
  <div class="card">
    <div class="card-title">New XSS Endpoint Patterns</div>
    <div class="card-num">$XSS_NEW_COUNT</div>
  </div>
</div>

<h2 style="margin-top:26px;">🔥 High-Risk XSS Endpoints</h2>
<table>
<tr><th>#</th><th>URL</th><th>Status</th><th>Risk</th><th>Reflected?</th><th></th></tr>
$HIGH_RISK_ROWS
</table>

<h2 style="margin-top:26px;">🧬 Unique Parameters</h2>
<table>
<tr><th>#</th><th>Parameter</th></tr>
$PARAM_ROWS
</table>

<h2 style="margin-top:26px;">🧠 JS & DOM XSS Analysis</h2>
<h3>DOM XSS Sink Candidates</h3>
<pre>$(printf '%s\n' "$JS_SINK_HTML")</pre>

<h3>Secret / API Key Candidates</h3>
<pre>$(printf '%s\n' "$JS_SECRET_HTML")</pre>

<h2 style="margin-top:26px;">🕵️ Hidden Parameter Discovery (High-Value Targets)</h2>
<table>
<tr><th>#</th><th>URL</th><th>Status</th><th>Body Info</th><th>Test Parameters</th></tr>
$HIDDEN_PARAM_ROWS
</table>

<h2 style="margin-top:26px;">🔬 DalFox XSS Findings</h2>
<pre>$(printf '%s\n' "$DALFOX_HTML")</pre>

<div class="footer">
  This report was automatically generated by FOxss Recon v4.5 — created by Caner Aktas.
</div>

</div>
<script src="report.js"></script>
</body>
</html>
EOF

    log_success "HTML report generated: ${REPORT}"
}

main() {
    banner
    check_tools
    init_evasion
    discover_subdomains
    resolve_subdomains_dns
    identify_active_subdomains
    collect_urls
    probe_active_urls
    analyze_xss
    analyze_js_dom
    discover_hidden_params
    reflection_analysis
    run_dalfox_scan
    generate_report

    log_success "FOxss Recon v4.5 pipeline finished."
}

main
