# 🦊 FOXss Recon v4.5  
### XSS Recon Framework  

FOxss Recon is an advanced, fully-automated XSS reconnaissance framework designed for bug bounty hunters, penetration testers and security researchers.

It focuses on:

- Smart, low-noise recon
- Deep JS/DOM analysis
- Diff-based scanning (only new stuff)
- WAF-friendly behavior
- A futuristic neon HTML dashboard

---

## ✨ Features

### 🔍 Subdomain & URL Discovery
- Passive subdomain enumeration (samoscout + subfinder)
- DNS resolution (shuffledns / puredns / dnsx)
- Active host detection (httpx)
- URL collection from:
  - katana
  - gau
  - waybackurls
  - urlfinder

### ⚡ Smart Recon (Noise Reduction)
- Static file filtering (.png, .jpg, .css, .svg, .woff, .pdf, etc.)
- Query parameter normalization with **qsreplace** (value -> `FOX`)
- Diffing with **anew**:
  - Only new subdomains
  - Only new URLs
  - Only new XSS endpoint patterns

### 🧪 XSS Endpoint Analysis
- Parameterized endpoint extraction (`?param=`, `&param=`)
- Normalized endpoint templates
- High-risk pattern detection (script, href, code, etc.)
- Reflection testing
- DalFox pipeline integration (with optional blind XSS domain)

### 🧬 JavaScript Intelligence Module
- Automatic JS URL collection
- JS download with WAF-aware headers
- DOM XSS sink detection:
  - `innerHTML`, `outerHTML`, `document.write`, `eval`, `Function()`, `setTimeout`, `setInterval`, etc.
- Secret/API key detection:
  - Google API keys (AIza...)
  - AWS access keys (AKIA...)
  - Generic 32+ char tokens

### 🕵️ Hidden Parameter Discovery
- Targets high-value endpoints:
  - login, admin, account, profile, dashboard, checkout, payment, etc.
- Tries hidden parameters:
  - `debug=1`, `admin=1`, `internal=1`, `sandbox=1`, `preview=1`
- Flags interesting responses by:
  - HTTP status
  - Body size changes

### 🧨 WAF Evasion
- Randomized User-Agent selection
- Random spoofed X-Forwarded-For IP
- Adjustable rate limiting via `HTTPX_RATE`

### 🎨 Futuristic Neon HTML Dashboard
- Obsidian dark background with noise texture
- Glassmorphism cards and panels
- Neon orange / cyan / purple accents
- Sidebar navigation with fox identity
- JetBrains Mono code sections
- Holographic-style tables
- Copy-to-clipboard buttons

---

## 📦 Requirements

You will need the following tools in your `$PATH`:

```bash
samoscout
subfinder
dnsx
httpx
katana
gau
waybackurls
urlfinder
dalfox
parallel
curl
qsreplace
anew
```

---

## 🚀 Usage

```bash
chmod +x foxss.sh
./foxss.sh target.com
```

All recon data and the HTML report will be stored under:

```text
recon_target.com/
 ├── xss_report.html
 ├── report_style.css
 ├── report.js
 ├── subdomains.txt
 ├── urls.txt
 ├── urls_filtered.txt
 ├── active_urls.txt
 ├── xss_endpoints.txt
 ├── xss_endpoints_qs.txt
 ├── xss_endpoints_new.txt
 ├── js_sinks.txt
 ├── js_secrets.txt
 ├── hidden_params.txt
 └── dalfox_findings.txt
```

Open `xss_report.html` in your browser to see the neon dashboard.

---

## 🦊 Why FOXss Recon?

- Deeper analysis with fewer requests  
- Diff-based scanning: focuses only on new attack surface  
- Automatically reduces noise and static junk  
- Designed specifically for **bug bounty workflows**

---

## ⭐ Contributing

Pull requests and feature ideas are very welcome.

You can:

- Add more DOM sink patterns
- Add more secret detection patterns
- Improve hidden parameter wordlists
- Integrate new sources (e.g. more JS crawlers)

If you find FOXss useful, please:

> ⭐ Star the repo on GitHub — it helps a lot!

---

## 📄 License

MIT License (you are free to use, modify, and distribute with attribution).
