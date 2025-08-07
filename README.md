# XSS Hunter

A lightweight Python tool to scan for reflected XSS vulnerabilities with advanced evasive payloads and randomized desktop User-Agents.

    ⚠️ Disclaimer: Use only on targets you own or have explicit permission to test.

## 🔎 Features

  Recursive crawling of target site (configurable depth)

  Form, URL parameter, header, and cookie-based testing

  50+ built-in WAF‑evasive payloads plus double‑encoded variants

  Random desktop-only User-Agent per request (no mobile/browser fakes)

  Optional Tor support for anonymized scans

  Headless Selenium verification for true-positive filtering

  JSON report with detailed reproduction steps saved to xss_reports/

## ⚙️ Requirements

  Python 3.8 or higher

  ChromeDriver in your PATH

  Tor (optional, for --tor)

## Install Python dependencies:

    pip install requests beautifulsoup4 selenium stem

## 🚀 Installation

  Clone the repository:

    git clone https://github.com/yourusername/xss-hunter.git cd xss-hunter
    
  2. Install dependencies (see Requirements above).
  3. Ensure `chromedriver` is executable and in your PATH.
  4. (Optional) Start Tor:

## 💻 Usage
    ./xss_hunter.py <target_url> [options]
    Option	Description	Default
    <target_url>	URL to scan (scheme auto-added if missing)	required
    --depth N	Crawl depth	2
    --tor	Route requests through Tor proxy	false
    --visible	Launch browser window instead of headless	false
    --output DIR	Custom report directory	xss_reports/

Example:
    ./xss_hunter.py example.com --depth 3 --tor

## 🤝 Contributing

    Fork the repository

    Create your feature branch (git checkout -b feature/YourFeature)

    Commit your changes (git commit -m 'Add YourFeature')

    Push to the branch (git push origin feature/YourFeature)

    Open a Pull Request

Please follow the existing code style and include tests where possible.

## 📄 License

This project is licensed under the MIT License. See LICENSE for details.

    ⚠️ Disclaimer: Use only on targets you own or have explicit permission to test.

❤️ Made with love for the community by the-shadow-0

