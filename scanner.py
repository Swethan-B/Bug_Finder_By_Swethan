import requests
from bs4 import BeautifulSoup
import urllib.parse
import colorama
import re
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Set
import warnings
import threading

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

class WebSecurityScanner:
    vulnerabilities_lock = threading.Lock()

    def __init__(self, target_url: str, max_depth: int = 3):
        self.target_url = target_url
        self.max_depth = max_depth
        self.visited_urls: Set[str] = set()
        self.vulnerabilities: List[Dict] = []
        self.session = requests.Session()
        colorama.init()

    def crawl(self, url: str, depth: int = 0) -> None:
        if depth > self.max_depth or url in self.visited_urls:
            return

        try:
            self.visited_urls.add(url)
            response = self.session.get(url, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')

            for link in soup.find_all('a', href=True):
                next_url = urllib.parse.urljoin(url, link['href'])
                if next_url.startswith(self.target_url):
                    self.crawl(next_url, depth + 1)

        except Exception as e:
            print(f"Error crawling {url}: {str(e)}")

    def check_sql_injection(self, url: str) -> None:
        payloads = ["'", "''", "`", "``", ";", "--", "#", "/*", "*/", "1=1", "1=0", "1 or 1=1", "1 or 1=0", "1 AND 1=1", "1 AND 1=0",
        "OR 1=1", "OR 1=0", "' OR 1=1--", "' OR 1=1#", "' OR 1=1 /*", "' OR 'x'='x", "' AND 1=1 --", "' AND 1=1#", "' AND 1=1 /*",
        "' OR 1=1--", "' OR 1=1#", "' OR 1=1 /*", "' or 'x'='x", "' or 1=1", "' and 1=1", "' and 1=0", "' or 1=1", "' or 1=0",
    ]

        for payload in payloads:
            try:
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)

                for param in params:
                    original = f"{param}={params[param][0]}"
                    test = f"{param}={payload}"
                    test_url = url.replace(original, test)
                    response = self.session.get(test_url)

                    if any(error in response.text.lower() for error in ['sql', 'mysql', 'sqlite', 'postgresql', 'oracle']):
                        self.report_vulnerability({
                            'type': 'SQL Injection',
                            'url': url,
                            'parameter': param,
                            'payload': payload
                        })

            except Exception as e:
                print(f"Error testing SQL injection on {url}: {str(e)}")

    def check_xss(self, url: str) -> None:
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]

        for payload in payloads:
            try:
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)

                for param in params:
                    original = f"{param}={params[param][0]}"
                    test = f"{param}={urllib.parse.quote(payload)}"
                    test_url = url.replace(original, test)
                    response = self.session.get(test_url)

                    if payload in response.text:
                        self.report_vulnerability({
                            'type': 'Cross-Site Scripting (XSS)',
                            'url': url,
                            'parameter': param,
                            'payload': payload
                        })

            except Exception as e:
                print(f"Error testing XSS on {url}: {str(e)}")

    def check_sensitive_info(self, url: str) -> None:
        patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'api_key': r'api[_-]?key[_-]?([\'"|`])([a-zA-Z0-9]{32,45})\1'
        }

        try:
            response = self.session.get(url)
            for info_type, pattern in patterns.items():
                matches = re.finditer(pattern, response.text)
                for match in matches:
                    self.report_vulnerability({
                        'type': 'Sensitive Information Exposure',
                        'url': url,
                        'info_type': info_type,
                        'match': match.group(0)
                    })
        except Exception as e:
            print(f"Error checking sensitive information on {url}: {str(e)}")

    def check_open_redirect(self, url: str) -> None:
        test_urls = ["https://example.com", "https://evil.com"]
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)

        for param in query:
            if 'url' in param or 'redirect' in param:
                for redirect_target in test_urls:
                    test_url = url.replace(query[param][0], redirect_target)
                    try:
                        response = self.session.get(test_url, allow_redirects=False)
                        location = response.headers.get("Location", "")
                        if redirect_target in location:
                            self.report_vulnerability({
                                "type": "Open Redirect",
                                "url": test_url,
                                "parameter": param,
                                "payload": redirect_target
                            })
                    except:
                        continue

    def check_command_injection(self, url: str) -> None:
        payloads = [";whoami", "&&dir", "|ls"]
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        for param in params:
            for payload in payloads:
                test = f"{param}={params[param][0]}{payload}"
                test_url = url.replace(f"{param}={params[param][0]}", test)
                try:
                    response = self.session.get(test_url)
                    if "uid=" in response.text or "root" in response.text or "admin" in response.text:
                        self.report_vulnerability({
                            "type": "Command Injection",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload
                        })
                except:
                    continue

    def check_directory_traversal(self, url: str) -> None:
        payloads = ["../../../../etc/passwd", "..\\..\\..\\windows\\win.ini"]
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        for param in params:
            for payload in payloads:
                test_url = url.replace(params[param][0], payload)
                try:
                    response = self.session.get(test_url)
                    if "root:x:" in response.text or "[extensions]" in response.text:
                        self.report_vulnerability({
                            "type": "Directory Traversal",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload
                        })
                except:
                    continue

    def check_clickjacking(self, url: str) -> None:
        try:
            response = self.session.get(url)
            headers = response.headers
            if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
                self.report_vulnerability({
                    "type": "Clickjacking",
                    "url": url,
                    "info": "Missing X-Frame-Options header"
                })
        except:
            pass

    def check_insecure_cookies(self, url: str) -> None:
        try:
            response = self.session.get(url)
            cookies = response.headers.get("Set-Cookie", "")
            if cookies and ("secure" not in cookies.lower() or "httponly" not in cookies.lower()):
                self.report_vulnerability({
                    "type": "Insecure Cookies",
                    "url": url,
                    "cookie": cookies
                })
        except:
            pass

    def check_debug_info(self, url: str) -> None:
        try:
            response = self.session.get(url)
            indicators = ["stack trace", "exception", "traceback", "fatal error", "undefined", "line "]
            for indicator in indicators:
                if indicator.lower() in response.text.lower():
                    self.report_vulnerability({
                        "type": "Exposed Debug Info",
                        "url": url,
                        "match": indicator
                    })
                    break
        except:
            pass

    def check_admin_paths(self) -> None:
        common_paths = ["/admin", "/login", "/cpanel", "/dashboard"]
        for path in common_paths:
            test_url = urllib.parse.urljoin(self.target_url, path)
            try:
                response = self.session.get(test_url)
                if response.status_code in [200, 401, 403]:
                    self.report_vulnerability({
                        "type": "Admin Panel Exposure",
                        "url": test_url,
                        "status_code": response.status_code
                    })
            except:
                continue

    def check_html_comments(self, url: str) -> None:
        try:
            response = self.session.get(url)
            comments = re.findall(r'<!--(.*?)-->', response.text, re.DOTALL)
            for comment in comments:
                if any(keyword in comment.lower() for keyword in ["todo", "fixme", "apikey", "password", "debug"]):
                    self.report_vulnerability({
                        "type": "HTML Comment Disclosure",
                        "url": url,
                        "comment": comment.strip()
                    })
        except:
            pass

    def scan(self) -> List[Dict]:
        print(f"\n{colorama.Fore.BLUE}Scanning {self.target_url}...{colorama.Style.RESET_ALL}")
        self.crawl(self.target_url)

        with ThreadPoolExecutor(max_workers=8) as executor:
            for url in self.visited_urls:
                executor.submit(self.check_sql_injection, url)
                executor.submit(self.check_xss, url)
                executor.submit(self.check_sensitive_info, url)

                # New checks
                executor.submit(self.check_open_redirect, url)
                executor.submit(self.check_command_injection, url)
                executor.submit(self.check_directory_traversal, url)
                executor.submit(self.check_clickjacking, url)
                executor.submit(self.check_insecure_cookies, url)
                executor.submit(self.check_debug_info, url)
                executor.submit(self.check_html_comments, url)

            executor.submit(self.check_admin_paths)

            self.scan_ports()
        return self.vulnerabilities


    def scan_ports(self, ports=range(1, 1025), timeout=1, threads=100):
        import socket
        from concurrent.futures import ThreadPoolExecutor

        def scan(host, port):
            try:
                with socket.create_connection((host, port), timeout=timeout):
                    return port
            except:
                return None

        print(f"\n🔍 Starting port scan on: {self.target_url}")
        host = urllib.parse.urlparse(self.target_url).hostname
        open_ports = []

        with ThreadPoolExecutor(max_workers=threads) as executor:
            results = executor.map(lambda p: scan(host, p), ports)

        for port in results:
            if port:
                open_ports.append(port)
                print(f"[+] Open port found: {port}")

        if open_ports:
            self.report_vulnerability({
                "type": "Open Ports",
                "url": self.target_url,
                "ports": open_ports
            })

    def report_vulnerability(self, vulnerability: Dict) -> None:
        with self.vulnerabilities_lock:
            self.vulnerabilities.append(vulnerability)
        print(f"{colorama.Fore.RED}[VULNERABILITY FOUND]{colorama.Style.RESET_ALL}")
        for key, value in vulnerability.items():
            print(f"{key}: {value}")
        print()
