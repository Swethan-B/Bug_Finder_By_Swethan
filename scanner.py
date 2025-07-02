import requests, re, threading, socket, urllib.parse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

requests.packages.urllib3.disable_warnings()
lock = threading.Lock()

class WebSecurityScanner:
    def __init__(self, target_url, max_depth=3):
        self.target_url = target_url.rstrip('/')
        self.max_depth = max_depth
        self.visited = set()
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.verify = False

    def crawl(self, url, depth=0):
        if depth > self.max_depth or url in self.visited: return
        if any(url.endswith(ext) for ext in [".jpg", ".png", ".gif", ".css", ".js", ".svg", ".ico"]): return
        self.visited.add(url)
        try:
            res = self.session.get(url, timeout=5)
            soup = BeautifulSoup(res.text, "html.parser")
            for tag in soup.find_all("a", href=True):
                link = urllib.parse.urljoin(url, tag['href']).split("#")[0]
                if link.startswith(self.target_url):
                    self.crawl(link, depth+1)
        except: return

    def scan(self):
        print(f"\n🔍 Scanning: {self.target_url}")
        self.crawl(self.target_url)
        print(f"🔗 Found {len(self.visited)} pages to analyze.")
        self.run_checks()
        return self.vulnerabilities

    def run_checks(self):
        with ThreadPoolExecutor(max_workers=15) as exec:
            for url in self.visited:
                exec.submit(self.check_sql_injection, url)
                exec.submit(self.check_xss, url)
                exec.submit(self.check_command_injection, url)
                exec.submit(self.check_open_redirect, url)
                exec.submit(self.check_sensitive_info, url)
                exec.submit(self.check_csrf, url)
                exec.submit(self.check_clickjacking, url)
                exec.submit(self.check_admin_panel, url)
                exec.submit(self.check_html_comments, url)

    def _report(self, vuln):
        with lock:
            self.vulnerabilities.append(vuln)
            print(f"\n[✅ DETECTED] {vuln['type']}")
            for k, v in vuln.items():
                if k != 'type':
                    print(f"  {k}: {v}")

    def _inject(self, url, payloads, vtype, match=None, errors=None):
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        for param in qs:
            for payload in payloads:
                inj_val = urllib.parse.quote(payload)
                test_url = url.replace(f"{param}={qs[param][0]}", f"{param}={inj_val}")
                try:
                    res = self.session.get(test_url, timeout=5)
                    content = res.text.lower()
                    if match and payload.lower() in content:
                        self._report({"type": vtype, "url": url, "parameter": param, "payload": payload})
                    elif errors and any(e in content for e in errors):
                        self._report({"type": vtype, "url": url, "parameter": param, "payload": payload})
                except: continue

    def check_sql_injection(self, url):
        payloads = ["'", "\"", "1' OR '1'='1", "' OR 1=1 --", "' AND 1=1", "' UNION SELECT NULL--"]
        errors = ["sql", "mysql", "sqlite", "syntax", "odbc", "pg", "psql"]
        self._inject(url, payloads, "SQL Injection", errors=errors)

    def check_xss(self, url):
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "\"'><svg onload=alert(1)>",
            "'><iframe src=javascript:alert(1)>"
        ]
        self._inject(url, payloads, "Cross-Site Scripting (XSS)", match=True)

    def check_command_injection(self, url):
        payloads = [";id", "|whoami", "&&dir", "`whoami`", "$(whoami)"]
        keywords = ["uid=", "gid=", "root", "admin", "user"]
        self._inject(url, payloads, "Command Injection", errors=keywords)

    def check_open_redirect(self, url):
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        redirect_targets = ["https://evil.com", "//evil.com", "/\\evil.com"]

        for param in qs:
            if "url" in param.lower() or "next" in param.lower():
                for evil in redirect_targets:
                    test_url = url.replace(qs[param][0], evil)
                    try:
                        res = self.session.get(test_url, allow_redirects=False, timeout=5)
                        if "evil.com" in res.headers.get("Location", ""):
                            self._report({
                                "type": "Open Redirect",
                                "url": test_url,
                                "parameter": param,
                                "payload": evil
                            })
                    except: continue

    def check_sensitive_info(self, url):
        patterns = {
            "Email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
            "AWS Key": r"AKIA[0-9A-Z]{16}",
            "JWT Token": r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
            "API Key": r"[A-Za-z0-9_\-]{32,}",
            "Phone": r"\b\d{10}\b",
            "Credit Card": r"\b(?:\d[ -]*?){13,16}\b"
        }
        try:
            res = self.session.get(url, timeout=5)
            for name, pattern in patterns.items():
                found = re.findall(pattern, res.text)
                for match in found:
                    self._report({
                        "type": "Sensitive Info Exposure",
                        "url": url,
                        "info_type": name,
                        "match": match
                    })
        except: pass

    def check_csrf(self, url):
        try:
            res = self.session.get(url, timeout=5)
            soup = BeautifulSoup(res.text, "html.parser")
            forms = soup.find_all("form")
            for form in forms:
                inputs = form.find_all("input")
                if not any("csrf" in i.get("name", "").lower() for i in inputs):
                    self._report({
                        "type": "CSRF Vulnerability",
                        "url": url,
                        "details": "Form missing CSRF token"
                    })
        except: pass

    def check_clickjacking(self, url):
        try:
            res = self.session.get(url, timeout=5)
            headers = res.headers
            if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
                self._report({
                    "type": "Clickjacking",
                    "url": url,
                    "details": "No X-Frame headers present"
                })
        except: pass

    def check_admin_panel(self, url):
        paths = ["/admin", "/dashboard", "/cpanel", "/login", "/console"]
        for path in paths:
            test_url = urllib.parse.urljoin(self.target_url, path)
            try:
                res = self.session.get(test_url, timeout=5)
                if res.status_code in [200, 401, 403]:
                    self._report({
                        "type": "Admin Panel Exposure",
                        "url": test_url,
                        "status_code": res.status_code
                    })
            except: continue

    def check_html_comments(self, url):
        try:
            res = self.session.get(url, timeout=5)
            comments = re.findall(r'<!--(.*?)-->', res.text, re.DOTALL)
            for comment in comments:
                if any(keyword in comment.lower() for keyword in ["todo", "fixme", "debug", "key", "pass"]):
                    self._report({
                        "type": "HTML Comment Disclosure",
                        "url": url,
                        "comment": comment.strip()
                    })
        except: pass

    def scan_ports(self, ports=range(1, 1025), timeout=1):
        host = urllib.parse.urlparse(self.target_url).hostname
        open_ports = []
        def scan(p):
            try:
                with socket.create_connection((host, p), timeout=timeout):
                    open_ports.append(p)
            except: pass
        with ThreadPoolExecutor(max_workers=100) as exec:
            exec.map(scan, ports)
        if open_ports:
            self._report({
                "type": "Open Ports",
                "url": self.target_url,
                "ports": open_ports
            })
