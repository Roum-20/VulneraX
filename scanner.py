import requests
from bs4 import BeautifulSoup
import urllib.parse
import colorama
import re
from concurrent.futures import ThreadPoolExecutor
import sys
from typing import List, Dict, Set
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
colorama.init()

class WebSecurityScanner:
    def __init__(self, target_url: str, max_depth: int = 3):
        self.target_url = target_url
        self.max_depth = max_depth
        self.visited_urls: Set[str] = set()
        self.vulnerabilities: List[Dict] = []
        self.session = requests.Session()

    def normalize_url(self, url: str) -> str:
        parsed = urllib.parse.urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def crawl(self, url: str, depth: int = 0) -> None:
        if depth > self.max_depth or url in self.visited_urls:
            return
        try:
            print(f"{colorama.Fore.CYAN}[Crawling]{colorama.Style.RESET_ALL} {url}")
            self.visited_urls.add(url)
            response = self.session.get(url, verify=False, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            links = soup.find_all('a', href=True)
            for link in links:
                next_url = urllib.parse.urljoin(url, link['href'])
                next_url = self.normalize_url(next_url)
                if next_url.startswith(self.target_url):
                    self.crawl(next_url, depth + 1)
        except Exception as e:
            print(f"Error crawling {url}: {str(e)}")

    def check_sql_injection(self, url: str) -> None:
        sql_payloads = ["'", "1' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--"]
        for payload in sql_payloads:
            try:
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                for param in params:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                    response = self.session.get(test_url, verify=False, timeout=10)
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
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        for payload in xss_payloads:
            try:
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                for param in params:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={urllib.parse.quote(payload)}")
                    response = self.session.get(test_url, verify=False, timeout=10)
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
        patterns =  {
    'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
    'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
    'api_key': r"api[_-]?key[_-]?(['\"|`])([a-zA-Z0-9]{32,45})\1"
}
        try:
            response = self.session.get(url, verify=False, timeout=10)
            for info_type, pattern in patterns.items():
                for match in re.finditer(pattern, response.text):
                    self.report_vulnerability({
                        'type': 'Sensitive Information Exposure',
                        'url': url,
                        'info_type': info_type,
                        'pattern': pattern
                    })
        except Exception as e:
            print(f"Error checking sensitive info on {url}: {str(e)}")

    def check_insecure_cookies(self, url: str) -> None:
        try:
            response = self.session.get(url, verify=False, timeout=10)
            for cookie in response.cookies:
                if not cookie.secure or not cookie.has_nonstandard_attr('HttpOnly'):
                    self.report_vulnerability({
                        'type': 'Insecure Cookie Settings',
                        'url': url,
                        'cookie': cookie.name,
                        'secure': cookie.secure,
                        'httponly': cookie.has_nonstandard_attr('HttpOnly')
                    })
        except Exception as e:
            print(f"Error checking cookies on {url}: {str(e)}")

    def check_info_leak_headers(self, url: str) -> None:
        try:
            response = self.session.get(url, verify=False, timeout=10)
            for header in ['Server', 'X-Powered-By']:
                if header in response.headers:
                    self.report_vulnerability({
                        'type': 'Information Disclosure via Headers',
                        'url': url,
                        'header': header,
                        'value': response.headers[header]
                    })
        except Exception as e:
            print(f"Error checking headers on {url}: {str(e)}")

    def check_security_headers(self, url: str) -> None:
        try:
            response = self.session.get(url, verify=False, timeout=10)
            headers = response.headers
            required = [
                'Content-Security-Policy',
                'Strict-Transport-Security',
                'X-Frame-Options',
                'X-XSS-Protection',
                'X-Content-Type-Options'
            ]
            for header in required:
                if header not in headers:
                    self.report_vulnerability({
                        'type': 'Missing Security Header',
                        'url': url,
                        'header': header
                    })
        except Exception as e:
            print(f"Error checking security headers on {url}: {str(e)}")

    def check_open_redirect(self, url: str) -> None:
        payload = "https://evil.com"
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            for param in params:
                if param.lower() in ['redirect', 'url', 'next']:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={urllib.parse.quote(payload)}")
                    resp = self.session.get(test_url, allow_redirects=False, verify=False, timeout=10)
                    if resp.status_code in [301, 302] and 'Location' in resp.headers:
                        if payload in resp.headers['Location']:
                            self.report_vulnerability({
                                'type': 'Open Redirect',
                                'url': url,
                                'parameter': param,
                                'payload': payload
                            })
        except Exception as e:
            print(f"Error checking open redirect on {url}: {str(e)}")

    def check_directory_listing(self, url: str) -> None:
        if not url.endswith('/'):
            return
        try:
            response = self.session.get(url, verify=False, timeout=10)
            if "Index of /" in response.text and "<title>Index of" in response.text:
                self.report_vulnerability({
                    'type': 'Directory Listing Enabled',
                    'url': url
                })
        except Exception as e:
            print(f"Error checking directory listing on {url}: {str(e)}")

    def check_http_methods(self, url: str) -> None:
        try:
            response = self.session.options(url, verify=False, timeout=10)
            allowed = response.headers.get('Allow', '')
            for method in ['PUT', 'DELETE', 'TRACE', 'CONNECT']:
                if method in allowed:
                    self.report_vulnerability({
                        'type': 'Insecure HTTP Method Enabled',
                        'url': url,
                        'method': method
                    })
        except Exception as e:
            print(f"Error checking HTTP methods on {url}: {str(e)}")

    def scan(self) -> List[Dict]:
        print(f"Starting scan of {self.target_url}")
        self.crawl(self.target_url)
        with ThreadPoolExecutor(max_workers=10) as executor:
            for url in self.visited_urls:
                executor.submit(self.check_sql_injection, url)
                executor.submit(self.check_xss, url)
                executor.submit(self.check_sensitive_info, url)
                executor.submit(self.check_insecure_cookies, url)
                executor.submit(self.check_info_leak_headers, url)
                executor.submit(self.check_security_headers, url)
                executor.submit(self.check_open_redirect, url)
                executor.submit(self.check_directory_listing, url)
                executor.submit(self.check_http_methods, url)
        return self.vulnerabilities

    def report_vulnerability(self, vulnerability: Dict) -> None:
        self.vulnerabilities.append(vulnerability)
        print(f"VULNERABILITY FOUND: {vulnerability}")

def run_scan(target_url: str) -> Dict:
    scanner = WebSecurityScanner(target_url)
    vulnerabilities = scanner.scan()
    return {
        'url': target_url,
        'total_urls': len(scanner.visited_urls),
        'vulnerabilities': scanner.vulnerabilities
    }
