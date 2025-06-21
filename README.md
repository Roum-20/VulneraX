# VulneraX-Expose the Risks. Secure the Web
A lightweight Python-based web security scanner that **crawls** and **scans** websites for common vulnerabilities inspired by the [OWASP Top 10](https://owasp.org/www-project-top-ten/). Perfect for developers, ethical hackers, and security students looking to understand common web application security flaws.

---

## 🧰 Features

- 🔎 Crawler with configurable depth
- ✅ Multithreaded scanning (fast)
- 📑 Terminal-friendly output with color
- 📌 Checks for vulnerabilities including:

| Vulnerability                          | OWASP Category         | Status |
|---------------------------------------|------------------------|--------|
| SQL Injection                         | A03 - Injection        | ✅     |
| Cross-Site Scripting (XSS)            | A03 - Injection        | ✅     |
| Sensitive Data Exposure               | A06 - Data Protection  | ✅     |
| Insecure Cookies                      | A02 - Cryptographic Failures | ✅ |
| Info Leak via HTTP Headers            | A06 - Sensitive Data   | ✅     |
| Missing Security Headers              | A05 - Misconfig        | ✅     |
| Open Redirect                         | A01 - Access Control   | ✅     |
| Directory Listing Enabled             | A05 - Misconfig        | ✅     |
| Insecure HTTP Methods (PUT, DELETE)   | A05 - Misconfig        | ✅     |

---

## 🚀 Getting Started

### 📦 Requirements

- Python 3.7+
- Install dependencies:

```bash
pip install requests beautifulsoup4 urllib3 colorama
```
## ▶️ Run the Scanner
```bash
python3 scanner.py https://example.com
```

### 🧪 Example Output
   [Crawling] https://example.com

   
[VULNERABILITY FOUND]
type: SQL Injection

url: https://example.com/search?q='

parameter: q

payload: '

[VULNERABILITY FOUND]
type: Missing Security Header

url: https://example.com

header: Content-Security-Policy

### ⚠️ Legal Notice
This tool is intended only for authorized testing and educational purposes. Scanning websites without permission is illegal and unethical.

Always have explicit permission before scanning a site.

