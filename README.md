# 🛡 Laravel Security Scanner

A comprehensive web-based vulnerability scanner for Laravel applications with a real-time dashboard UI.

<img width="1132" height="401" alt="image" src="https://github.com/user-attachments/assets/f9cbd6a9-4c5b-4cc3-ac19-4b9b512ce98c" />


## Features

Scans for **15 vulnerability categories**:

| # | Check | Severity |
|---|-------|----------|
| 1 | Laravel Debug Mode (APP_DEBUG=true) | Critical |
| 2 | .env File Public Exposure | Critical |
| 3 | Missing HTTP Security Headers | Medium |
| 4 | Laravel Telescope / Horizon Exposure | High |
| 5 | phpinfo() Page Exposure | High |
| 6 | SQL Injection (Error-based) | Critical |
| 7 | CSRF Token Absence | High |
| 8 | Directory Listing Enabled | High |
| 9 | Sensitive Files Accessible (.git, logs, composer.json) | High |
| 10 | SSL/TLS Configuration | Critical |
| 11 | Open Redirect Vulnerability | Medium |
| 12 | Reflected XSS | High |
| 13 | Missing Rate Limiting on Login | Medium |
| 14 | Exposed Admin / Default Routes | Medium |
| 15 | Insecure Cookie Attributes | Medium |

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python app.py
```

Then open **http://localhost:5000** in your browser.

Enter your Laravel application URL and click **Scan Now**.

## ⚠️ Legal Warning

Only scan applications you **own or have explicit written permission** to test. Unauthorized scanning is illegal.

## Output

- **Security Score** (0–100)
- **Severity breakdown** (Critical / High / Medium / Low)
- **Detailed findings** with evidence and recommended fixes
- **Code snippets** for remediation

## How Scoring Works

| Score | Grade |
|-------|-------|
| 85–100 | 🟢 Good |
| 60–84 | 🟡 Fair |
| 35–59 | 🟠 Poor |
| 0–34 | 🔴 Critical |

Deductions: Critical −25, High −15, Medium −8, Low −3
