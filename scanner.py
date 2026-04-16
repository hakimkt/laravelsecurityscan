#!/usr/bin/env python3
"""
Laravel Security Scanner
A comprehensive security vulnerability scanner for Laravel web applications.
"""

import asyncio
import json
import re
import ssl
import socket
import time
import urllib.parse
from dataclasses import dataclass, asdict
from typing import Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class Finding:
    id: str
    category: str
    title: str
    severity: str  # critical, high, medium, low, info
    description: str
    evidence: str
    fix: str
    references: list


class LaravelScanner:
    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.findings = []
        self.session = self._create_session()
        self.scan_log = []

    def _create_session(self):
        session = requests.Session()
        retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[500, 502, 503])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; LaravelSecurityScanner/1.0)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
        return session

    def _get(self, path="", params=None, allow_redirects=True, verify=False):
        url = self.target_url + path if path else self.target_url
        try:
            resp = self.session.get(
                url, params=params, timeout=self.timeout,
                allow_redirects=allow_redirects, verify=verify
            )
            return resp
        except Exception as e:
            return None

    def _post(self, path="", data=None, headers=None):
        url = self.target_url + path
        try:
            resp = self.session.post(
                url, data=data, headers=headers,
                timeout=self.timeout, verify=False
            )
            return resp
        except Exception:
            return None

    def _add_finding(self, **kwargs):
        self.findings.append(Finding(**kwargs))

    def _log(self, message):
        self.scan_log.append(message)

    # ─── Check 1: Laravel Debug Mode ──────────────────────────────────────────
    def check_debug_mode(self):
        self._log("Checking Laravel debug mode...")
        resp = self._get()
        if not resp:
            return

        debug_indicators = [
            "Whoops! There was an error.",
            "Illuminate\\",
            "vendor/laravel",
            "APP_DEBUG",
            "ErrorException",
            "Stack trace:",
            "symfony/debug",
        ]
        body = resp.text
        found = [i for i in debug_indicators if i in body]

        # Try triggering an error
        err_resp = self._get("/?_debug_test=" + "A" * 5000)
        if err_resp:
            for ind in debug_indicators:
                if ind in err_resp.text and ind not in found:
                    found.append(ind)

        if found:
            self._add_finding(
                id="DEBUG_001",
                category="Configuration",
                title="Laravel Debug Mode Enabled",
                severity="critical",
                description="APP_DEBUG is set to true in production. This exposes detailed error messages, stack traces, environment variables, and application internals to attackers.",
                evidence=f"Debug indicators found: {', '.join(found[:3])}",
                fix="Set APP_DEBUG=false in your .env file and run: php artisan config:cache\n\nAlso ensure APP_ENV=production in .env.",
                references=["https://laravel.com/docs/configuration#environment-configuration", "CWE-209"]
            )

    # ─── Check 2: .env File Exposure ──────────────────────────────────────────
    def check_env_exposure(self):
        self._log("Checking .env file exposure...")
        paths = ["/.env", "/.env.backup", "/.env.bak", "/.env.old",
                 "/.env.production", "/.env.local", "/.env.example"]
        for path in paths:
            resp = self._get(path)
            if resp and resp.status_code == 200:
                body = resp.text
                if any(k in body for k in ["APP_KEY", "DB_PASSWORD", "DB_HOST", "APP_ENV", "APP_DEBUG"]):
                    sensitive = []
                    if "APP_KEY" in body:
                        sensitive.append("APP_KEY")
                    if "DB_PASSWORD" in body:
                        sensitive.append("DB_PASSWORD")
                    if "MAIL_PASSWORD" in body:
                        sensitive.append("MAIL_PASSWORD")
                    self._add_finding(
                        id="ENV_001",
                        category="Sensitive Data Exposure",
                        title=f"Laravel .env File Publicly Accessible ({path})",
                        severity="critical",
                        description="The .env file containing application secrets is publicly accessible. This exposes database credentials, API keys, application encryption key, and other sensitive configuration.",
                        evidence=f"HTTP 200 at {self.target_url}{path} — sensitive keys found: {', '.join(sensitive)}",
                        fix="1. Deny access to .env in your web server config:\n   Nginx: location ~ /\\.env { deny all; }\n   Apache: <Files .env>\n     Require all denied\n   </Files>\n\n2. Ensure the document root points to /public, not the project root.\n3. Rotate ALL exposed credentials immediately.",
                        references=["https://laravel.com/docs/deployment#server-configuration", "CWE-312"]
                    )
                    return  # One critical finding is enough

    # ─── Check 3: Security Headers ────────────────────────────────────────────
    def check_security_headers(self):
        self._log("Checking HTTP security headers...")
        resp = self._get()
        if not resp:
            return

        headers = {k.lower(): v for k, v in resp.headers.items()}
        missing = []

        required_headers = {
            "x-content-type-options": {
                "expected": "nosniff",
                "description": "Prevents MIME-type sniffing attacks"
            },
            "x-frame-options": {
                "expected": "DENY or SAMEORIGIN",
                "description": "Prevents clickjacking attacks"
            },
            "x-xss-protection": {
                "expected": "1; mode=block",
                "description": "Enables browser XSS filter"
            },
            "strict-transport-security": {
                "expected": "max-age=31536000; includeSubDomains",
                "description": "Enforces HTTPS connections"
            },
            "content-security-policy": {
                "expected": "A strict CSP policy",
                "description": "Prevents XSS and data injection attacks"
            },
            "referrer-policy": {
                "expected": "no-referrer or strict-origin-when-cross-origin",
                "description": "Controls referrer information leakage"
            },
            "permissions-policy": {
                "expected": "Restrict camera, microphone, geolocation",
                "description": "Controls browser feature access"
            }
        }

        for header, info in required_headers.items():
            if header not in headers:
                missing.append(f"  - {header.title()}: {info['description']}")

        if missing:
            self._add_finding(
                id="HEADER_001",
                category="Security Headers",
                title="Missing HTTP Security Headers",
                severity="medium",
                description="Critical HTTP security headers are absent. These headers protect against common attacks like clickjacking, XSS, and MIME sniffing.",
                evidence="Missing headers:\n" + "\n".join(missing),
                fix="Add to your Laravel middleware (App\\Http\\Middleware\\SecurityHeaders.php):\n\n```php\n$response->headers->set('X-Content-Type-Options', 'nosniff');\n$response->headers->set('X-Frame-Options', 'DENY');\n$response->headers->set('X-XSS-Protection', '1; mode=block');\n$response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');\n$response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');\n```\nRegister it in Kernel.php under $middleware.",
                references=["https://owasp.org/www-project-secure-headers/", "CWE-693"]
            )

        # Check server header info leakage
        if "server" in headers and any(v in headers["server"].lower() for v in ["apache", "nginx", "php", "laravel"]):
            self._add_finding(
                id="HEADER_002",
                category="Information Disclosure",
                title="Server Version Disclosed in HTTP Headers",
                severity="low",
                description=f"The Server header reveals technology details: '{headers['server']}'. This aids attackers in targeting known vulnerabilities.",
                evidence=f"Server: {headers['server']}",
                fix="Nginx: Add 'server_tokens off;' in nginx.conf\nApache: Set 'ServerTokens Prod' and 'ServerSignature Off'\nPHP: Set 'expose_php = Off' in php.ini",
                references=["CWE-200"]
            )

    # ─── Check 4: Laravel Telescope Exposure ──────────────────────────────────
    def check_telescope_exposure(self):
        self._log("Checking Laravel Telescope/Horizon exposure...")
        paths = {
            "/telescope": "Laravel Telescope (debug dashboard)",
            "/telescope/requests": "Laravel Telescope API",
            "/horizon": "Laravel Horizon (queue dashboard)",
            "/horizon/api/stats": "Laravel Horizon API",
            "/_debugbar": "Laravel Debugbar",
        }

        for path, tool in paths.items():
            resp = self._get(path)
            if resp and resp.status_code == 200:
                if any(k in resp.text for k in ["telescope", "Telescope", "horizon", "Horizon", "debugbar"]):
                    self._add_finding(
                        id=f"TOOLS_{path.replace('/', '_').upper()}",
                        category="Sensitive Data Exposure",
                        title=f"{tool} Publicly Accessible",
                        severity="high",
                        description=f"{tool} is publicly accessible without authentication. This exposes application internals, database queries, request/response data, job queues, and potentially sensitive user data.",
                        evidence=f"HTTP 200 at {self.target_url}{path}",
                        fix=f"Restrict access in your TelescopeServiceProvider / HorizonServiceProvider:\n\n```php\nprotected function gate()\n{{\n    Gate::define('viewTelescope', function ($user) {{\n        return in_array($user->email, [\n            'admin@yourapp.com',\n        ]);\n    }});\n}}\n```\nOr disable it entirely in non-local environments:\n```php\nif ($this->app->environment('local')) {{\n    $this->app->register(TelescopeServiceProvider::class);\n}}\n```",
                        references=["https://laravel.com/docs/telescope#dashboard-authorization"]
                    )

    # ─── Check 5: phpinfo() Exposure ──────────────────────────────────────────
    def check_phpinfo(self):
        self._log("Checking for phpinfo() exposure...")
        paths = ["/phpinfo.php", "/info.php", "/php.php", "/test.php",
                 "/php_info.php", "/phpinfo/", "/server-info"]
        for path in paths:
            resp = self._get(path)
            if resp and resp.status_code == 200 and "phpinfo()" in resp.text:
                self._add_finding(
                    id="PHP_001",
                    category="Information Disclosure",
                    title="phpinfo() Page Exposed",
                    severity="high",
                    description="A phpinfo() page is publicly accessible, revealing PHP configuration, loaded modules, environment variables, file system paths, and server information.",
                    evidence=f"phpinfo() found at: {self.target_url}{path}",
                    fix=f"1. Immediately delete the file: rm {path}\n2. Audit your server for other debug/info files\n3. Restrict sensitive paths in your web server config",
                    references=["CWE-200", "CWE-538"]
                )
                return

    # ─── Check 6: SQL Injection (Basic) ───────────────────────────────────────
    def check_sql_injection(self):
        self._log("Checking for basic SQL injection indicators...")
        payloads = ["'", "''", "`", "1' OR '1'='1", "1; DROP TABLE users--",
                    "1 UNION SELECT null--", "admin'--"]
        sql_errors = [
            "SQL syntax", "mysql_fetch", "ORA-01756", "pg_query",
            "sqlite_query", "SQLSTATE", "PDOException", "QueryException",
            "Illuminate\\Database", "SQLSTATE[", "syntax error",
            "mysql error", "ora-", "microsoft jet database"
        ]

        for payload in payloads[:3]:  # Test with a subset
            resp = self._get(f"/?id={urllib.parse.quote(payload)}")
            if resp:
                for err in sql_errors:
                    if err.lower() in resp.text.lower():
                        self._add_finding(
                            id="SQLI_001",
                            category="Injection",
                            title="Potential SQL Injection Vulnerability",
                            severity="critical",
                            description="The application appears to be vulnerable to SQL Injection. Database error messages are leaking into responses, suggesting user input is not properly sanitized before use in database queries.",
                            evidence=f"SQL error triggered with payload: {payload}\nError indicator: {err}",
                            fix="1. Always use Laravel's Eloquent ORM or Query Builder with parameterized queries:\n```php\n// SAFE\n$user = DB::select('select * from users where id = ?', [$id]);\n// or\n$user = User::where('id', $id)->first();\n\n// UNSAFE - never do this\n$user = DB::select(\"select * from users where id = $id\");\n```\n2. Validate and sanitize all user inputs\n3. Use Laravel Form Request validation\n4. Enable query logging only in development",
                            references=["https://laravel.com/docs/queries", "OWASP A03:2021", "CWE-89"]
                        )
                        return

    # ─── Check 7: CSRF Protection ─────────────────────────────────────────────
    def check_csrf(self):
        self._log("Checking CSRF protection...")
        resp = self._get()
        if not resp:
            return

        has_csrf_token = "_token" in resp.text or "csrf-token" in resp.text.lower() or \
                         "X-CSRF-TOKEN" in resp.text

        # Try POST without CSRF token
        post_resp = self._post("/login", data={"email": "test@test.com", "password": "test"})
        if post_resp and post_resp.status_code == 200 and "419" not in str(post_resp.status_code):
            if "csrf" not in post_resp.text.lower() and "token" not in post_resp.text.lower():
                # If we get a non-419 response on a form without CSRF token, might be unprotected
                if post_resp.status_code not in [419, 302]:
                    pass  # Could be a false positive; flag as info only

        if not has_csrf_token:
            self._add_finding(
                id="CSRF_001",
                category="CSRF",
                title="CSRF Token Not Detected in Page Source",
                severity="high",
                description="Laravel's CSRF token was not found in the page HTML. Without CSRF protection, attackers can trick authenticated users into performing unintended actions.",
                evidence="No _token field or csrf-token meta tag found in page HTML",
                fix="1. Ensure VerifyCsrfToken middleware is in your Kernel.php $middlewareGroups['web']\n2. Add @csrf to all your Blade forms:\n```blade\n<form method='POST'>\n    @csrf\n    ...\n</form>\n```\n3. For AJAX, include the token in headers:\n```js\naxios.defaults.headers.common['X-CSRF-TOKEN'] = document.querySelector('meta[name=csrf-token]').content;\n```",
                references=["https://laravel.com/docs/csrf", "OWASP A01:2021", "CWE-352"]
            )

    # ─── Check 8: Directory Listing ───────────────────────────────────────────
    def check_directory_listing(self):
        self._log("Checking for directory listing...")
        paths = ["/storage", "/storage/app", "/storage/logs",
                 "/bootstrap", "/vendor", "/app", "/resources"]
        for path in paths:
            resp = self._get(path)
            if resp and resp.status_code == 200:
                if any(ind in resp.text for ind in ["Index of /", "Directory listing", "<title>Index of"]):
                    self._add_finding(
                        id="DIR_001",
                        category="Information Disclosure",
                        title=f"Directory Listing Enabled ({path})",
                        severity="high",
                        description="Web server directory listing is enabled, exposing file structure and potentially sensitive files to attackers.",
                        evidence=f"Directory listing found at: {self.target_url}{path}",
                        fix="Nginx: Remove 'autoindex on;' from your config\nApache: Add 'Options -Indexes' to your .htaccess or VirtualHost config\n\nAlso ensure Laravel's document root is set to /public, not the project root.",
                        references=["CWE-548"]
                    )
                    return

    # ─── Check 9: Sensitive Files ─────────────────────────────────────────────
    def check_sensitive_files(self):
        self._log("Checking for exposed sensitive files...")
        sensitive = {
            "/.git/config": ("Git Repository Exposed", "critical",
                             "Source code and credentials accessible"),
            "/.git/HEAD": ("Git Repository Exposed", "critical",
                           "Git HEAD reference accessible"),
            "/composer.json": ("Composer Dependencies Exposed", "medium",
                               "Package versions reveal potential vulnerable dependencies"),
            "/composer.lock": ("Composer Lock File Exposed", "medium",
                               "Exact dependency versions exposed"),
            "/storage/logs/laravel.log": ("Laravel Log File Accessible", "high",
                                          "Application logs may contain sensitive data, stack traces, and user info"),
            "/.htaccess": ("Apache .htaccess Accessible", "low",
                           "Web server configuration exposed"),
            "/phpunit.xml": ("PHPUnit Config Exposed", "low",
                             "Test configuration and database credentials possibly exposed"),
            "/Makefile": ("Makefile Exposed", "low", "Build scripts exposed"),
            "/server.php": ("Server Entry Point Exposed", "low", "Laravel server file accessible"),
        }

        for path, (title, severity, desc) in sensitive.items():
            resp = self._get(path)
            if resp and resp.status_code == 200 and len(resp.text) > 50:
                self._add_finding(
                    id=f"FILE_{path.replace('/', '_').replace('.', '_').upper()}",
                    category="Sensitive Data Exposure",
                    title=title,
                    severity=severity,
                    description=f"{desc}. Path: {path}",
                    evidence=f"HTTP 200 at {self.target_url}{path} ({len(resp.text)} bytes)",
                    fix=f"Deny access in your web server config:\n\nNginx:\nlocation ~ /\\.git {{ deny all; }}\nlocation ~* (composer\\.json|composer\\.lock|\\.env|\\.htaccess)$ {{ deny all; }}\n\nApache .htaccess:\n<FilesMatch \"(composer\\.json|composer\\.lock|\\.env)$\">\n  Require all denied\n</FilesMatch>\n\nAlso: Ensure document root points to /public directory.",
                    references=["CWE-538", "CWE-312"]
                )

    # ─── Check 10: SSL/TLS ────────────────────────────────────────────────────
    def check_ssl(self):
        self._log("Checking SSL/TLS configuration...")
        parsed = urllib.parse.urlparse(self.target_url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if parsed.scheme != "https":
            self._add_finding(
                id="SSL_001",
                category="Transport Security",
                title="Application Not Using HTTPS",
                severity="critical",
                description="The application is served over HTTP instead of HTTPS. All data transmitted between client and server is unencrypted and vulnerable to interception (MITM attacks).",
                evidence=f"URL scheme is HTTP: {self.target_url}",
                fix="1. Obtain an SSL certificate (free via Let's Encrypt)\n2. Configure your web server for HTTPS\n3. In Laravel .env: APP_URL=https://yourdomain.com\n4. Force HTTPS in AppServiceProvider:\n```php\nif ($this->app->environment('production')) {\n    URL::forceScheme('https');\n}\n```\n5. Add HSTS header in middleware",
                references=["OWASP A02:2021", "CWE-319"]
            )
            return

        # Check for HTTP->HTTPS redirect
        if parsed.scheme == "https":
            http_url = self.target_url.replace("https://", "http://", 1)
            try:
                r = requests.get(http_url, timeout=5, allow_redirects=False, verify=False)
                if r.status_code not in [301, 302, 307, 308]:
                    self._add_finding(
                        id="SSL_002",
                        category="Transport Security",
                        title="HTTP to HTTPS Redirect Not Enforced",
                        severity="medium",
                        description="HTTP requests are not automatically redirected to HTTPS, allowing users to accidentally use insecure connections.",
                        evidence=f"HTTP {r.status_code} on {http_url} without redirect",
                        fix="Configure permanent redirect in your web server:\nNginx:\nserver { listen 80; return 301 https://$host$request_uri; }\n\nApache:\nRewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]",
                        references=["OWASP A02:2021"]
                    )
            except Exception:
                pass

    # ─── Check 11: Open Redirect ──────────────────────────────────────────────
    def check_open_redirect(self):
        self._log("Checking for open redirect vulnerabilities...")
        payloads = [
            "//evil.com", "https://evil.com",
            "//evil.com/%2F..", "///evil.com"
        ]
        redirect_params = ["redirect", "url", "next", "return",
                           "returnUrl", "redirect_to", "back", "goto"]

        for param in redirect_params[:4]:
            for payload in payloads[:2]:
                resp = self._get(f"/?{param}={urllib.parse.quote(payload)}",
                                 allow_redirects=False)
                if resp and resp.status_code in [301, 302, 307, 308]:
                    location = resp.headers.get("Location", "")
                    if "evil.com" in location:
                        self._add_finding(
                            id="REDIRECT_001",
                            category="Open Redirect",
                            title="Open Redirect Vulnerability",
                            severity="medium",
                            description=f"The application accepts external URLs in the '{param}' parameter and redirects users to arbitrary external sites. This can be used for phishing attacks.",
                            evidence=f"Redirect to {location} via {param}={payload}",
                            fix="Validate redirect URLs against an allowlist:\n```php\n$allowedDomains = ['yourdomain.com', 'app.yourdomain.com'];\n$redirectUrl = request('redirect');\n$host = parse_url($redirectUrl, PHP_URL_HOST);\n\nif (!in_array($host, $allowedDomains)) {\n    $redirectUrl = '/';\n}\nreturn redirect($redirectUrl);\n```",
                            references=["OWASP A01:2021", "CWE-601"]
                        )
                        return

    # ─── Check 12: XSS (Reflected) ────────────────────────────────────────────
    def check_xss(self):
        self._log("Checking for reflected XSS vulnerabilities...")
        payload = "<script>alert('XSS')</script>"
        encoded = urllib.parse.quote(payload)

        params = ["q", "search", "name", "query", "s", "term", "keyword"]
        for param in params:
            resp = self._get(f"/?{param}={encoded}")
            if resp and payload in resp.text:
                self._add_finding(
                    id="XSS_001",
                    category="XSS",
                    title="Reflected Cross-Site Scripting (XSS)",
                    severity="high",
                    description=f"User input in the '{param}' parameter is reflected in the response without proper encoding, allowing script injection.",
                    evidence=f"Payload reflected: {payload} via ?{param}=",
                    fix="1. Always use Blade's double-curly-brace syntax which auto-escapes:\n```blade\n{{ $userInput }}  ✓ Safe\n{!! $userInput !!}  ✗ Unsafe - only use for trusted HTML\n```\n2. Use Laravel's e() helper for escaping in PHP:\n```php\necho e($userInput);\n```\n3. Set Content-Security-Policy header to restrict script sources",
                    references=["OWASP A03:2021", "CWE-79"]
                )
                return

    # ─── Check 13: Rate Limiting ──────────────────────────────────────────────
    def check_rate_limiting(self):
        self._log("Checking login rate limiting...")
        login_paths = ["/login", "/auth/login", "/admin/login", "/api/login"]
        for path in login_paths:
            resp = self._get(path)
            if resp and resp.status_code == 200:
                # Make multiple rapid requests
                blocked = False
                for i in range(8):
                    r = self._post(path, data={
                        "_token": "fake_token",
                        "email": f"test{i}@test.com",
                        "password": "wrongpassword"
                    })
                    if r and r.status_code == 429:
                        blocked = True
                        break

                if not blocked:
                    self._add_finding(
                        id="AUTH_001",
                        category="Authentication",
                        title="No Rate Limiting on Login Endpoint",
                        severity="medium",
                        description=f"The login endpoint ({path}) does not appear to rate-limit failed attempts, making it susceptible to brute-force and credential stuffing attacks.",
                        evidence=f"Sent 8 requests to {path} without receiving HTTP 429",
                        fix="Laravel has built-in throttling. Ensure it's active in routes/web.php:\n```php\nRoute::middleware(['throttle:login'])->group(function () {\n    Route::post('/login', [AuthController::class, 'login']);\n});\n```\n\nCustomize in RouteServiceProvider:\n```php\nRateLimiter::for('login', function (Request $request) {\n    return Limit::perMinute(5)->by($request->ip());\n});\n```",
                        references=["OWASP A07:2021", "CWE-307"]
                    )
                return

    # ─── Check 14: Default Routes ─────────────────────────────────────────────
    def check_default_routes(self):
        self._log("Checking for exposed admin and default routes...")
        admin_paths = {
            "/admin": "Admin Panel",
            "/admin/login": "Admin Login",
            "/administrator": "Administrator Panel",
            "/wp-admin": "WordPress Admin (wrong platform indicator)",
            "/api/user": "User API (potentially unauthenticated)",
            "/api/users": "Users List API",
        }
        for path, name in admin_paths.items():
            resp = self._get(path, allow_redirects=False)
            if resp and resp.status_code == 200:
                if len(resp.text) > 200:
                    self._add_finding(
                        id=f"ROUTE_{path.replace('/', '_').upper()}",
                        category="Access Control",
                        title=f"Potentially Unprotected Route: {name}",
                        severity="medium",
                        description=f"The route {path} ({name}) is accessible without authentication or returns sensitive data.",
                        evidence=f"HTTP 200 at {self.target_url}{path}",
                        fix="Protect routes with authentication middleware:\n```php\nRoute::middleware(['auth'])->group(function () {\n    Route::get('/admin', [AdminController::class, 'index']);\n});\n```\nFor API routes:\n```php\nRoute::middleware(['auth:sanctum'])->group(function () {\n    Route::get('/api/users', [UserController::class, 'index']);\n});\n```",
                        references=["OWASP A01:2021", "CWE-306"]
                    )

    # ─── Check 15: Cookie Security ────────────────────────────────────────────
    def check_cookies(self):
        self._log("Checking cookie security attributes...")
        resp = self._get()
        if not resp:
            return

        issues = []
        for cookie in resp.cookies:
            cookie_issues = []
            if not cookie.secure:
                cookie_issues.append("missing Secure flag")
            if not cookie.has_nonstandard_attr("HttpOnly") and "httponly" not in str(cookie).lower():
                cookie_issues.append("missing HttpOnly flag")
            samesite = cookie.get_nonstandard_attr("SameSite")
            if not samesite:
                cookie_issues.append("missing SameSite attribute")

            if cookie_issues:
                issues.append(f"Cookie '{cookie.name}': {', '.join(cookie_issues)}")

        if issues:
            self._add_finding(
                id="COOKIE_001",
                category="Session Security",
                title="Insecure Cookie Configuration",
                severity="medium",
                description="Session or authentication cookies lack important security attributes, making them vulnerable to theft or misuse.",
                evidence="\n".join(issues[:5]),
                fix="In config/session.php:\n```php\n'secure' => env('SESSION_SECURE_COOKIE', true),\n'http_only' => true,\n'same_site' => 'lax',\n```\nFor application cookies:\n```php\nCookie::make('name', 'value')\n    ->withSameSite('Strict')\n    ->withSecure(true)\n    ->withHttpOnly(true);\n```",
                references=["OWASP A02:2021", "CWE-614"]
            )

    def run(self, progress_callback=None):
        """Run all checks and return findings."""
        checks = [
            self.check_debug_mode,
            self.check_env_exposure,
            self.check_security_headers,
            self.check_telescope_exposure,
            self.check_phpinfo,
            self.check_sql_injection,
            self.check_csrf,
            self.check_directory_listing,
            self.check_sensitive_files,
            self.check_ssl,
            self.check_open_redirect,
            self.check_xss,
            self.check_rate_limiting,
            self.check_default_routes,
            self.check_cookies,
        ]

        for i, check in enumerate(checks):
            try:
                check()
            except Exception as e:
                self._log(f"Error in {check.__name__}: {e}")
            if progress_callback:
                progress_callback(int((i + 1) / len(checks) * 100))

        return self.findings

    def get_summary(self):
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        score = 100
        score -= severity_counts["critical"] * 25
        score -= severity_counts["high"] * 15
        score -= severity_counts["medium"] * 8
        score -= severity_counts["low"] * 3
        score = max(0, score)

        return {
            "total": len(self.findings),
            "severity_counts": severity_counts,
            "security_score": score,
            "findings": [asdict(f) for f in self.findings],
            "scan_log": self.scan_log
        }
