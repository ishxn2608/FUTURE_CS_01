# 🛡️ OWASP Juice Shop – Web Application Security Assessment  
Status: Completed | Risk Rating: CRITICAL  

## 📌 Project Overview

This repository documents a complete security assessment of the OWASP Juice Shop web application, an intentionally vulnerable Node.js-based training app maintained by OWASP for learning web application security.
As part of a cybersecurity internship, a full vulnerability assessment and penetration test was conducted using OWASP-aligned methodologies and industry-standard tools to simulate real-world attack scenarios.

- **Assessment Date:** December 1–4, 2025  
- **Target Application:** https://juice-shop.herokuapp.com
- **Assessed By:** Ishan Acharya  
- **Overall Risk Rating:** ⚠️ CRITICAL  

## 🎯 Objectives

- ✔️ Identify and document vulnerabilities across the application in line with modern web attack techniques.
- ✔️ Evaluate the application against the OWASP Top 10 (2021) web application security risks.
- ✔️ Utilize professional penetration testing tools to perform manual and automated testing.
- ✔️ Produce high-quality, evidence-backed security documentation.
- ✔️ Provide actionable remediation and hardening recommendations.

## 📁 Repository Contents

### 1️⃣ Security Assessment Report  
**File:** `OWASP Juice Shop - Security Assessment Report - Dec 2025.pdf`  
**Contains:** Executive summary, detailed findings with severity ratings, proof-of-concept screenshots, CVSS scoring, impact analysis, remediation steps, and secure code fix examples.

**Key findings included (examples):**  
- SQL Injection → Authentication bypass  
- Cross-Site Scripting (XSS)  
- Broken Access Control  
- Sensitive Data Exposure  
- Security Misconfigurations

### 2️⃣ OWASP Top 10 Compliance Checklist  
**File:** `OWASP Top 10 Compliance Checklist - Juice Shop.pdf`  
**Provides a mapping of discovered issues to the OWASP Top 10 (2021) categories:**

| OWASP 2021 Category                           | Status |
|----------------------------------------------|--------|
| A01 – Broken Access Control                  | ✓      |
| A02 – Cryptographic Failures                 | ✓      |
| A03 – Injection                              | ✓      |
| A04 – Insecure Design                        | ✓      |
| A05 – Security Misconfiguration              | ✓      |
| A06 – Vulnerable and Outdated Components     | ✗      |
| A07 – Identification & Authentication Failures | ✓    |
| A08 – Software & Data Integrity Failures     | ✗      |
| A09 – Security Logging & Monitoring Failures | ✓      |
| A10 – Server-Side Request Forgery (SSRF)     | ✗      |   

**Summary:**  
- Critical Issues: 2  
- High-Risk Issues: 2  
- Medium-Risk Issues: 1  

### 3️⃣ Security Testing Tools & Logs  
**File:** `OWASP Juice Shop - Security Testing Tools & Logs.pdf`  
**Includes raw logs, captured requests, configuration snippets, and tool output from:**  
- Burp Suite Professional  
- OWASP ZAP  
- SQLMap  
- Nikto  
- Nmap  
- Gobuster / Dirb  
- Browser DevTools & Postman

## 🛑 Key Vulnerabilities Identified

### 🔴 Critical Severity

**1. SQL Injection – Authentication Bypass**  
- **CVSS:** 9.8  
- **Endpoint:** `/rest/user/login`  
- **Example payload:** `admin@juice-sh.op' OR 1=1--`  
- **Impact:** Full administrative account takeover due to unsanitized input in login logic.

**2. Broken Access Control**  
- **CVSS:** 9.1  
- **Endpoint:** `/administration`  
- **Impact:** Direct access to administrative functionality without proper authorization checks.

**3. Sensitive Data Exposure**  
- **CVSS:** 8.2  
- **Location:** `/ftp` directory  
- **Impact:** Access to internal files and system information via exposed directory and unprotected resources.

### 🟠 High Severity

**4. Cross-Site Scripting (XSS)**  
- **CVSS:** 7.3  
- **Endpoint:** `/rest/products/search`  
- **Example payload:** `<iframe src="javascript:alert('XSS')">`  
- **Impact:** Potential cookie theft, session hijacking, and execution of arbitrary scripts in the victim's browser.

### 🟡 Medium Severity

**5. Security Misconfiguration**  
- **CVSS:** 6.5  
- **Location:** Verbose error messages and server responses  
- **Impact:** Disclosure of stack traces and environment details that help attackers refine exploits.

## 📊 Risk Assessment Summary

| Severity | Count | Percentage |
|----------|-------|-----------|
| 🔴 Critical | 3 | 60% |
| 🟠 High | 2 | 40% |
| 🟡 Medium | 0 | 0% |
| **Total** | **5** | **100%** |  

**Overall Risk Rating:** ⚠️ **CRITICAL** – all Critical and High issues should be remediated before any production deployment.

## 🔧 Tools & Technologies Used

### Testing Environment  
- OWASP Juice Shop (Node.js / Express, Angular frontend)
- Kali Linux & Windows 11  
- Chrome DevTools  

### Security Tools  
- Burp Suite Pro  
- OWASP ZAP 2.14.0  
- SQLMap  
- Nikto v2.5  
- Nmap 7.94  
- Gobuster 3.6  
- Postman  
- Browser Developer Tools

### Documentation & Reporting  
- Google Docs, Markdown-based notes, and screenshot utilities for evidence-driven reporting.

## 🛡️ Remediation Recommendations

### Priority 1 – Immediate Fixes

#### SQL Injection  
- Replace string-concatenated queries with prepared statements or parameterized queries.
- Prefer secure ORM frameworks (e.g., Sequelize, TypeORM) and enforce strict input validation and server-side sanitization.

#### Access Control  
- Enforce robust authorization checks on all sensitive endpoints, including `/administration`.
- Implement Role-Based Access Control (RBAC) and verify permissions on each request.

#### XSS Protection  
- Properly encode all user-controlled output in templates and APIs.
- Deploy a strong Content Security Policy (CSP) and sanitize user inputs on both client and server.

### Priority 2 – Hardening Measures

#### Security Headers  
Enable headers such as:  
- `X-XSS-Protection: 1; mode=block`  
- `X-Content-Type-Options: nosniff`  
- `Content-Security-Policy: default-src 'self'`  
- `Strict-Transport-Security: max-age=31536000`

#### Session Management  
- Use `HttpOnly`, `Secure`, and `SameSite` flags on cookies, along with reasonable token lifetimes.
- Implement refresh tokens and session invalidation on logout or credential change.

#### Additional Controls  
- Introduce rate limiting and brute-force protection on authentication endpoints.
- Configure centralized logging, alerting, and monitoring to detect attacks and anomalies.

## 🎓 Skills Demonstrated

- ✅ Web application penetration testing against a modern, intentionally vulnerable training application.
- ✅ Practical application of OWASP Top 10 (2021) categories and risk understanding.
- ✅ Hands-on use of industry-standard tools (Burp Suite, OWASP ZAP, SQLMap, Nikto, Nmap, Gobuster, Postman).
- ✅ CVSS-based risk scoring, vulnerability documentation, and ethical hacking practices.
- ✅ Technical report writing and security documentation.

## ⚠️ Disclaimer

**This assessment targets only OWASP Juice Shop, an intentionally insecure application designed for security education and Capture The Flag scenarios.**

- ⚠️ Techniques, payloads, and methodologies from this project must **not** be used on systems without explicit authorization.
- ⚠️ Unauthorized penetration testing is **illegal and unethical**.
- ⚠️ This work is conducted solely for educational purposes and skills development.

## 👤 Author

**Ishan Acharya**  
Cybersecurity Student (3rd Year)  
GitHub: [@ishxn2608](https://github.com/ishxn2608)  

## 📄 License

This repository is intended solely for **educational and training purposes** in web application security.  
Use all information responsibly, ethically, and in compliance with applicable laws and organizational policies.
