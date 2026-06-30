# VulnShop Security Project

## Overview

VulnShop is a full stack cybersecurity learning platform designed to demonstrate common web application vulnerabilities and their secure implementations. It simulates real world attack and defense scenarios using a Flask based web application combined with an automated security scanner.

This project helps visualize how vulnerabilities are introduced, how attackers exploit them, and how secure coding practices mitigate risks.

---

## Features

### Web Application

* Product listing and product detail pages
* User authentication system with session handling
* Customer review system
* Order history tracking
* Session based login system

---

### Security Demonstrations

* SQL injection vulnerability simulation in login system
* Cross site scripting safe review rendering
* Broken access control (IDOR) simulation
* Account enumeration behavior comparison
* Plaintext vs secure data handling examples

---

### Security Scanner

* Automated vulnerability detection tool
* SQL injection testing module
* Cross site scripting detection module
* Access control testing module
* Authentication and session security checks
* HTML report generation with severity classification

---

## Tech Stack

* Python
* Flask
* SQLite
* HTML
* CSS
* Bootstrap
* Jinja2 Templates

---

## Project Structure

```text
vulnshop-app
│
├── app.py
├── scanner.py
├── vulnshop.db
│
├── templates
│   ├── base.html
│   ├── index.html
│   ├── products.html
│   ├── product_detail.html
│   ├── login.html
│   ├── dashboard.html
│   └── orders.html
│
├── static
│   └── style.css
│
├── modules
│   ├── sqli_detector.py
│   ├── xss_detector.py
│   ├── access_control.py
│   └── auth_tester.py
│
└── reports
```

---

## Security Concepts Covered

* SQL Injection
* Cross Site Scripting (XSS)
* Broken Access Control (IDOR)
* Authentication Flaws
* Session Management Risks
* Insecure Data Storage
* Security Testing Automation

---

## How to Run

### 1. Install dependencies

```bash
pip install flask sqlite3 colorama requests
```

---

### 2. Run the web application

```bash
python app.py
```

---

### 3. Open in browser

```
http://127.0.0.1:5001
```

---

### 4. Run security scanner

```bash
python scanner.py
```

---

## Educational Purpose

This project is built strictly for educational purposes to understand:

* how vulnerabilities are introduced in real applications
* how attackers exploit insecure code
* how security scanners detect weaknesses
* how secure coding practices mitigate risks

---

## Key Learning Outcomes

* Web application security fundamentals
* Backend development with Flask
* Database design using SQLite
* Security testing automation
* Vulnerability analysis and reporting

---

## Author

**Manav Patel**

Cybersecurity Student at Drexel University

---

## Future Improvements

* Add password hashing using bcrypt
* Implement role based access control
* Deploy secure version to cloud
* Add real time attack simulation dashboard
* Improve scanner accuracy and coverage
