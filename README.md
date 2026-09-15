# VulnShop Security Project

**Vulnerable Web Application & Automated Security Testing Platform**

VulnShop is a Flask-based cybersecurity learning platform built to demonstrate common web application vulnerabilities, their security impact, and approaches to secure implementation.

The project combines a simulated e-commerce web application with an automated security scanner, allowing vulnerable application behavior and security testing techniques to be explored in a controlled environment.

---

## Key Features

### Vulnerable Web Application

VulnShop provides a functional e-commerce-style application with:

- Product listings and product detail pages
- User authentication and session handling
- Customer reviews
- Order history
- Session-based login functionality

### Security Demonstrations

The application demonstrates web security concepts including:

- SQL injection in authentication workflows
- Cross-site scripting (XSS) and safe output rendering
- Broken access control / IDOR
- Account enumeration behavior
- Insecure vs. secure data handling
- Authentication and session security risks

### Automated Security Scanner

VulnShop includes a Python-based scanner for testing application security behavior.

Scanner functionality includes:

- SQL injection testing
- Cross-site scripting testing
- Access control testing
- Authentication and session security checks
- Automated vulnerability detection
- HTML security reports
- Severity classification

---

## How It Works

```text
                 VulnShop
                     │
          ┌──────────┴──────────┐
          │                     │
          ▼                     ▼
   Flask Web App         Security Scanner
          │                     │
   ┌──────┴──────┐       ┌──────┴──────┐
   │             │       │             │
Authentication  SQLite   SQLi / XSS   Access Control
Products        Database Auth Tests   Testing
Reviews
Orders
          │                     │
          └──────────┬──────────┘
                     ▼
              Security Report
```

The web application provides controlled vulnerable behaviors while the scanner sends security tests to the application and evaluates the responses.

---

## Security Concepts

VulnShop explores several common areas of web application security:

### SQL Injection

Demonstrates how unsafe handling of user-controlled input can affect database queries and authentication logic.

### Cross-Site Scripting (XSS)

Explores unsafe user-generated content and the importance of safely rendering untrusted input.

### Broken Access Control / IDOR

Demonstrates how improperly enforced authorization can expose resources belonging to other users.

### Authentication Security

Explores authentication behavior, account enumeration, and session-related security concerns.

### Secure Data Handling

Compares insecure implementation patterns with safer approaches to handling application data.

---

## Tech Stack

### Backend

- Python
- Flask
- SQLite

### Frontend

- HTML
- CSS
- Bootstrap
- Jinja2

### Security Testing

- Python
- Requests
- Automated vulnerability testing
- HTML report generation

---

## Project Structure

```text
vulnshop-security-project/
│
├── app.py
├── scanner.py
├── vulnshop.db
│
├── modules/
│   ├── sqli_detector.py
│   ├── xss_detector.py
│   ├── access_control.py
│   └── auth_tester.py
│
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── products.html
│   ├── product_detail.html
│   ├── login.html
│   ├── dashboard.html
│   └── orders.html
│
├── static/
│   └── style.css
│
└── reports/
```

---

## Running the Project

### 1. Clone the Repository

```bash
git clone https://github.com/manav1777/vulnshop-security-project.git
cd vulnshop-security-project
```

### 2. Install Dependencies

If the repository contains a `requirements.txt` file:

```bash
pip install -r requirements.txt
```

Otherwise, install the required third-party packages:

```bash
pip install flask colorama requests
```

### 3. Start VulnShop

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5001
```

### 4. Run the Security Scanner

With the application running, open another terminal and run:

```bash
python scanner.py
```

The scanner tests supported security scenarios and generates security findings based on the application's responses.

---

## Security Testing Workflow

```text
Start VulnShop
      │
      ▼
Run Security Scanner
      │
      ▼
Send Test Requests
      │
      ├── SQL Injection
      ├── XSS
      ├── Access Control
      └── Authentication
      │
      ▼
Analyze Responses
      │
      ▼
Classify Findings
      │
      ▼
Generate HTML Report
```

---

## What This Project Demonstrates

VulnShop demonstrates practical experience with:

- Web application security
- Vulnerability analysis
- Secure coding concepts
- Automated security testing
- Python and Flask development
- SQLite database integration
- Authentication and session security
- Security report generation

---

## Future Improvements

Potential future improvements include:

- Password hashing with bcrypt
- Role-based access control
- Additional vulnerability scenarios
- Real-time attack simulation dashboard
- Expanded scanner coverage
- Improved vulnerability classification
- Additional security reporting

---

## Educational & Security Notice

VulnShop is intentionally designed to demonstrate insecure application behavior.

It should only be used in controlled environments for educational purposes and authorized security testing. The intentionally vulnerable components should not be deployed or exposed as production systems.

---

## Author

**Manav Patel**  
Cybersecurity Student at Drexel University

[GitHub](https://github.com/manav1777) · [LinkedIn](https://linkedin.com/in/manavpatel017)
