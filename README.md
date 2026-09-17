# VulnShop Security Project

**Vulnerable Web Application & Automated Security Testing Platform**

VulnShop is a Flask-based cybersecurity learning platform built to demonstrate common web application vulnerabilities, their security impact, and approaches to secure remediation.

The project includes intentionally vulnerable and secured implementations of an e-commerce-style web application, allowing insecure behavior and safer coding practices to be compared in a controlled environment. VulnShop also includes an automated security scanner for testing supported vulnerability scenarios and generating security findings.

**Live Demo:** https://vulnshop-security-project-1.onrender.com/

---

## Key Features

### Vulnerable Web Application

VulnShop provides a functional e-commerce-style application with:

- Product listings and product detail pages
- User authentication and session handling
- Customer reviews
- Order history
- Session-based login functionality
- Intentionally vulnerable application behavior for security testing

### Security Demonstrations

The vulnerable implementation demonstrates security issues including:

- SQL injection in authentication workflows
- Cross-site scripting (XSS)
- Broken access control / IDOR
- Account enumeration behavior
- Insecure data handling
- Authentication and session security risks

### Secure Implementation

The secure version demonstrates safer approaches to the vulnerabilities explored in the vulnerable application, including:

- Parameterized SQL queries
- Password hashing with bcrypt
- Improved access-control enforcement
- Safer handling of user-controlled data
- Improved authentication practices
- Security-focused HTTP configuration

### Automated Security Scanner

VulnShop includes a Python-based scanner for testing supported application security scenarios.

Scanner functionality includes:

- SQL injection testing
- Cross-site scripting testing
- Access-control testing
- Authentication and session security checks
- Automated vulnerability detection
- Severity classification
- HTML security report generation

---

## Vulnerable vs. Secure

One of the main goals of VulnShop is to demonstrate not only how vulnerabilities work, but also how implementation choices can mitigate them.

### Example: SQL Injection

A vulnerable authentication workflow may construct a database query directly from user-controlled input.

```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
```

The secure implementation instead uses parameterized queries:

```python
cursor.execute(
    "SELECT * FROM users WHERE username = ?",
    (username,)
)
```

### Example: Password Security

The secure implementation uses bcrypt to verify password hashes rather than relying on plaintext password storage.

```python
bcrypt.checkpw(...)
```

### Example: Access Control

The vulnerable implementation demonstrates how user-controlled identifiers can expose another user's resources when authorization is not properly enforced.

The secure implementation uses authenticated session information to determine which resources the current user is authorized to access.

---

## How VulnShop Works

```text
                         VulnShop
                            │
             ┌──────────────┴──────────────┐
             │                             │
             ▼                             ▼
     Vulnerable Web App              Secure Web App
             │                             │
      ┌──────┴──────┐               ┌──────┴──────┐
      │             │               │             │
 Authentication   SQLite       Secure Auth      SQLite
 Products         Database     Access Control   Database
 Reviews                       Safer Queries
 Orders                        Password Hashing
      │                             │
      └──────────────┬──────────────┘
                     │
                     ▼
              Security Scanner
                     │
          ┌──────────┼──────────┐
          │          │          │
         SQLi       XSS      Access Control
          │          │          │
          └──────────┼──────────┘
                     ▼
              Security Findings
                     │
                     ▼
                HTML Report
```

The vulnerable application provides controlled insecure behaviors for testing and learning.

The secure implementation demonstrates defensive approaches to those behaviors, while the scanner tests supported security scenarios and evaluates application responses.

---

## Security Concepts

### SQL Injection

Demonstrates how unsafe handling of user-controlled input can affect database queries and authentication logic.

The secure implementation demonstrates parameterized queries as a mitigation.

### Cross-Site Scripting (XSS)

Explores how unsafe rendering of user-generated content can introduce client-side security risks and why untrusted output should be handled carefully.

### Broken Access Control / IDOR

Demonstrates how missing or improperly enforced authorization checks can expose resources belonging to other users.

### Authentication Security

Explores authentication behavior, password handling, account enumeration, and session-related security concerns.

### Secure Data Handling

Compares insecure implementation patterns with safer approaches to processing and storing application data.

### Automated Security Testing

Demonstrates how Python-based testing tools can send security-focused requests, analyze responses, classify findings, and generate reports.

---

## Tech Stack

### Backend

- Python
- Flask
- SQLite
- bcrypt

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
- Severity classification

### Security Concepts

- SQL Injection
- Cross-Site Scripting
- Broken Access Control / IDOR
- Authentication Security
- Password Hashing
- Session Security
- Secure Coding
- Vulnerability Testing

---

## Project Structure

```text
vulnshop-security-project/
│
├── vulnshop-app/
│   ├── app.py
│   ├── templates/
│   ├── static/
│   └── ...
│
├── vulnshop-app-secure/
│   ├── app.py
│   ├── templates/
│   ├── static/
│   └── ...
│
├── scanner/
│   └── ...
│
├── docs/
│   └── ...
│
├── README.md
└── .gitignore
```

The vulnerable and secure applications are kept separate so their implementation differences can be examined and compared.

Generated databases, virtual environments, macOS metadata, credentials, and other local development files should remain excluded from the repository.

---

## Running the Project

### 1. Clone the Repository

```bash
git clone https://github.com/manav1777/vulnshop-security-project.git
cd vulnshop-security-project
```

### 2. Install Dependencies

Navigate to the application you want to run and install its dependencies.

For example:

```bash
cd vulnshop-app
pip install -r requirements.txt
```

For the secure implementation:

```bash
cd vulnshop-app-secure
pip install -r requirements.txt
```

### 3. Start VulnShop

From the appropriate application directory:

```bash
python3 app.py
```

Flask will display the local development URL in the terminal.

Open the displayed address in your web browser.

### 4. Run the Security Scanner

With the target VulnShop application running, open another terminal and navigate to the scanner directory.

Run the scanner with:

```bash
python3 scanner.py
```

The scanner tests supported security scenarios and generates findings based on the application's responses.

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
Generate Security Report
```

---

## What This Project Demonstrates

VulnShop demonstrates practical experience with:

- Web application security
- Vulnerability analysis
- Secure coding
- Vulnerable vs. secure implementation comparison
- Automated security testing
- Python and Flask development
- SQLite database integration
- Password hashing with bcrypt
- Authentication and session security
- Access-control testing
- Security report generation

---

## Future Improvements

Potential future improvements include:

- Role-based access control (RBAC)
- Additional vulnerability scenarios
- Cross-site request forgery (CSRF) demonstrations
- Additional authentication attack scenarios
- Expanded scanner coverage
- Improved vulnerability classification
- Real-time security testing dashboard
- Additional security reporting
- Exportable scan results
- Additional secure remediation examples

---

## Educational & Security Notice

VulnShop intentionally contains insecure application behavior for cybersecurity education and authorized security testing.

The vulnerable components should only be used in controlled environments. Do not deploy intentionally vulnerable versions as production applications or use the scanner against systems you do not own or have explicit permission to test.

The secure implementation demonstrates improved security practices for educational comparison but should not be treated as a complete production security reference.

---

## Author

**Manav Patel**  
Cybersecurity Student at Drexel University

[GitHub](https://github.com/manav1777) · [LinkedIn](https://linkedin.com/in/manavpatel017)
