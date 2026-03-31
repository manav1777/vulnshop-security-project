import requests
from colorama import Fore, Style

class SQLiDetector:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
    
    def load_payloads(self):
        """Load SQL injection payloads from file"""
        with open('payloads/sqli_payloads.txt', 'r') as f:
            return [line.strip() for line in f if line.strip()]
    
    def test_login(self):
        """Test login form for SQL injection"""
        print(f"\n{Fore.CYAN}[*] Testing SQL Injection on login form...{Style.RESET_ALL}")
        
        payloads = self.load_payloads()
        login_url = f"{self.target_url}/login"
        
        for payload in payloads:
            try:
                data = {
                    'username': payload,
                    'password': 'test'
                }
                
                response = requests.post(login_url, data=data, allow_redirects=False)
                
                # Check if we got redirected (successful login bypass)
                if response.status_code == 302 and '/dashboard' in response.headers.get('Location', ''):
                    vuln = {
                        'type': 'SQL Injection',
                        'severity': 'CRITICAL',
                        'location': 'Login Form (username field)',
                        'payload': payload,
                        'description': 'SQL injection allows authentication bypass',
                        'impact': 'Attacker can bypass login and access any account'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"{Fore.RED}[!] VULNERABLE! Payload: {payload}{Style.RESET_ALL}")
                    return  # Found vulnerability, no need to test more
                
                # Check for ACTUAL SQL errors (not CSP errors)
                error_keywords = ['sqlite3', 'syntax error', 'near', 'unrecognized token']
                response_lower = response.text.lower()
                
                # Ignore CSP-related errors
                if 'content-security-policy' in response_lower or 'csp' in response_lower:
                    continue
                    
                if any(keyword in response_lower for keyword in error_keywords):
                    vuln = {
                        'type': 'SQL Injection (Error-Based)',
                        'severity': 'HIGH',
                        'location': 'Login Form',
                        'payload': payload,
                        'description': 'SQL error messages exposed in response',
                        'impact': 'Attacker can extract database information'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"{Fore.YELLOW}[!] SQL Error Detected! Payload: {payload}{Style.RESET_ALL}")
                    
            except Exception as e:
                print(f"{Fore.RED}[ERROR] {str(e)}{Style.RESET_ALL}")
        
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[✓] No SQL injection vulnerabilities found{Style.RESET_ALL}")
    
    def get_results(self):
        """Return all found vulnerabilities"""
        return self.vulnerabilities
